import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart' as crypto; // For SHA-256 hashing
import 'package:pointycastle/api.dart' as pc;
import 'dart:math';

import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/macs/hmac.dart'; // For generating random bytes

Future<void> main() async {
  final ecdheAlgorithm = X25519(); // ECDHE using X25519

  // Generate random bytes for Alice and Bob (to simulate TLS nonces or entropy)
  final aliceRandomBytes = generateRandomBytes(32); // 32-byte random value
  final bobRandomBytes = generateRandomBytes(32); // 32-byte random value

  print("Alice Random Bytes: ${hex.encode(aliceRandomBytes)}");
  print("Bob Random Bytes: ${hex.encode(bobRandomBytes)}");

  // Generate the key pair for Alice (private and public keys) for key exchange
  final aliceKeyPair = await ecdheAlgorithm.newKeyPair();
  final alicePrivateKey = await aliceKeyPair.extractPrivateKeyBytes();
  final alicePublicKey = await aliceKeyPair.extractPublicKey();
  final alicePublicKeyBytes = Uint8List.fromList(alicePublicKey.bytes);

  // Generate the key pair for Bob (private and public keys) for key exchange
  final bobKeyPair = await ecdheAlgorithm.newKeyPair();
  final bobPublicKey = await bobKeyPair.extractPublicKey();
  final bobPublicKeyBytes = Uint8List.fromList(bobPublicKey.bytes);

  // Generate Alice's Ed25519 private key for signing
  final ed25519Algorithm = Ed25519();
  final ed25519KeyPair = await ed25519Algorithm.newKeyPair();
  final ed25519PrivateKey = await ed25519KeyPair.extractPrivateKeyBytes();
  final ed25519PublicKey = await ed25519KeyPair.extractPublicKey();
  final ed25519PublicKeyBytes = Uint8List.fromList(ed25519PublicKey.bytes);

  // Alice signs Bob's public key (after hashing) using Ed25519 private key
  final signature = await signPublicKeyWithHash(
      Uint8List.fromList(ed25519PrivateKey), bobPublicKeyBytes);

  // For demonstration, Bob will verify the signature using Alice's Ed25519 public key
  final isSignatureValid = await verifySignatureWithHash(
      ed25519PublicKeyBytes, bobPublicKeyBytes, signature);

  if (isSignatureValid) {
    print('Signature is valid. Bob can trust Alice\'s public key.');
  } else {
    print('Signature is invalid. Bob cannot trust the public key.');
  }

  // Perform Diffie-Hellman key exchange (shared secret) with the random bytes as additional entropy
  final sharedSecretKey = await ecdheAlgorithm.sharedSecretKey(
    keyPair: aliceKeyPair,
    remotePublicKey: bobPublicKey,
  );

  // Use the shared secret as the pre-master secret (for TLS-like exchange)
  final preMasterSecret = await sharedSecretKey.extractBytes();
  print("Pre-Master Secret: ${hex.encode(preMasterSecret)}");

  // Derive further keys from the pre-master secret using HKDF
  final derivedKeys =
      await deriveKeysFromPreMasterSecret(Uint8List.fromList(preMasterSecret));

  // Print derived keys (session key, MAC key)
  print("Derived Session Key: ${hex.encode(derivedKeys.sessionKey)}");
  print("Derived MAC Key: ${hex.encode(derivedKeys.macKey)}");
}

// Function to generate random bytes (simulate nonces or entropy in TLS)
Uint8List generateRandomBytes(int length) {
  final random = Random.secure(); // Secure random number generator
  final List<int> randomBytes =
      List<int>.generate(length, (_) => random.nextInt(256));
  return Uint8List.fromList(randomBytes);
}

// Function to sign Bob's public key hash with Alice's Ed25519 private key
Future<Uint8List> signPublicKeyWithHash(
    Uint8List privateKey, Uint8List publicKey) async {
  // Compute SHA-256 hash of Bob's public key
  final hash = crypto.sha256.convert(publicKey).bytes;

  // Sign the hash using Ed25519
  final signatureAlgorithm = Ed25519();
  final keyPair = await signatureAlgorithm.newKeyPairFromSeed(privateKey);
  final signature = await signatureAlgorithm.sign(hash, keyPair: keyPair);

  return Uint8List.fromList(signature.bytes);
}

// Function to verify the signature using Alice's Ed25519 public key and the hash of Bob's public key
Future<bool> verifySignatureWithHash(Uint8List publicKey,
    Uint8List publicKeyToVerify, Uint8List signature) async {
  // Compute SHA-256 hash of Bob's public key
  final hash = crypto.sha256.convert(publicKeyToVerify).bytes;

  final signatureAlgorithm = Ed25519();

  // Create a public key object for verification (using Ed25519 public key)
  final publicKeyObject = SimplePublicKey(publicKey, type: KeyPairType.ed25519);

  // Verify the signature
  final isValid = await signatureAlgorithm.verify(hash,
      signature: Signature(signature, publicKey: publicKeyObject));
  return isValid;
}

// Function to derive keys from the pre-master secret using HKDF
Future<DerivedKeys> deriveKeysFromPreMasterSecret(
    Uint8List preMasterSecret) async {
// Extract phase (HMAC with SHA-256)
  final hkdf = Hkdf(
    hmac: Hmac.sha256(),
    outputLength: 32,
  );
  //hkdf.deriveKey(secretKey: secretKey)
  final secretKey = SecretKey(preMasterSecret);
  final salt = [4, 5, 6];
  final extractKey = await hkdf.deriveKey(
    secretKey: secretKey,
    nonce: salt,
  );

  final (derivedBytes, er) = await PHash(
      Uint8List.fromList(extractKey.bytes), Uint8List.fromList(salt), 64);

  // Expand phase to generate the session key and MAC key (here we derive two 32-byte keys)
  // final derivedBytes = await hkdf.(
  //   inputKeyMaterial: extractKey,
  //   outputLength: 64, // Total 64 bytes, split into session key and MAC key
  // );

  //final derivedBytes = extractKey.bytes;

  final sessionKey =
      derivedBytes.sublist(0, 32); // First 32 bytes for the session key
  final macKey = derivedBytes.sublist(32, 64); // Next 32 bytes for the MAC key

  return DerivedKeys(
      Uint8List.fromList(sessionKey), Uint8List.fromList(macKey));
}

// Data class to hold the derived session key and MAC key
class DerivedKeys {
  final Uint8List sessionKey;
  final Uint8List macKey;

  DerivedKeys(this.sessionKey, this.macKey);
}

Future<(Uint8List, Exception?)> PHash(
    Uint8List secret, Uint8List seed, int requestedLength) async {
  final hmac = HMac(SHA256Digest(), 64);
  hmac.init(pc.KeyParameter(secret));

  var result = Uint8List(requestedLength);
  var a = seed;
  var offset = 0;

  while (offset < requestedLength) {
    a = hmac.process(a);
    final output = hmac.process(Uint8List.fromList([...a, ...seed]));
    final remaining = requestedLength - offset;
    final toCopy = remaining < output.length ? remaining : output.length;
    result.setRange(offset, offset + toCopy, output);
    offset += toCopy;
  }

  return (result, null);
}
