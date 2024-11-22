import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart'; // For SHA-256 hashing
import 'dart:math'; // For generating random bytes

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

  // Optionally, you can use the pre-master secret to derive further keys (e.g., using HKDF or other KDFs).
  // Here we just print the pre-master secret for demonstration.
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
  final hash = sha256.convert(publicKey).bytes;

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
  final hash = sha256.convert(publicKeyToVerify).bytes;

  final signatureAlgorithm = Ed25519();

  // Create a public key object for verification (using Ed25519 public key)
  final publicKeyObject = SimplePublicKey(publicKey, type: KeyPairType.ed25519);

  // Verify the signature
  final isValid = await signatureAlgorithm.verify(hash,
      signature: Signature(signature, publicKey: publicKeyObject));
  return isValid;
}
