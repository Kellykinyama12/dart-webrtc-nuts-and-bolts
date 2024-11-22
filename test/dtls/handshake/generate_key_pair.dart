import 'dart:typed_data';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as crypto;

void main() async {
  // Generate random data for clientRandom and serverRandom
  final clientRandom = generateRandomBytes(32); // 32 bytes of random data
  final serverRandom = generateRandomBytes(32); // 32 bytes of random data

  // Generate X25519 key pair for Alice
  final aliceKeyPair = await generateKeyPair(KeyPairType.x25519);
  final alicePublicKey = await aliceKeyPair.extractPublicKey();
  final alicePrivateKey = await aliceKeyPair.extract();

  // Generate X25519 key pair for Bob
  final bobKeyPair = await generateKeyPair(KeyPairType.x25519);
  final bobPublicKey = await bobKeyPair.extractPublicKey();
  final bobPrivateKey = await bobKeyPair.extract();

  // Simulate curve with an example value (e.g., curve ID for Curve25519)
  final curve = Curve(0x001d); // Example curve ID for Curve25519 in TLS

  // Generate Ed25519 private key (seed) for signing
  final ed25519KeyPair = await generateKeyPair(KeyPairType.ed25519);
  final ed25519PrivateKeyBytes = await ed25519KeyPair.extractPrivateKeyBytes();
  final ed25519PublicKeyBytes = await ed25519KeyPair.extractPublicKey();

  // Call generateKeySignature
  final signature = await generateKeySignature(
    clientRandom,
    serverRandom,
    Uint8List.fromList(bobPublicKey.bytes),
    curve,
    Uint8List.fromList(ed25519PrivateKeyBytes),
  );

  print(
      'Signature (hex): ${signature.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');

  // Verify the signature using Alice's public key (Ed25519)
  final isValid = await verifySignature(
    signature,
    Uint8List.fromList(bobPublicKey.bytes),
    Uint8List.fromList(ed25519PublicKeyBytes.bytes),
    clientRandom,
    serverRandom,
    curve,
  );

  if (isValid) {
    print('Signature is valid. The public key can be trusted.');
  } else {
    print('Signature is invalid. The public key cannot be trusted.');
  }

  // Perform Diffie-Hellman key exchange to generate a shared secret
  final sharedSecretKey = await X25519().sharedSecretKey(
    keyPair: aliceKeyPair,
    remotePublicKey: bobPublicKey,
  );

  // Extract the shared secret as bytes
  final sharedSecretBytes = await sharedSecretKey.extractBytes();
  print(
      'Shared Secret (hex): ${sharedSecretBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');

  // Optional: Derive further keys using HKDF
  final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
  final derivedKey = await hkdf.deriveKey(
    secretKey: sharedSecretKey,
    nonce: Uint8List.fromList(
        [...clientRandom, ...serverRandom]), // Combined randoms
    info:
        Uint8List.fromList('key expansion'.codeUnits), // Optional context info
  );

  final derivedKeyBytes = await derivedKey.extractBytes();
  print(
      'Derived Key (hex): ${derivedKeyBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');
}

// Function to generate random bytes
Uint8List generateRandomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}

// Define the Curve class as a placeholder
class Curve {
  final int value;
  Curve(this.value);
}

// Function to generate a key pair for a specified algorithm type (X25519 or Ed25519)
Future<SimpleKeyPair> generateKeyPair(KeyPairType keyPairType) async {
  switch (keyPairType) {
    case KeyPairType.x25519:
      return await X25519().newKeyPair();
    case KeyPairType.ed25519:
      return await Ed25519().newKeyPair();
    default:
      throw Exception('Unsupported KeyPairType');
  }
}

// The generateKeySignature function (defined in your previous code)
Future<Uint8List> generateKeySignature(
    Uint8List clientRandom,
    Uint8List serverRandom,
    Uint8List publicKey,
    Curve curve,
    Uint8List privateKey) async {
  final msg =
      generateValueKeyMessage(clientRandom, serverRandom, publicKey, curve);

  // Compute SHA-256 hash of the generated message
  final hash = crypto.sha256.convert(msg).bytes;

  // Sign the hash using Ed25519
  final signatureAlgorithm = Ed25519();

  // Create the key pair from the private key seed (Ed25519 requires 32 bytes)
  final keyPair = await signatureAlgorithm.newKeyPairFromSeed(privateKey);

  // Sign the hash
  final signature = await signatureAlgorithm.sign(
    hash,
    keyPair: keyPair,
  );

  return Uint8List.fromList(signature.bytes);
}

// The generateValueKeyMessage function (defined in your previous code)
Uint8List generateValueKeyMessage(Uint8List clientRandom,
    Uint8List serverRandom, Uint8List publicKey, Curve curve) {
  final serverECDHParams = Uint8List(4);
  serverECDHParams[0] = 3; // CurveTypeNamedCurve
  serverECDHParams.buffer.asByteData().setUint16(1, curve.value);
  serverECDHParams[3] = publicKey.length;

  final plaintext = Uint8List.fromList([
    ...clientRandom,
    ...serverRandom,
    ...serverECDHParams,
    ...publicKey,
  ]);

  return plaintext;
}

// Function to verify the signature using Alice's Ed25519 public key
Future<bool> verifySignature(
  Uint8List signature,
  Uint8List publicKey,
  Uint8List alicePublicKey,
  Uint8List clientRandom,
  Uint8List serverRandom,
  Curve curve,
) async {
  final msg =
      generateValueKeyMessage(clientRandom, serverRandom, publicKey, curve);

  // Compute SHA-256 hash of the generated message
  final hash = crypto.sha256.convert(msg).bytes;

  // Create the public key object for verification
  final publicKeyObject =
      SimplePublicKey(alicePublicKey, type: KeyPairType.ed25519);

  // Verify the signature using Ed25519
  final signatureAlgorithm = Ed25519();
  final isValid = await signatureAlgorithm.verify(
    hash,
    signature: Signature(signature, publicKey: publicKeyObject),
  );

  return isValid;
}
