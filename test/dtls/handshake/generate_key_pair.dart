import 'dart:typed_data';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto_final.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_random.dart';

void main() async {
  // Generate random data for clientRandom and serverRandom
  final clientRandom = generateRandomBytes(32); // 32 bytes of random data
  final serverRandom = generateRandomBytes(32); // 32 bytes of random data

  // Generate X25519 key pair for Alice
  final aliceKeyPair = await generateCurveKeypair(KeyPairType.x25519);
  final alicePublicKey = await aliceKeyPair.extractPublicKey();
  final alicePrivateKey = await aliceKeyPair.extract();

  // Generate X25519 key pair for Bob
  final bobKeyPair = await generateCurveKeypair(KeyPairType.x25519);
  final bobPublicKey = await bobKeyPair.extractPublicKey();
  final bobPrivateKey = await bobKeyPair.extract();

  // Simulate curve with an example value (e.g., curve ID for Curve25519)
  final curve = Curve(0x001d); // Example curve ID for Curve25519 in TLS

  // Generate Ed25519 private key (seed) for signing
  final ed25519KeyPair = await generateCurveKeypair(KeyPairType.ed25519);
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







