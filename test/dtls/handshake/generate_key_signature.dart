import 'dart:typed_data';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto_final.dart';

void main() async {
  // Generate random data for clientRandom and serverRandom
  final clientRandom = generateRandomBytes(32); // 32 bytes of random data
  final serverRandom = generateRandomBytes(32); // 32 bytes of random data

  // Generate X25519 key pair for Alice
  final x25519Algorithm = X25519();
  final aliceKeyPair = await x25519Algorithm.newKeyPair();
  final alicePublicKey = await aliceKeyPair.extractPublicKey();
  final alicePublicKeyBytes = alicePublicKey.bytes;

  // Generate X25519 key pair for Bob
  final bobKeyPair = await x25519Algorithm.newKeyPair();
  final bobPublicKey = await bobKeyPair.extractPublicKey();
  final bobPublicKeyBytes = bobPublicKey.bytes;

  // Simulate curve with an example value (e.g., curve ID for Curve25519)
  final curve = Curve(0x001d); // Example curve ID for Curve25519 in TLS

  // Generate Ed25519 private key (seed) for signing
  final ed25519Algorithm = Ed25519();
  final ed25519KeyPair = await ed25519Algorithm.newKeyPair();
  final ed25519PrivateKeyBytes = await ed25519KeyPair.extractPrivateKeyBytes();

  // Call generateKeySignature
  final signature = await generateKeySignature(
    clientRandom,
    serverRandom,
    Uint8List.fromList(bobPublicKeyBytes),
    curve,
    Uint8List.fromList(ed25519PrivateKeyBytes),
  );

  print(
      'Signature (hex): ${signature.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}');

  // Perform Diffie-Hellman key exchange to generate a shared secret
  final sharedSecretKey = await x25519Algorithm.sharedSecretKey(
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
