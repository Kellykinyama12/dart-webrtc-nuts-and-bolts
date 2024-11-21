import 'package:cryptography/cryptography.dart';
import 'package:cryptography_flutter/cryptography_flutter.dart';

void main() async {
  // Enable the FlutterCryptography backend for better support on mobile.
  //flutterCryptography.enable();

  // Proceed with cryptography code
  await runCryptographyExample();
}

Future<void> runCryptographyExample() async {
  // Algorithms
  final keyExchangeAlgorithm = X25519();
  final signatureAlgorithm = //Ecdsa.p256(Sha256()); // Use ECDSA with SHA-256
      FlutterEcdsa.p256(Sha256());
  // Step 1: Generate key pairs for Alice and Bob
  // Alice's key pair for key exchange
  final aliceKeyExchangePair = await keyExchangeAlgorithm.newKeyPair();
  final alicePublicKey = await aliceKeyExchangePair.extractPublicKey();

  // Alice's ECDSA key pair for signing
  final aliceSigningKeyPair = await signatureAlgorithm.newKeyPair();
  final aliceSigningPublicKey = await aliceSigningKeyPair.extractPublicKey();

  // Bob's key pair for key exchange
  final bobKeyExchangePair = await keyExchangeAlgorithm.newKeyPair();
  final bobPublicKey = await bobKeyExchangePair.extractPublicKey();

  // Bob's ECDSA key pair for signing
  final bobSigningKeyPair = await signatureAlgorithm.newKeyPair();
  final bobSigningPublicKey = await bobSigningKeyPair.extractPublicKey();

  // Step 2: Alice signs her public key
  final aliceSignature = await signatureAlgorithm.sign(
    alicePublicKey.bytes,
    keyPair: aliceSigningKeyPair,
  );

  // Bob signs his public key
  final bobSignature = await signatureAlgorithm.sign(
    bobPublicKey.bytes,
    keyPair: bobSigningKeyPair,
  );

  // Step 3: Public keys and signatures are exchanged
  // Alice verifies Bob's signature
  final isBobSignatureValid = await signatureAlgorithm.verify(
    bobPublicKey.bytes,
    signature: bobSignature,
    //publicKeyBytes: bobSigningPublicKey.bytes,
  );

  if (!isBobSignatureValid) {
    throw Exception("Bob's signature is invalid!");
  }

  // Bob verifies Alice's signature
  final isAliceSignatureValid = await signatureAlgorithm.verify(
    alicePublicKey.bytes,
    signature: aliceSignature,
    //publicKeyBytes: aliceSigningPublicKey.bytes,
  );

  if (!isAliceSignatureValid) {
    throw Exception("Alice's signature is invalid!");
  }

  // Step 4: Derive the shared secret
  final aliceSharedSecret = await keyExchangeAlgorithm.sharedSecretKey(
    keyPair: aliceKeyExchangePair,
    remotePublicKey: bobPublicKey,
  );

  final bobSharedSecret = await keyExchangeAlgorithm.sharedSecretKey(
    keyPair: bobKeyExchangePair,
    remotePublicKey: alicePublicKey,
  );

  // Compare the shared secrets
  final aliceSharedSecretBytes = await aliceSharedSecret.extractBytes();
  final bobSharedSecretBytes = await bobSharedSecret.extractBytes();

  print('Alice\'s shared secret: $aliceSharedSecretBytes');
  print('Bob\'s shared secret:   $bobSharedSecretBytes');
  print(
      'Shared secrets match: ${aliceSharedSecretBytes == bobSharedSecretBytes}');
}
