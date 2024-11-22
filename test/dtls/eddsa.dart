import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:convert/convert.dart';

Future<void> main() async {
  final ecdheAlgorithm = X25519(); // ECDHE using X25519

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
  final ed25519PrivateKeyBytes = Uint8List.fromList(ed25519PrivateKey);
  final ed25519PublicKey = await ed25519KeyPair.extractPublicKey();
  final ed25519PublicKeyBytes = Uint8List.fromList(ed25519PublicKey.bytes);

  // Print Alice's Ed25519 public key (debugging)
  print('Alice Ed25519 public key: ${hex.encode(ed25519PublicKeyBytes)}');

  // Alice signs Bob's public key using Ed25519 private key
  final signature =
      await signPublicKey(ed25519PrivateKeyBytes, bobPublicKeyBytes);

  // Print signature (debugging)
  print('Signature: ${hex.encode(signature)}');

  // For demonstration, Bob will verify the signature using Alice's Ed25519 public key
  final isSignatureValid = await verifySignature(
      ed25519PublicKeyBytes, bobPublicKeyBytes, signature);

  if (isSignatureValid) {
    print('Signature is valid. Bob can trust Alice\'s public key.');
  } else {
    print('Signature is invalid. Bob cannot trust the public key.');
  }

  // Perform Diffie-Hellman key exchange (shared secret)
  final sharedSecretKey = await ecdheAlgorithm.sharedSecretKey(
    keyPair: aliceKeyPair,
    remotePublicKey: bobPublicKey,
  );
}

// Function to sign Bob's public key with Alice's Ed25519 private key
Future<Uint8List> signPublicKey(
    Uint8List privateKey, Uint8List publicKey) async {
  final signatureAlgorithm = Ed25519();
  final keyPair = await signatureAlgorithm.newKeyPairFromSeed(privateKey);

  // Sign Bob's public key
  final signature = await signatureAlgorithm.sign(publicKey, keyPair: keyPair);
  return Uint8List.fromList(signature.bytes);
}

// Function to verify the signature using Alice's Ed25519 public key
Future<bool> verifySignature(Uint8List publicKey, Uint8List publicKeyToVerify,
    Uint8List signature) async {
  final signatureAlgorithm = Ed25519();

  // Create a public key object for verification (using Ed25519 public key)
  final publicKeyObject = SimplePublicKey(publicKey, type: KeyPairType.ed25519);

  // Verify the signature
  final isValid = await signatureAlgorithm.verify(publicKeyToVerify,
      signature: Signature(signature, publicKey: publicKeyObject));
  return isValid;
}
