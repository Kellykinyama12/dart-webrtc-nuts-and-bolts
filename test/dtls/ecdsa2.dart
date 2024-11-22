import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:convert/convert.dart';

// Future<void> main() async {
//   final ecdsaAlgorithm = Ecdsa.p256(Sha256()); // Use ECDSA with P-256 curve
//   final ecdheAlgorithm = X25519(); // ECDHE using X25519
//   final aesGcmAlgorithm = AesGcm.with256bits(); // AES-GCM for encryption

//   // Step 1: Generate Alice's ECDSA key pair (for signing)
//   final aliceKeyPair = await ecdsaAlgorithm.newKeyPair();
//   final alicePrivateKey = await aliceKeyPair.extract();
//   final alicePrivateKeyBytes = Uint8List.fromList(alicePrivateKey.d);
//   final alicePublicKey = await aliceKeyPair.extractPublicKey();

//   // Step 2: Generate Bob's ECDSA key pair (for signing)
//   final bobKeyPair = await ecdsaAlgorithm.newKeyPair();
//   final bobPublicKey = await bobKeyPair.extractPublicKey();

//   // Step 3: Perform ECDHE key exchange to generate shared secret
//   final sharedSecretKey = await ecdheAlgorithm.sharedSecretKey(
//     keyPair: aliceKeyPair,
//     remotePublicKey: bobPublicKey,
//   );

//   // Step 4: Sign Bob's public key with Alice's private key (ECDSA signature)
//   final signature = await signPublicKey(alicePrivateKeyBytes, bobPublicKey);

//   // Step 5: Verify signature with Alice's public key (ECDSA verification)
//   final isSignatureValid =
//       await verifySignature(alicePrivateKeyBytes, bobPublicKey, signature);

//   if (isSignatureValid) {
//     print('Signature is valid. Bob can trust Alice\'s public key.');
//   } else {
//     print('Signature is invalid. Bob cannot trust the public key.');
//   }

//   // Step 6: Encrypt a message using AES-128-GCM with the shared secret as the key
//   final message = 'Hello Bob!';
//   // final encryptedMessage = await encryptWithAesGcm(sharedSecretKey, message);
//   // print('Encrypted message: $encryptedMessage');
// }

// Function to sign Bob's public key with Alice's private key (ECDSA)
Future<Uint8List> signPublicKey(
    Uint8List privateKey, Uint8List publicKey) async {
  final signatureAlgorithm = Ecdsa.p256(Sha256());
  final keyPair = await signatureAlgorithm.newKeyPairFromSeed(privateKey);

  // Sign Bob's public key
  final signature = await signatureAlgorithm.sign(publicKey, keyPair: keyPair);
  return Uint8List.fromList(signature.bytes);
}

// Function to verify the signature using Alice's public key (ECDSA)
Future<bool> verifySignature(Uint8List publicKey, Uint8List publicKeyToVerify,
    Uint8List signature) async {
  final signatureAlgorithm = Ecdsa.p256(Sha256());

  // Create a public key object for verification
  final publicKeyObject = SimplePublicKey(publicKey, type: KeyPairType.ecdsa);

  // Verify the signature
  final isValid = await signatureAlgorithm.verify(publicKeyToVerify,
      signature: Signature(signature, publicKey: publicKeyObject));
  return isValid;
}

// Function to encrypt a message using AES-GCM with a shared secret
Future<String> encryptWithAesGcm(
    Uint8List sharedSecretKey, String message) async {
  final secretKey = SecretKey(sharedSecretKey);

  // Convert the message to bytes
  final messageBytes = Uint8List.fromList(message.codeUnits);

  // Generate nonce (random 12-byte nonce for AES-GCM)
  final nonce = Uint8List(12); // Typically a random nonce
  for (int i = 0; i < 12; i++) {
    nonce[i] = i;
  }

  // Encrypt the message using AES-GCM
  final aesGcmAlgorithm = AesGcm.with128bits(); // AES 128 GCM mode
  final encryptionResult = await aesGcmAlgorithm.encrypt(
    messageBytes,
    secretKey: secretKey,
    nonce: nonce,
  );

  // Return the encrypted message as a hex string
  return hex.encode(encryptionResult.cipherText);
}
