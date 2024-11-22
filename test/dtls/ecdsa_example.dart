import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
 import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:convert/convert.dart';
// import 'dart:math';

// import 'package:pointycastle/random/fortuna_random.dart';

Future<void> main() async {
  final algorithm = X25519();

  // We need the private key pair of Alice.
  final aliceKeyPair = await algorithm.newKeyPair();
  final alicePrivateKey = await aliceKeyPair.extractPrivateKeyBytes();

  // We need only public key of Bob.
  final bobKeyPair = await algorithm.newKeyPair();
  final bobPublicKey = await bobKeyPair.extractPublicKey();

  // We can now calculate a 32-byte shared secret key.
  final sharedSecretKey = await algorithm.sharedSecretKey(
    keyPair: aliceKeyPair,
    remotePublicKey: bobPublicKey,
  );

   final signer = pc.Signer("SHA-256/ECDSA");

   pc.ECDHKDFParameters(ECPrivateKey privateKey, ECPublicKey publicKey)

   signer.init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(alicePrivateKey));

  final signatureAlgorithm = Ecdsa.p256(Sha256());
  final keyPair = await signatureAlgorithm.newKeyPairFromSeed(alicePrivateKey);

  final signature =
      await signatureAlgorithm.sign(bobPublicKey.bytes, keyPair: keyPair);

  print('Shared Secret: ${hex.encode(signature.bytes)}');
}

// void main() async {
//   final algorithm = X25519();
// //   // Step 1: Generate an X25519 key pair
//   final (privateKey, publicKey) = await generateX25519KeyPair();

//   print('Private Key: ${hex.encode(privateKey)}');
//   print('Public Key: ${hex.encode(publicKey)}');

//   //   // We need only public key of Bob.
//   final bobKeyPair = await algorithm.newKeyPair();
//   final bobPublicKey = await bobKeyPair.extractPublicKey();

//   final bobPublicKeyBytes = Uint8List.fromList(bobPublicKey.bytes);

// //   // Step 2: Generate a shared secret by performing Diffie-Hellman key exchange
//   final sharedSecret = await performKeyExchange(privateKey, bobPublicKeyBytes);

//   print('Shared Secret: ${hex.encode(sharedSecret)}');
// }

/// Generate a random X25519 private key and derive the public key.
Future<(Uint8List, Uint8List)> generateX25519KeyPair() async {
  final algorithm = X25519();

  // We need the private key pair of Alice.
  final aliceKeyPair = await algorithm.newKeyPair();
  final alicePrivateKey = await aliceKeyPair.extractPrivateKeyBytes();
  final alicePrivateKeyBytes = Uint8List.fromList(alicePrivateKey);
  final alicePublicKey = await aliceKeyPair.extractPublicKey();
  final alicePublicKeyBytes = Uint8List.fromList(alicePublicKey.bytes);

  return (alicePrivateKeyBytes, alicePublicKeyBytes);
}

// /// Perform a Diffie-Hellman key exchange using X25519.
Future<Uint8List> performKeyExchange(
    Uint8List privateKey, Uint8List publicKey) async {
  final algorithm = X25519();

  // Example private key bytes (32 bytes)

  // Example public key bytes (32 bytes)

  // Create the private key object
  final keyPair = SimpleKeyPairData(
    privateKey,
    publicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );

  // // Create the public key object
  final publicKeyBytes = SimplePublicKey(publicKey, type: KeyPairType.x25519);

  // Calculate the shared secret (pre-master secret)
  final sharedSecret = await algorithm.sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: publicKeyBytes,
  );

  // Extract the shared secret bytes
  final sharedSecretBytes = await sharedSecret.extractBytes();
  return Uint8List.fromList(sharedSecretBytes);
}
