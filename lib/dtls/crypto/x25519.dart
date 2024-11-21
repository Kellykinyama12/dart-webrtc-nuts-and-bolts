import 'package:cryptography/cryptography.dart';

/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final signedMessage = [1,2,3];
///
///   final ed25519 = Ed25519();
///   final keyPair = await ed25519.newKeyPair();
///   final signature = await ed25519.sign(
///     signedMessage,
///     keyPair: keyPair,
///   );
///
///   // ...
///
///   final isRealSignature = await ed25519.verify(
///     signedMessage,
///     signature: signature,
///   );
///
///   print('Signature verification result: $isRealSignature');
/// }

void main() async {
  // Algorithms
  final keyExchangeAlgorithm = X25519();
  // final signatureAlgorithm = Ecdsa.p256(Sha256());
  final signatureAlgorithm = Ed25519();

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
  );

  if (!isBobSignatureValid) {
    throw Exception("Bob's signature is invalid!");
  }

  // Bob verifies Alice's signature
  final isAliceSignatureValid = await signatureAlgorithm.verify(
    alicePublicKey.bytes,
    signature: aliceSignature,
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
