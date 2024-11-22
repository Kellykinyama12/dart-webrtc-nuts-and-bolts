import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart' as cipher;
import 'dart:math';

Uint8List generateValueKeyMessage(Uint8List clientRandom,
    Uint8List serverRandom, Uint8List publicKey, cipher.Curve curve) {
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

Future<Uint8List> generateKeySignature(
    Uint8List clientRandom,
    Uint8List serverRandom,
    Uint8List publicKey,
    cipher.Curve curve,
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

// Function to generate a key pair for a specified algorithm type (X25519 or Ed25519)
Future<SimpleKeyPair> generateCurveKeypair(KeyPairType keyPairType) async {
  switch (keyPairType) {
    case KeyPairType.x25519:
      return await X25519().newKeyPair();
    case KeyPairType.ed25519:
      return await Ed25519().newKeyPair();
    default:
      throw Exception('Unsupported KeyPairType');
  }
}

// Function to verify the signature using Alice's Ed25519 public key
Future<bool> verifySignature(
  Uint8List signature,
  Uint8List publicKey,
  Uint8List alicePublicKey,
  Uint8List clientRandom,
  Uint8List serverRandom,
  cipher.Curve curve,
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

// Function to generate random bytes
// Uint8List generateRandomBytes(int length) {
//   final random = Random.secure();
//   return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
// }
Future<Uint8List> generatePreMasterSecret(
    Uint8List publicKey, Uint8List privateKey, cipher.Curve curve) async {
  if (curve.value != 0x001d) {
    throw ArgumentError('Only CurveX25519 is supported');
  }

  try {
    // Perform X25519 key exchange to generate the pre-master secret
    final ecdhAlgorithm = X25519();
    final keyPair = await ecdhAlgorithm.newKeyPairFromSeed(privateKey);

    // Exchange the keys using X25519 to generate the shared secret
    final sharedSecret = await ecdhAlgorithm.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
    );

    print(
        "Generated Pre-Master Secret using ClientKeyExchangePublic key and ServerPrivateKey via X25519");

    return Uint8List.fromList(await sharedSecret.extractBytes());
  } catch (e) {
    print("Error generating Pre-Master Secret: $e");
    rethrow;
  }
}

Future<Uint8List> generateExtendedMasterSecret(Uint8List preMasterSecret,
    Uint8List handshakeHash, cipher.HashAlgorithm hashAlgorithm) async {
  // Step 1: Create the seed by concatenating "extended master secret" with the handshakeHash
  final seed = Uint8List.fromList([
    ...'extended master secret'.codeUnits,
    ...handshakeHash,
  ]);

  // Step 2: Use the PHash function to derive the extended master secret
  final result = await pHash(preMasterSecret, seed, 48, hashAlgorithm);

  print(
      "Generated Extended Master Secret: 0x${result.map((e) => e.toRadixString(16).padLeft(2, '0')).join()}");
  return result;
}

Future<Uint8List> pHash(Uint8List secret, Uint8List seed, int requestedLength,
    cipher.HashAlgorithm hashAlgorithm) async {
  // Determine the hash function based on the provided hash algorithm
  final hashFunc = Sha256();
  final hashOutputSize = 32;

  List<int> lastRound = seed;
  List<int> out = [];

  final iterations = (requestedLength / hashOutputSize).ceil();
  for (int i = 0; i < iterations; i++) {
    // First HMAC with secret and last round
    final firstHmac = await hmacSha256(secret, lastRound);

    // Second HMAC with secret and the concatenated last round + seed
    final secondHmac =
        await hmacSha256(secret, [...firstHmac, ...lastRound, ...seed]);

    out.addAll(secondHmac);
    lastRound = secondHmac;
  }

  return Uint8List.fromList(out.sublist(0, requestedLength));
}

// HMAC implementation
Future<List<int>> hmacSha256(Uint8List key, List<int> data) async {
  final hmac = Hmac(Sha256());
  final mac = await hmac.calculateMac(data, secretKey: SecretKey(key));
  return mac.bytes;
}

Future<Uint8List> generateMasterSecret(
    Uint8List preMasterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom,
    cipher.HashAlgorithm hashAlgorithm) async {
  // Step 1: Create the seed by concatenating "master secret", client random, and server random
  final masterSecretLabel = utf8.encode('master secret');
  final seed = Uint8List.fromList(
      [...masterSecretLabel, ...clientRandom, ...serverRandom]);

  // Step 2: Call PHash (HMAC-based key derivation) with the preMasterSecret and seed
  final result = await pHash(preMasterSecret, seed, 48, hashAlgorithm);

  // Step 3: Return the generated master secret
  return result;
}
