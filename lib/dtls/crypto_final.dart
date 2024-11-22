import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';

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

Future<Uint8List> generateKeySignature(
    Uint8List clientRandom,
    Uint8List serverRandom,
    Uint8List publicKey,
    Curve curve,
    Uint8List privateKey) async {
  final msg =
      generateValueKeyMessage(clientRandom, serverRandom, publicKey, curve);

  // Compute SHA-256 hash of the generated message
  final hash = sha256.convert(msg).bytes;

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
