import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:pointycastle/export.dart' as pc;

Future<(Uint8List, Uint8List)> generateCurveKeypair(String curve) async {
  final algorithm = cryptography.X25519();

  // We need the private key pair of Alice.
  final aliceKeyPair = await algorithm.newKeyPair();
  final privatekey = await aliceKeyPair.extractPrivateKeyBytes();
  final privateKeyBytesBytes = Uint8List.fromList(privatekey);
  final simplePublicKey = await aliceKeyPair.extractPublicKey();
  final publicKeyBytesBytes = Uint8List.fromList(simplePublicKey.bytes);
  // return {'private': privateKeyBytesBytes, 'public:': publicKeyBytesBytes};
  return (privateKeyBytesBytes, publicKeyBytesBytes);
  // We need only public key of Bob.
  // final bobKeyPair = await algorithm.newKeyPair();
  // final bobPublicKey = await bobKeyPair.extractPublicKey();

  // // We can now calculate a 32-byte shared secret key.
  // final sharedSecretKey = await algorithm.sharedSecretKey(
  //   keyPair: aliceKeyPair,
  //   remotePublicKey: bobPublicKey,
  //);
}

// Uint8List generateValueKeyMessage(Uint8List clientRandom, Uint8List serverRandom, Uint8List publicKey, Curve curve )  {
// 	//See signed_params enum: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.3

// 	logging.Descf(logging.ProtoCRYPTO,
// 		common.JoinSlice("\n", false,
// 			common.ProcessIndent("Generating plaintext of signed_params values consist of:", "+", []string{
// 				fmt.Sprintf("Client Random <u>0x%x</u> (<u>%d bytes</u>)", clientRandom, len(clientRandom)),
// 				fmt.Sprintf("Server Random <u>0x%x</u> (<u>%d bytes</u>)", serverRandom, len(serverRandom)),
// 				common.ProcessIndent("ECDH Params:", "", []string{
// 					fmt.Sprintf("[0]: <u>%s</u>\n[1:2]: <u>%s</u>\n[3]: <u>%d</u> (public key length)", CurveTypeNamedCurve, curve, len(publicKey)),
// 				}),
// 				fmt.Sprintf("Public Key: <u>0x%x</u>", publicKey),
// 			})))
// 	serverECDHParams := make([]byte, 4)
// 	serverECDHParams[0] = byte(CurveTypeNamedCurve)
// 	binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(curve))
// 	serverECDHParams[3] = byte(len(publicKey))

// 	plaintext := []byte{}
// 	plaintext = append(plaintext, clientRandom...)
// 	plaintext = append(plaintext, serverRandom...)
// 	plaintext = append(plaintext, serverECDHParams...)
// 	plaintext = append(plaintext, publicKey...)
// 	logging.Descf(logging.ProtoCRYPTO, "Generated plaintext of signed_params values: <u>0x%x</u> (<u>%d</u> bytes)", plaintext, len(plaintext))
// 	return plaintext
// }

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

// Future<(Uint8List, Exception?)> generateKeySignature(
//     Uint8List clientRandom,
//     Uint8List serverRandom,
//     Uint8List publicKeyBytes,
//     Curve curve,
//     Uint8List privateKeyBytes,
//     HashAlgorithm hashAlgorithm) async
// //([]byte, error)
// {
//   final msg = generateValueKeyMessage(
//       clientRandom, serverRandom, publicKeyBytes, curve);
//   //switch privateKeyObj := privateKey.(type) {
//   //case *ecdsa.PrivateKey:
//   // hashed = hashAlgorithm.Execute(msg) //SHA256 sum
//   // logging.Descf(logging.ProtoCRYPTO, "signed_params values hashed: <u>0x%x</u> (<u>%d</u> bytes)", hashed, len(hashed))
//   // signed, err := privateKeyObj.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHashType()) //crypto.SHA256
//   // logging.Descf(logging.ProtoCRYPTO, "signed_params values signed (result will be called as ServerKeySignature): <u>0x%x</u> (<u>%d</u> bytes)", signed, len(signed))
//   // return signed, err

//   final algorithm = cryptography.Sha256();
//   final hash = await algorithm.hash(msg);

//   // Create the private key object
//   final keyPair = cryptography.SimpleKeyPairData(
//     privateKeyBytes,
//     publicKey: cryptography.SimplePublicKey(publicKeyBytes,
//         type: cryptography.KeyPairType.x25519),
//     type: cryptography.KeyPairType.x25519,
//   );

//   // In this example, we use ECDSA-P256-SHA256
//   final signer = cryptography.Ecdsa.p256(cryptography.Sha256());
//   final signature = await signer.sign(hash.bytes, keyPair: keyPair);

//   // Return the signature
//   return (Uint8List.fromList(signature.bytes), null);

//   // Generate a random key pair
//   // final secretKey = await signer.newSecretKey();
//   // final publicKey = await signer.publicKey(secretKey);

//   // Sign a message
//   // final message = <int>[1, 2, 3];
//   // final signature = await signer.sign(
//   //   [1, 2, 3],
//   //   secretKey: secretKey,
//   // );
// }

Future<(Uint8List, Exception?)> generateKeySignature(
    Uint8List clientRandom,
    Uint8List serverRandom,
    Uint8List publicKeyBytes,
    Curve curve,
    Uint8List privateKeyBytes,
    HashAlgorithm hashAlgorithm) async {
  //try {
  // Validate the curve type
  // if (curve != 'Curve25519') {
  //   return (Uint8List(0), Exception('Unsupported curve type: $curve'));
  // }

  // Combine inputs to generate the message
  // final msg = Uint8List.fromList([
  //   ...clientRandom,
  //   ...serverRandom,
  //   ...publicKeyBytes,
  // ]);

  final msg = generateValueKeyMessage(
      clientRandom, serverRandom, publicKeyBytes, curve);

  final hashalgo = cryptography.Sha256();
  final hash = await hashalgo.hash(msg);

  // Use the Ed25519 algorithm (suitable for signing)
  final algorithm = cryptography.Ed25519();

  // Create a key pair directly from the private key bytes
  final privateKey = await algorithm.newKeyPairFromSeed(privateKeyBytes);

  // Sign the message
  final signature = await algorithm.sign(
    hash.bytes,
    keyPair: privateKey,
  );

  print("signature: ${signature.bytes}. length: ${signature.bytes.length}");
  // Return the signature
  return (Uint8List.fromList(signature.bytes), null);
  //} catch (e) {
  //  return (Uint8List(0), e as Exception);
  // }
}

Future<(Uint8List, Exception?)> generatePreMasterSecret(
    Uint8List publicKey, Uint8List privateKey, Curve curve) async {
  // final algorithm = cryptography.X25519();
  //final keyPair = cryptography.SimpleKeyPairData(privateKey, type: cryptography.KeyPairType.x25519);
  // final sharedSecret = await algorithm.sharedSecret(
  //   keyPair: keyPair,
  //   remotePublicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
  // );

  final algorithm = cryptography.X25519();

  // Example private key bytes (32 bytes)

  // Example public key bytes (32 bytes)

  // Create the private key object
  final keyPair = cryptography.SimpleKeyPairData(
    privateKey,
    publicKey: cryptography.SimplePublicKey(publicKey,
        type: cryptography.KeyPairType.x25519),
    type: cryptography.KeyPairType.x25519,
  );

  // // Create the public key object
  final publicKeyBytes = cryptography.SimplePublicKey(publicKey,
      type: cryptography.KeyPairType.x25519);

  // Calculate the shared secret (pre-master secret)
  final sharedSecret = await algorithm.sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: publicKeyBytes,
  );

  // Extract the shared secret bytes
  final sharedSecretBytes = await sharedSecret.extractBytes();
  return (Uint8List.fromList(sharedSecretBytes), null);
}

Future<(Uint8List, Exception?)> generateExtendedMasterSecret(
    Uint8List preMasterSecret,
    Uint8List handshakeHash,
    HashAlgorithm hashAlgorithm) async {
  final seed = Uint8List.fromList(
      [...utf8.encode('extended master secret'), ...handshakeHash]);
  final (result, err) = await PHash(preMasterSecret, seed, 48, hashAlgorithm);
  return (result, null);
}

Future<(Uint8List, Exception?)> PHash(Uint8List secret, Uint8List seed,
    int requestedLength, HashAlgorithm hashAlgorithm) async {
  final hmac = pc.HMac(pc.SHA256Digest(), 64);
  hmac.init(pc.KeyParameter(secret));

  var result = Uint8List(requestedLength);
  var a = seed;
  var offset = 0;

  while (offset < requestedLength) {
    a = hmac.process(a);
    final output = hmac.process(Uint8List.fromList([...a, ...seed]));
    final remaining = requestedLength - offset;
    final toCopy = remaining < output.length ? remaining : output.length;
    result.setRange(offset, offset + toCopy, output);
    offset += toCopy;
  }

  return (result, null);
}

Future<(Uint8List, Exception?)> generateMasterSecret(
    Uint8List preMasterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom,
    HashAlgorithm hashAlgorithm) async {
  final seed = Uint8List.fromList(
      [...utf8.encode('master secret'), ...clientRandom, ...serverRandom]);
  final (result, err) = await PHash(preMasterSecret, seed, 48, hashAlgorithm);
  return (result, null);
}
