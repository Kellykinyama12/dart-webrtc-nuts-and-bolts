import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:pointycastle/export.dart';
//import 'package:basic_utils/basic_utils.dart';
//import 'package:convert/convert.dart';
//import 'package:cryptography/cryptography.dart'
//    as cryptography; // Add this import

import 'package:basic_utils/basic_utils.dart' as cryptoUtils;

//import 'package:asn1lib/asn1lib.dart';

class EcdsaSignature {
  BigInt r, s;
  EcdsaSignature(this.r, this.s);
}

Uint8List generateSelfSignedCertificate() {
  cryptoUtils.AsymmetricKeyPair<cryptoUtils.PublicKey, cryptoUtils.PrivateKey>
      pair = cryptoUtils.CryptoUtils.generateEcKeyPair();
  var privKey = pair.privateKey as cryptoUtils.ECPrivateKey;
  var pubKey = pair.publicKey as cryptoUtils.ECPublicKey;
  var dn = {
    'CN': 'Self-Signed',
  };
  var csr = cryptoUtils.X509Utils.generateEccCsrPem(dn, privKey, pubKey);

  var x509PEM = cryptoUtils.X509Utils.generateSelfSignedCertificate(
    privKey,
    csr,
    365,
  );
  //return x509PEM;
  return Uint8List.fromList(utf8.encode(x509PEM));
}

// Future<AsymmetricKeyPair<PublicKey, PrivateKey>>
//     generateServerCertificatePrivateKey() async {
//   print("Generating ecc private key");
//   final keyParams = ECKeyGeneratorParameters(ECCurve_secp256r1());
//   final random = FortunaRandom();
//   final keyGen = ECKeyGenerator();
//   keyGen.init(ParametersWithRandom(keyParams, random));
//   return keyGen.generateKeyPair();
// }

Future<AsymmetricKeyPair<PublicKey, PrivateKey>>
    generateServerCertificatePrivateKey() async {
  print("Generating ECC private key");
  final keyParams = ECKeyGeneratorParameters(ECCurve_secp256r1());
  final random = FortunaRandom();

  // Seed the random number generator
  final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => Random.secure().nextInt(256)));
  random.seed(KeyParameter(seed));

  final keyGen = ECKeyGenerator();
  keyGen.init(ParametersWithRandom(keyParams, random));
  return keyGen.generateKeyPair();
}
