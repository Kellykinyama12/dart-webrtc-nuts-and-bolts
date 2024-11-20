import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto_gcm.dart';
import 'package:pointycastle/export.dart';
import 'package:basic_utils/basic_utils.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart'
    as cryptography; // Add this import

import 'package:basic_utils/basic_utils.dart' as cryptoUtils;

import 'package:asn1lib/asn1lib.dart';

class EncryptionKeys {
  final Uint8List masterSecret;
  final Uint8List clientWriteKey;
  final Uint8List serverWriteKey;
  final Uint8List clientWriteIV;
  final Uint8List serverWriteIV;

  EncryptionKeys({
    required this.masterSecret,
    required this.clientWriteKey,
    required this.serverWriteKey,
    required this.clientWriteIV,
    required this.serverWriteIV,
  });
}

class EcdsaSignature {
  BigInt r, s;
  EcdsaSignature(this.r, this.s);
}

String generateSelfSignedCertificate() {
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
  return x509PEM;
  //return Uint16List.fromList(utf8.encode(x509PEM));
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

// Future<Uint8List> generateSelfSignedCertificate(cryptography.KeyPair keyPair, PublicKey publicKey) async {
//   final asn1Sequence = ASN1Sequence();

//   // Add version
//   final version = ASN1Integer(BigInt.from(2));
//   asn1Sequence.add(version);

//   // Add serial number
//   final serialNumber = ASN1Integer(BigInt.from(1));
//   asn1Sequence.add(serialNumber);

//   // Add signature algorithm
//   final signatureAlgorithm = ASN1Sequence();
//   signatureAlgorithm.add(ASN1ObjectIdentifier.fromName('ecdsa-with-SHA256'));
//   asn1Sequence.add(signatureAlgorithm);

//   // Add issuer
//   final issuer = ASN1Sequence();
//   issuer.add(ASN1Set()..add(ASN1Sequence()..add(ASN1ObjectIdentifier.fromName('commonName'))..add(ASN1UTF8String('Self-Signed'))));
//   asn1Sequence.add(issuer);

//   // Add validity
//   final validity = ASN1Sequence();
//   validity.add(ASN1UtcTime(DateTime.now()));
//   validity.add(ASN1UtcTime(DateTime.now().add(Duration(days: 365))));
//   asn1Sequence.add(validity);

//   // Add subject
//   final subject = ASN1Sequence();
//   subject.add(ASN1Set()..add(ASN1Sequence()..add(ASN1ObjectIdentifier.fromName('commonName'))..add(ASN1UTF8String('Self-Signed'))));
//   asn1Sequence.add(subject);

//   // Add public key
//   final publicKeyBytes = (publicKey as cryptography.EcPublicKey).toBytes;
//   final publicKeyInfo = ASN1Sequence();
//   publicKeyInfo.add(ASN1Sequence()..add(ASN1ObjectIdentifier.fromName('ecPublicKey'))..add(ASN1ObjectIdentifier.fromName('secp256r1')));
//   publicKeyInfo.add(ASN1BitString(Uint8List.fromList(publicKeyBytes)));
//   asn1Sequence.add(publicKeyInfo);

//   // Sign the certificate
//   final signature = ASN1BitString(Uint8List.fromList([])); // Placeholder for signature
//   asn1Sequence.add(signature);

//   return asn1Sequence.encodedBytes;
// }

Future<Uint8List> generateServerCertificate(String cn) async {
  final keyPair = await generateServerCertificatePrivateKey();
  final privateKey = keyPair.privateKey as ECPrivateKey;
  final publicKey = keyPair.publicKey as ECPublicKey;

  // Generate a serial number within the valid range
  final serialNumber = BigInt.from(Random.secure().nextInt(1 << 32));

  final subject = 'CN=$cn';
  final issuer = subject;

  var dn = {
    'CN': cn,
  };
  print("Generating ECC CSR PEM");
  var csr = X509Utils.generateEccCsrPem(dn, privateKey, publicKey);

  var x509PEM = X509Utils.generateSelfSignedCertificate(privateKey, csr, 365,
      serialNumber: serialNumber.toString(), issuer: dn);

  return Uint8List.fromList(utf8.encode(x509PEM));
}

String generateSelfSignedCertificateKelly() {
  AsymmetricKeyPair<PublicKey, PrivateKey> pair =
      CryptoUtils.generateEcKeyPair();
  var privKey = pair.privateKey as ECPrivateKey;
  var pubKey = pair.publicKey as ECPublicKey;
  var dn = {
    'CN': 'Self-Signed',
  };
  var csr = X509Utils.generateEccCsrPem(dn, privKey, pubKey);

  var x509PEM = X509Utils.generateSelfSignedCertificate(
    privKey,
    csr,
    365,
  );
  return x509PEM;
}

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
    ECPrivateKey privateKey) async {
  final msg =
      generateValueKeyMessage(clientRandom, serverRandom, publicKey, curve);
  final digest = SHA256Digest().process(msg);
  final signer = Signer('SHA-256/ECDSA');
  signer.init(true, PrivateKeyParameter<ECPrivateKey>(privateKey));
  final sig = signer.generateSignature(digest) as ECSignature;
  return Uint8List.fromList(
      [...bigIntToUint8List(sig.r), ...bigIntToUint8List(sig.s)]);
}

Uint8List bigIntToUint8List(BigInt number) {
  var hexString = number.toRadixString(16);
  if (hexString.length % 2 != 0) {
    hexString = '0' + hexString; // Ensure even length
  }
  return Uint8List.fromList(hex.decode(hexString));
}

String getCertificateFingerprint(Uint8List certificate) {
  print(utf8.decode(certificate));
  final digest = SHA256Digest().process(certificate);
  return digest
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join(':')
      .toUpperCase();
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

Future<(Uint8List, Exception?)> generateExtendedMasterSecret(
    Uint8List preMasterSecret,
    Uint8List handshakeHash,
    HashAlgorithm hashAlgorithm) async {
  final seed = Uint8List.fromList(
      [...utf8.encode('extended master secret'), ...handshakeHash]);
  final (result, err) = await PHash(preMasterSecret, seed, 48, hashAlgorithm);
  return (result, null);
}

Future<Uint8List> generateKeyingMaterial(
    Uint8List masterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom,
    int length,
    HashAlgorithm hashAlgorithm) async {
  final seed = Uint8List.fromList([
    ...utf8.encode('EXTRACTOR-dtls_srtp'),
    ...clientRandom,
    ...serverRandom
  ]);
  final (result, err) = await PHash(masterSecret, seed, length, hashAlgorithm);
  return result;
}

Future<(Uint8List, Exception?)> PHash(Uint8List secret, Uint8List seed,
    int requestedLength, HashAlgorithm hashAlgorithm) async {
  final hmac = HMac(SHA256Digest(), 64);
  hmac.init(KeyParameter(secret));

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

Future<(GCM?, Exception?)> initGCM(Uint8List masterSecret,
    Uint8List clientRandom, Uint8List serverRandom, CipherSuite cipherSuite)
//  (*GCM, error)
async {
  //https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/internal/ciphersuite/tls_ecdhe_ecdsa_with_aes_128_gcm_sha256.go#L60
  //const (
  const prfKeyLen = 16;
  const prfIvLen = 4;
  //)
  // logging.Descf(logging.ProtoCRYPTO, "Initializing GCM with Key Length: <u>%d</u>, IV Length: <u>%d</u>, these values are constants of <u>%s</u> cipher suite.",
  // 	prfKeyLen, prfIvLen, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")

  var (keys, err) = await generateEncryptionKeys(masterSecret, clientRandom,
      serverRandom, prfKeyLen, prfIvLen, cipherSuite.hashAlgorithm);
  if (err != null) {
    return (null, err);
  }

  //logging.Descf(logging.ProtoCRYPTO, "Generated encryption keys from keying material (Key Length: <u>%d</u>, IV Length: <u>%d</u>) (<u>%d bytes</u>)\n\tMasterSecret: <u>0x%x</u> (<u>%d bytes</u>)\n\tClientWriteKey: <u>0x%x</u> (<u>%d bytes</u>)\n\tServerWriteKey: <u>0x%x</u> (<u>%d bytes</u>)\n\tClientWriteIV: <u>0x%x</u> (<u>%d bytes</u>)\n\tServerWriteIV: <u>0x%x</u> (<u>%d bytes</u>)",
  // prfKeyLen, prfIvLen, prfKeyLen*2+prfIvLen*2,
  // keys.MasterSecret, len(keys.MasterSecret),
  // keys.ClientWriteKey, len(keys.ClientWriteKey),
  // keys.ServerWriteKey, len(keys.ServerWriteKey),
  // keys.ClientWriteIV, len(keys.ClientWriteIV),
  // keys.ServerWriteIV, len(keys.ServerWriteIV))

  GCM gcm = await GCM.create(keys!.serverWriteKey, keys.serverWriteIV,
      keys.clientWriteKey, keys.clientWriteIV);

  return (gcm, null);
}

Future<(EncryptionKeys?, Exception?)> generateEncryptionKeys(
    Uint8List masterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom,
    int keyLen,
    int ivLen,
    HashAlgorithm hashAlgorithm)
//  (*EncryptionKeys, error)
async {
  //https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/prf/prf.go#L199
  //logging.Descf(logging.ProtoCRYPTO, "Generating encryption keys with Key Length: <u>%d</u>, IV Length: <u>%d</u> via <u>%s</u>, using Master Secret, Server Random, Client Random...", keyLen, ivLen, hashAlgorithm)
  //seed := append(append([]byte("key expansion"), serverRandom...), clientRandom...)
  Uint8List seed = Uint8List.fromList([...serverRandom, ...clientRandom]);
  var (keyMaterial, err) = await PHash(
      masterSecret, seed, (2 * keyLen) + (2 * ivLen), hashAlgorithm);
  if (err != null) {
    return (null, err);
  }

  Uint8List clientWriteKey = keyMaterial.sublist(0, keyLen);
  keyMaterial = keyMaterial.sublist(keyLen);

  Uint8List serverWriteKey = keyMaterial.sublist(0, keyLen);
  keyMaterial = keyMaterial.sublist(keyLen);

  Uint8List clientWriteIV = keyMaterial.sublist(0, ivLen);
  keyMaterial = keyMaterial.sublist(ivLen);

  Uint8List serverWriteIV = keyMaterial.sublist(0, ivLen);

  return (
    EncryptionKeys(
      masterSecret: masterSecret,
      clientWriteKey: clientWriteKey,
      serverWriteKey: serverWriteKey,
      clientWriteIV: clientWriteIV,
      serverWriteIV: serverWriteIV,
    ),
    null
  );
}
