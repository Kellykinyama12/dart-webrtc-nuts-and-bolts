import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:cryptography/cryptography.dart'; // For cryptography functions like signing

class CipherContext {
  late DtlsRandom localRandom;
  late DtlsRandom remoteRandom;
  late CipherSuites cipherSuite;
  Uint8List? remoteCertificate;
  late NamedCurveKeyPair remoteKeyPair;
  late NamedCurveKeyPair localKeyPair;
  late Uint8List masterSecret;
  late AEADCipher cipher;
  late NamedCurveAlgorithms namedCurve;
  SignatureHash? signatureHashAlgorithm;
  late Uint8List localCert;
  late PrivateKey localPrivateKey;

  CipherContext(
    this.sessionType, {
    this.certPem,
    this.keyPem,
    this.signatureHashAlgorithm,
  }) {
    if (certPem != null && keyPem != null && signatureHashAlgorithm != null) {
      parseX509(certPem!, keyPem!, signatureHashAlgorithm!);
    }
  }

  final SessionTypes sessionType;
  final String? certPem;
  final String? keyPem;

  static Future<Map<String, dynamic>> createSelfSignedCertificateWithKey(
      SignatureHash signatureHash,
      {NamedCurveAlgorithms? namedCurveAlgorithm}) async {
    String signatureAlgorithmName;
    String hash;
    String namedCurve;
    Map<String, dynamic> alg;

    // Determine signature algorithm
    switch (signatureHash.signature) {
      case SignatureAlgorithm.rsa_1:
        signatureAlgorithmName = 'RSASSA-PKCS1-v1_5';
        break;
      case SignatureAlgorithm.ecdsa_3:
        signatureAlgorithmName = 'ECDSA';
        break;
      default:
        signatureAlgorithmName = 'RSASSA-PKCS1-v1_5';
    }

    // Determine hash algorithm
    switch (signatureHash.hash) {
      case HashAlgorithm.sha256_4:
        hash = 'SHA-256';
        break;
      default:
        hash = 'SHA-256';
    }

    // Determine named curve for ECDSA
    switch (namedCurveAlgorithm) {
      case NamedCurveAlgorithm.secp256r1_23:
        namedCurve = 'P-256';
        break;
      case NamedCurveAlgorithm.x25519_29:
        if (signatureAlgorithmName == 'ECDSA') {
          namedCurve = 'P-256';
        } else {
          namedCurve = 'X25519';
        }
        break;
      default:
        namedCurve = 'P-256';
    }

    // Generate the key pair
    alg = {
      'name': signatureAlgorithmName,
      'hash': hash,
      'namedCurve': namedCurve,
    };

    final keyPair = await _generateKey(alg);

    // Generate self-signed certificate
    final certPem = await _generateCertificate(keyPair, alg, signatureHash);

    final keyPem = await _exportKeyToPem(keyPair.privateKey);

    return {
      'certPem': certPem,
      'keyPem': keyPem,
      'signatureHash': signatureHash
    };
  }

  Future<void> parseX509(
      String certPem, String keyPem, SignatureHash signatureHash) async {
    final cert = await X509Certificate.fromPem(certPem);
    final privateKey = await PrivateKey.fromPem(keyPem);

    this.localCert = cert.raw;
    this.localPrivateKey = privateKey;
    this.signatureHashAlgorithm = signatureHash;
  }

  DtlsPlaintext encryptPacket(DtlsPlaintext pkt) {
    final header = pkt.recordLayerHeader;
    final enc = this.cipher.encrypt(this.sessionType, pkt.fragment, {
      'type': header.contentType,
      'version': decodeVersion(header.protocolVersion),
      'epoch': header.epoch,
      'sequenceNumber': header.sequenceNumber,
    });
    pkt.fragment = enc;
    pkt.recordLayerHeader.contentLen = enc.length;
    return pkt;
  }

  DtlsPlaintext decryptPacket(DtlsPlaintext pkt) {
    final header = pkt.recordLayerHeader;
    final dec = this.cipher.decrypt(this.sessionType, pkt.fragment, {
      'type': header.contentType,
      'version': decodeVersion(header.protocolVersion),
      'epoch': header.epoch,
      'sequenceNumber': header.sequenceNumber,
    });
    return dec;
  }

  Future<Uint8List> verifyData(Uint8List buf) async {
    if (this.sessionType == SessionType.CLIENT) {
      return prfVerifyDataClient(this.masterSecret, buf);
    } else {
      return prfVerifyDataServer(this.masterSecret, buf);
    }
  }

  Future<Uint8List> signatureData(Uint8List data, String hash) async {
    final signature = await _createSignature(hash, data);
    final key = await _exportKeyToPem(this.localPrivateKey);
    return await _signData(signature, key);
  }

  Future<Uint8List> generateKeySignature(String hashAlgorithm) async {
    final clientRandom = this.sessionType == SessionType.CLIENT
        ? this.localRandom
        : this.remoteRandom;
    final serverRandom = this.sessionType == SessionType.SERVER
        ? this.localRandom
        : this.remoteRandom;

    final sig = await valueKeySignature(clientRandom.serialize(),
        serverRandom.serialize(), this.localKeyPair.publicKey, this.namedCurve);

    return await this.localPrivateKey.sign(sig, hashAlgorithm);
  }

  Future<Uint8List> valueKeySignature(Uint8List clientRandom,
      Uint8List serverRandom, Uint8List publicKey, int namedCurve) async {
    final serverParams = encodeServerParams(namedCurve, publicKey.length);
    return Uint8List.fromList([
      ...clientRandom,
      ...serverRandom,
      ...serverParams,
      ...publicKey,
    ]);
  }

  // Helper function to decode version
  int decodeVersion(Uint8List version) {
    return ByteData.sublistView(version).getUint16(0, Endian.big);
  }

  // Encode server parameters
  Uint8List encodeServerParams(int namedCurve, int len) {
    final encoded = encode(
      {
        'type': CurveType.named_curve_3,
        'curve': namedCurve,
        'len': len,
      },
      {'type': types.uint8, 'curve': types.uint16be, 'len': types.uint8},
    );
    return Uint8List.fromList(encoded);
  }

  // Placeholder for X509 Certificate parsing and key generation
  static Future<String> _generateCertificate(Map<String, dynamic> keyPair,
      Map<String, dynamic> alg, SignatureHash signatureHash) async {
    // You need to implement the certificate generation with the desired algorithm.
    return 'CERT_PEM_PLACEHOLDER';
  }

  static Future<String> _exportKeyToPem(PrivateKey key) async {
    // Implement the conversion of private key to PEM format.
    return 'PRIVATE_KEY_PEM_PLACEHOLDER';
  }

  static Future<Map<String, dynamic>> _generateKey(
      Map<String, dynamic> alg) async {
    // Implement key generation based on the algorithm.
    return {
      'privateKey': PrivateKey(),
      'publicKey': PublicKey(),
    };
  }

  Future<Uint8List> _createSignature(String hash, Uint8List data) async {
    // Placeholder for signature creation.
    return Uint8List.fromList([]);
  }

  Future<Uint8List> _signData(Uint8List signature, String key) async {
    // Implement the signing process using the private key.
    return Uint8List.fromList([]);
  }
}
