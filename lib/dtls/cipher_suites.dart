import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

class CipherSuiteID {
  final int value;
  const CipherSuiteID(this.value);

  @override
  String toString() {
    switch (value) {
      case 0xc02b:
        return 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0x${value.toRadixString(16)})';
      default:
        return 'Unknown Cipher Suite (0x${value.toRadixString(16)})';
    }
  }
}

class CurveType {
  final int value;
  const CurveType(this.value);

  @override
  String toString() {
    switch (value) {
      case 0x03:
        return 'NamedCurve (0x${value.toRadixString(16)})';
      default:
        return 'Unknown Curve Type (0x${value.toRadixString(16)})';
    }
  }
}

class Curve {
  final int value;
  const Curve(this.value);

  @override
  String toString() {
    switch (value) {
      case 0x001d:
        return 'X25519 (0x${value.toRadixString(16)})';
      default:
        return 'Unknown Curve (0x${value.toRadixString(16)})';
    }
  }
}

class PointFormat {
  final int value;
  const PointFormat(this.value);

  @override
  String toString() {
    switch (value) {
      case 0:
        return 'Uncompressed (0x${value.toRadixString(16)})';
      default:
        return 'Unknown Point Format (0x${value.toRadixString(16)})';
    }
  }
}

class HashAlgorithm {
  final int value;
  const HashAlgorithm(this.value);

  Uint8List execute(Uint8List input) {
    switch (value) {
      case 4: // HashAlgorithmSHA256
        var digest = sha256.convert(input);
        return Uint8List.fromList(digest.bytes);
      default:
        throw ArgumentError('Unsupported hash algorithm');
    }
  }

  @override
  String toString() {
    switch (value) {
      case 4:
        return 'SHA256 (0x${value.toRadixString(16)})';
      default:
        return 'Unknown Hash Algorithm (0x${value.toRadixString(16)})';
    }
  }
}

class SignatureAlgorithm {
  final int value;
  const SignatureAlgorithm(this.value);

  @override
  String toString() {
    switch (value) {
      case 3:
        return 'ECDSA (0x${value.toRadixString(16)})';
      default:
        return 'Unknown Signature Algorithm (0x${value.toRadixString(16)})';
    }
  }
}

class CertificateType {
  final int value;
  const CertificateType(this.value);

  @override
  String toString() {
    switch (value) {
      case 64:
        return 'ECDSASign (0x${value.toRadixString(16)})';
      default:
        return 'Unknown Certificate Type (0x${value.toRadixString(16)})';
    }
  }
}

class KeyExchangeAlgorithm {
  final int value;
  const KeyExchangeAlgorithm(this.value);

  @override
  String toString() {
    switch (value) {
      case 0:
        return 'None';
      case 1:
        return 'ECDHE';
      default:
        return 'Unknown Key Exchange Algorithm (0x${value.toRadixString(16)})';
    }
  }
}

class SRTPProtectionProfile {
  final int value;
  const SRTPProtectionProfile(this.value);

  @override
  String toString() {
    switch (value) {
      case 0x0007:
        return 'SRTP_AEAD_AES_128_GCM (0x${value.toRadixString(16)})';
      default:
        return 'Unknown SRTP Protection Profile (0x${value.toRadixString(16)})';
    }
  }
}

class CipherSuite {
  final CipherSuiteID id;
  final KeyExchangeAlgorithm keyExchangeAlgorithm;
  final CertificateType certificateType;
  final HashAlgorithm hashAlgorithm;
  final SignatureAlgorithm signatureAlgorithm;

  const CipherSuite({
    required this.id,
    required this.keyExchangeAlgorithm,
    required this.certificateType,
    required this.hashAlgorithm,
    required this.signatureAlgorithm,
  });

  @override
  String toString() {
    return 'ID: $id, KeyExchangeAlgorithm: $keyExchangeAlgorithm, CertificateType: $certificateType, HashAlgorithm: $hashAlgorithm, SignatureAlgorithm: $signatureAlgorithm';
  }
}

const CipherSuiteID cipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = CipherSuiteID(0xc02b);
const CurveType curveTypeNamedCurve = CurveType(0x03);
const Curve curveX25519 = Curve(0x001d);
const PointFormat pointFormatUncompressed = PointFormat(0);
const HashAlgorithm hashAlgorithmSHA256 = HashAlgorithm(4);
const SignatureAlgorithm signatureAlgorithmECDSA = SignatureAlgorithm(3);
const CertificateType certificateTypeECDSASign = CertificateType(64);
const KeyExchangeAlgorithm keyExchangeAlgorithmNone = KeyExchangeAlgorithm(0);
const KeyExchangeAlgorithm keyExchangeAlgorithmECDHE = KeyExchangeAlgorithm(1);
const SRTPProtectionProfile srtpProtectionProfile_AEAD_AES_128_GCM = SRTPProtectionProfile(0x0007);

final Map<Curve, bool> supportedCurves = {
  curveX25519: true,
};

final Map<SRTPProtectionProfile, bool> supportedSRTPProtectionProfiles = {
  srtpProtectionProfile_AEAD_AES_128_GCM: true,
};

final Map<CipherSuiteID, CipherSuite> supportedCipherSuites = {
  cipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: CipherSuite(
    id: cipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    keyExchangeAlgorithm: keyExchangeAlgorithmECDHE,
    certificateType: certificateTypeECDSASign,
    hashAlgorithm: hashAlgorithmSHA256,
    signatureAlgorithm: signatureAlgorithmECDSA,
  ),
};

// void main() {
//   // Example usage of HashAlgorithm execute method
//   Uint8List input = Uint8List.fromList(utf8.encode('Hello, world!'));
//   HashAlgorithm hashAlgorithm = hashAlgorithmSHA256;
//   Uint8List output = hashAlgorithm.execute(input);
//   print('Hash output: $output');

//   // Example usage of supported configurations
//   print('Supported Curves: $supportedCurves');
//   print('Supported SRTP Protection Profiles: $supportedSRTPProtectionProfiles');
//   print('Supported Cipher Suites: $supportedCipherSuites');
// }