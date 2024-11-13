import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';

class AlgoPair {
  HashAlgorithm hashAlgorithm;
  SignatureAlgorithm signatureAlgorithm;

  AlgoPair({
    required this.hashAlgorithm,
    required this.signatureAlgorithm,
  });

  @override
  String toString() {
    return '{HashAlg: $hashAlgorithm, Signature Alg: $signatureAlgorithm}';
  }

  static (AlgoPair, int) decode(Uint8List buf, int offset, int arrayLength) {
    HashAlgorithm hashAlgorithm = HashAlgorithm(buf[offset]);
    offset += 1;
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm(buf[offset]);
    offset += 1;

    return (
      AlgoPair(
        hashAlgorithm: hashAlgorithm,
        signatureAlgorithm: signatureAlgorithm,
      ),
      offset
    );
  }

  Uint8List encode() {
    return Uint8List.fromList([
      hashAlgorithm.value,
      signatureAlgorithm.value,
    ]);
  }
}
