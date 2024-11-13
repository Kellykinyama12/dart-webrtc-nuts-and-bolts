import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/algo_pair.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class CertificateVerify {
  AlgoPair algoPair;
  Uint8List signature;

  CertificateVerify({
    required this.algoPair,
    required this.signature,
  });

  @override
  String toString() {
    return '[CertificateVerify] AlgoPair: $algoPair, Signature: 0x${signature.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.CertificateVerify;
  }

  int decode(Uint8List buf, int offset) {
    algoPair = AlgoPair(
      hashAlgorithm: HashAlgorithm(buf[offset]),
      signatureAlgorithm: SignatureAlgorithm(buf[offset + 1]),
    );
    offset += 2;

    var signatureLength = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    signature =
        Uint8List.fromList(buf.sublist(offset, offset + signatureLength));
    offset += signatureLength;

    return offset;
  }

  Uint8List encode() {
    var result = Uint8List(2 + 2 + signature.length);
    result.setRange(0, 2, algoPair.encode());
    result[2] = (signature.length >> 8) & 0xff;
    result[3] = signature.length & 0xff;
    result.setRange(4, 4 + signature.length, signature);

    return result;
  }
}
