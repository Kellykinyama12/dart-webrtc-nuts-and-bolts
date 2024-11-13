import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/algo_pair.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class CertificateType {
  final int value;
  const CertificateType(this.value);

  @override
  String toString() => 'CertificateType($value)';
}

class CertificateRequest {
  List<CertificateType> certificateTypes;
  List<AlgoPair> algoPairs;

  CertificateRequest({
    required this.certificateTypes,
    required this.algoPairs,
  });

  @override
  String toString() {
    return '[CertificateRequest] CertificateTypes: $certificateTypes, AlgoPairs: $algoPairs';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.CertificateRequest;
  }

  int decode(Uint8List buf, int offset) {
    var certificateTypeCount = buf[offset];
    offset++;
    certificateTypes = List.generate(
        certificateTypeCount, (i) => CertificateType(buf[offset + i]));
    offset += certificateTypeCount;

    var algoPairLength = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    var algoPairCount = algoPairLength ~/ 2;
    algoPairs = List.generate(algoPairCount, (i) {
      var algoPair = AlgoPair(
        hashAlgorithm: HashAlgorithm(buf[offset]),
        signatureAlgorithm: SignatureAlgorithm(buf[offset + 1]),
      );
      offset += 2;
      return algoPair;
    });

    offset += 2; // Distinguished Names Length

    return offset;
  }

  Uint8List encode() {
    var result = <int>[];
    result.add(certificateTypes.length);
    result.addAll(certificateTypes.map((type) => type.value));

    var encodedAlgoPairs = algoPairs.expand((pair) => pair.encode()).toList();
    result.addAll([
      (encodedAlgoPairs.length >> 8) & 0xff,
      encodedAlgoPairs.length & 0xff
    ]);
    result.addAll(encodedAlgoPairs);
    result.addAll([0x00, 0x00]); // Distinguished Names Length

    return Uint8List.fromList(result);
  }
}
