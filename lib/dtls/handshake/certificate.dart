import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_message.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class Certificate {
  List<Uint8List> certificates;

  Certificate({required this.certificates});

  @override
  String toString() {
    return '[Certificate] Certificates: ${certificates.isNotEmpty ? certificates[0].length : 0} bytes';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.Certificate;
  }

  int decode(Uint8List buf, int offset) {
    certificates = [];
    var length = Uint24.fromBytes(buf.sublist(offset, offset + 3));
    var lengthInt = length.toUint32();
    offset += 3;
    var offsetBackup = offset;

    while (offset < offsetBackup + lengthInt) {
      var certificateLength = Uint24.fromBytes(buf.sublist(offset, offset + 3));
      var certificateLengthInt = certificateLength.toUint32();
      offset += 3;

      var certificateBytes = Uint8List.fromList(
          buf.sublist(offset, offset + certificateLengthInt));
      offset += certificateLengthInt;
      certificates.add(certificateBytes);
    }
    return offset;
  }

  Uint8List encode() {
    var encodedCertificates = <int>[];
    for (var certificate in certificates) {
      var certificateLength = Uint24.fromUint32(certificate.length);
      encodedCertificates.addAll(certificateLength.bytes);
      encodedCertificates.addAll(certificate);
    }
    var length = Uint24.fromUint32(encodedCertificates.length);
    return Uint8List.fromList(length.bytes + encodedCertificates);
  }
}
