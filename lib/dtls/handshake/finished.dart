import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class Finished {
  List<int> verifyData;

  Finished({required this.verifyData});

  @override
  String toString() {
    return '[Finished] VerifyData: 0x${verifyData.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()} (${verifyData.length} bytes)';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.Finished;
  }

  static (Finished, int, Exception?) decode(
      Uint8List buf, int offset, int arrayLen) {
    Uint8List verifyData = buf.sublist(offset, offset + arrayLen);
    return (Finished(verifyData: verifyData), offset + arrayLen, null);
  }

  Uint8List encode() {
    return Uint8List.fromList(verifyData);
  }
}
