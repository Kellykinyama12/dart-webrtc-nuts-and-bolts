import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class ServerHelloDone {
  @override
  String toString() {
    return '[ServerHelloDone]';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerHelloDone;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    return offset;
  }

  Uint8List encode() {
    return Uint8List(0);
  }
}
