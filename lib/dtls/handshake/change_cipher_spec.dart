import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class ChangeCipherSpec {
  @override
  String toString() {
    return '[ChangeCipherSpec] Data: 1';
  }

  ContentType getContentType() {
    return ContentType.ChangeCipherSpec;
  }

  int decode(Uint8List buf, int offset, int arrayLen) {
    if (arrayLen < 1 || buf[offset] != 1) {
      offset++;
      throw ArgumentError('invalid cipher spec');
    }
    offset++;
    return offset;
  }

  Uint8List encode() {
    return Uint8List.fromList([0x01]);
  }
}
