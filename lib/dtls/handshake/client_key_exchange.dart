import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class ClientKeyExchange {
  Uint8List publicKey;

  ClientKeyExchange({required this.publicKey});

  @override
  String toString() {
    return '[ClientKeyExchange] PublicKey: 0x${publicKey.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ClientKeyExchange;
  }

  int decode(Uint8List buf, int offset) {
    var publicKeyLength = buf[offset];
    offset++;
    publicKey =
        Uint8List.fromList(buf.sublist(offset, offset + publicKeyLength));
    offset += publicKeyLength;
    return offset;
  }

  Uint8List encode() {
    var result = Uint8List(1 + publicKey.length);
    result[0] = publicKey.length;
    result.setRange(1, 1 + publicKey.length, publicKey);
    return result;
  }
}
