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

  static (ClientKeyExchange, int, Exception?) decode(
      Uint8List buf, int offset, int arrayLen) {
    var publicKeyLength = buf[offset];
    offset++;
    Uint8List publicKey =
        Uint8List.fromList(buf.sublist(offset, offset + publicKeyLength));
    offset += publicKeyLength;
    return (ClientKeyExchange(publicKey: publicKey), offset, null);
  }

  Uint8List encode() {
    var result = Uint8List(1 + publicKey.length);
    result[0] = publicKey.length;
    result.setRange(1, 1 + publicKey.length, publicKey);
    return result;
  }
}
