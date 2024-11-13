import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class DtlsVersion {
  final int version;
  DtlsVersion(this.version);

  @override
  String toString() => version.toString();
}

class HelloVerifyRequest {
  DtlsVersion version;
  Uint8List cookie;

  HelloVerifyRequest({required this.version, required this.cookie});

  @override
  String toString() {
    var cookieStr = cookie.isEmpty ? '' : '0x${hex.encode(cookie)}';
    return '[HelloVerifyRequest] Ver: $version, Cookie: $cookieStr';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.HelloVerifyRequest;
  }

  int decode(Uint8List buf, int offset) {
    version = DtlsVersion((buf[offset] << 8) | buf[offset + 1]);
    offset += 2;

    var cookieLength = buf[offset];
    offset++;
    cookie = Uint8List.fromList(buf.sublist(offset, offset + cookieLength));
    offset += cookieLength;

    return offset;
  }

  Uint8List encode() {
    var result = Uint8List(3 + cookie.length);
    result[0] = (version.version >> 8) & 0xff;
    result[1] = version.version & 0xff;
    result[2] = cookie.length;
    result.setRange(3, 3 + cookie.length, cookie);

    return result;
  }
}
