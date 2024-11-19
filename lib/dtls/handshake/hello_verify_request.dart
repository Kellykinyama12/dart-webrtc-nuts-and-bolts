import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

// class DtlsVersion {
//   final int version;
//   DtlsVersion(this.version);

//   @override
//   String toString() => version.toString();
// }

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

  static (HelloVerifyRequest, int, Exception?) decode(
      Uint8List buf, int offset, int arrayLen) {
    DtlsVersion version =
        DtlsVersion.fromUint16((buf[offset] << 8) | buf[offset + 1]);
    offset += 2;

    var cookieLength = buf[offset];
    offset++;
    Uint8List cookie =
        Uint8List.fromList(buf.sublist(offset, offset + cookieLength));
    offset += cookieLength;

    return (HelloVerifyRequest(version: version, cookie: cookie), offset, null);
  }

  // Uint8List encode() {
  //   var result = Uint8List(3 + cookie.length);
  //   result[0] = version.major;
  //   result[1] = version.minor;
  //   result[2] = cookie.length;
  //   result.setRange(3, 3 + cookie.length, cookie);

  //   return result;
  // }

  Uint8List encode() {
    // Create a result Uint8List: 2 bytes for version, 1 byte for cookie length, and cookie bytes
    var result = Uint8List(3 + cookie.length);
    //final int intVersion = 0xFEFD;

    // Add version (big-endian)
    result[0] = version.major; // Version MSB
    result[1] = version.minor; // Version LSB

    // Add cookie length
    result[2] = cookie.length;

    // Add the cookie bytes
    result.setRange(3, 3 + cookie.length, cookie);

    return result;
  }
}
