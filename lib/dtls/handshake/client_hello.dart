import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_random.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/simple_extensions.dart';

import 'package:convert/convert.dart';

class ClientHello {
  DtlsVersion version;
  Random random;
  Uint8List cookie;
  Uint8List sessionID;
  List<CipherSuiteID> cipherSuiteIDs;
  Uint8List compressionMethodIDs;
  Map<ExtensionType, Extension> extensions;

  ClientHello({
    required this.version,
    required this.random,
    required this.cookie,
    required this.sessionID,
    required this.cipherSuiteIDs,
    required this.compressionMethodIDs,
    required this.extensions,
  });

  @override
  String toString() {
    var extensionsStr =
        extensions.values.map((ext) => ext.toString()).join('\n');
    var cipherSuiteIDsStr =
        cipherSuiteIDs.map((cs) => cs.toString()).join(', ');
    var cookieStr = cookie.isEmpty ? '' : '0x${hex.encode(cookie)}';

    return '[ClientHello] Ver: $version, Cookie: $cookieStr, SessionID: ${hex.encode(sessionID)}\n'
        'Cipher Suite IDs: $cipherSuiteIDsStr\n'
        'Extensions:\n$extensionsStr';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ClientHello;
  }

  Uint8List encode() {
    // Implement encoding logic here
    return Uint8List(0);
  }

  static ClientHello decode(Uint8List buf, int offset, int arrayLen) {
    if (arrayLen < offset + 2) {
      throw ArgumentError(
          'Buffer too small to contain a valid ClientHello structure');
    }

    var version = DtlsVersion.fromUint16(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;

    var random = decodeRandom(buf, offset, arrayLen);
    offset += 4 + randomBytesLength;

    var sessionIDLength = buf[offset];
    offset++;
    var sessionID = buf.sublist(offset, offset + sessionIDLength);
    offset += sessionIDLength;

    var cookieLength = buf[offset];
    offset++;
    var cookie = buf.sublist(offset, offset + cookieLength);
    offset += cookieLength;

    var cipherSuiteIDs = decodeCipherSuiteIDs(buf, offset, arrayLen);
    offset += 2 + cipherSuiteIDs.length * 2;

    var compressionMethodIDs =
        decodeCompressionMethodIDs(buf, offset, arrayLen);
    offset += 1 + compressionMethodIDs.length;

    var extensions = decodeExtensionMap(buf, offset, arrayLen);

    return ClientHello(
      version: version,
      random: random,
      cookie: cookie,
      sessionID: sessionID,
      cipherSuiteIDs: cipherSuiteIDs,
      compressionMethodIDs: compressionMethodIDs,
      extensions: extensions,
    );
  }
}

List<CipherSuiteID> decodeCipherSuiteIDs(
    Uint8List buf, int offset, int arrayLen) {
  var length =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
  var count = length ~/ 2;
  offset += 2;
  var result = List<CipherSuiteID>.generate(count, (i) {
    var id = CipherSuiteID(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;
    return id;
  });
  return result;
}

Uint8List decodeCompressionMethodIDs(Uint8List buf, int offset, int arrayLen) {
  var count = buf[offset];
  offset++;
  return buf.sublist(offset, offset + count);
}

Map<ExtensionType, Extension> decodeExtensionMap(
    Uint8List buf, int offset, int arrayLen) {
  // Implement decoding logic for extensions
  return {};
}
