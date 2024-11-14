import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/simple_extensions.dart';

class DtlsVersion {
  final int major;
  final int minor;

  DtlsVersion(this.major, this.minor);

  int toUint16() {
    return (major << 8) | minor;
  }

  factory DtlsVersion.fromUint16(int value) {
    return DtlsVersion((value >> 8) & 0xFF, value & 0xFF);
  }

  @override
  String toString() => '$major.$minor';
}

class Random {
  final Uint8List randomBytes;
  Random(this.randomBytes);

  Uint8List encode() => randomBytes;

  static Random decode(Uint8List buf, int offset) {
    return Random(Uint8List.fromList(buf.sublist(offset, offset + 32)));
  }
}

class ServerHello {
  DtlsVersion version;
  Random random;
  Uint8List sessionId;
  int cipherSuiteId;
  int compressionMethodId;
  Map<ExtensionType, Extension> extensions;

  ServerHello({
    required this.version,
    required this.random,
    required this.sessionId,
    required this.cipherSuiteId,
    required this.compressionMethodId,
    required this.extensions,
  });

  @override
  String toString() {
    var extensionsStr =
        extensions.values.map((ext) => ext.toString()).join('\n');
    return '[ServerHello] Ver: $version, SessionID: ${sessionId.length}\n'
        'Cipher Suite ID: 0x${cipherSuiteId.toRadixString(16)}\n'
        'Extensions:\n$extensionsStr';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerHello;
  }

  static (ServerHello, int, Exception?) decode(
      Uint8List buf, int offset, int arrayLen) {
    DtlsVersion version =
        DtlsVersion.fromUint16((buf[offset] << 8) | buf[offset + 1]);
    offset += 2;

    Random random = Random.decode(buf, offset);
    offset += 32;

    var sessionIdLength = buf[offset];
    offset++;
    Uint8List sessionId =
        Uint8List.fromList(buf.sublist(offset, offset + sessionIdLength));
    offset += sessionIdLength;

    int cipherSuiteId = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;

    int compressionMethodId = buf[offset];
    offset++;

    Map<ExtensionType, Extension> extensions = decodeExtensionMap(buf, offset);
    return (
      ServerHello(
          version: version,
          random: random,
          sessionId: sessionId,
          cipherSuiteId: cipherSuiteId,
          compressionMethodId: compressionMethodId,
          extensions: extensions),
      offset,
      null
    );
  }

  Uint8List encode() {
    var result = Uint8List(2 + 32 + 1 + sessionId.length + 2 + 1);
    result[0] = (version.toUint16() >> 8) & 0xff;
    result[1] = version.toUint16() & 0xff;
    result.setRange(2, 34, random.encode());
    result[34] = sessionId.length;
    result.setRange(35, 35 + sessionId.length, sessionId);
    result[35 + sessionId.length] = (cipherSuiteId >> 8) & 0xff;
    result[36 + sessionId.length] = cipherSuiteId & 0xff;
    result[37 + sessionId.length] = compressionMethodId;

    var encodedExtensions = encodeExtensionMap(extensions);
    return Uint8List.fromList(result + encodedExtensions);
  }
}

Map<ExtensionType, Extension> decodeExtensionMap(Uint8List buf, int offset) {
  var extensions = <ExtensionType, Extension>{};
  // Implement the decoding logic for extensions
  return extensions;
}

Uint8List encodeExtensionMap(Map<ExtensionType, Extension> extensions) {
  var encoded = <int>[];
  // Implement the encoding logic for extensions
  return Uint8List.fromList(encoded);
}
