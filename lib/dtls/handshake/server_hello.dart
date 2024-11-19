import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_random.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/client_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/simple_extensions.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/utils.dart';

// class DtlsVersion {
//   final int major;
//   final int minor;

//   DtlsVersion(this.major, this.minor);

//   int toUint16() {
//     return (major << 8) | minor;
//   }

//   factory DtlsVersion.fromUint16(int value) {
//     return DtlsVersion((value >> 8) & 0xFF, value & 0xFF);
//   }

//   @override
//   String toString() => '$major.$minor';
// }

// class Random {
//   final Uint8List randomBytes;
//   Random(this.randomBytes);

//   Uint8List encode() => randomBytes;

//   static Random decode(Uint8List buf, int offset) {
//     return Random(Uint8List.fromList(buf.sublist(offset, offset + 32)));
//   }
// }

class ServerHello {
  DtlsVersion version;
  Random random;
  Uint8List sessionId;
  List<CipherSuiteID> cipherSuiteId;
  Uint8List compressionMethodIDs;
  Map<ExtensionType, dynamic> extensions;

  ServerHello({
    required this.version,
    required this.random,
    required this.sessionId,
    required this.cipherSuiteId,
    required this.compressionMethodIDs,
    required this.extensions,
  });

  @override
  String toString() {
    var extensionsStr =
        extensions!.values.map((ext) => ext.toString()).join('\n');
    return '[ServerHello] Ver: $version, SessionID: ${sessionId.length}\n'
        'Cipher Suite ID: $cipherSuiteId\n'
        'Extensions:\n$extensionsStr';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerHello;
  }

  Uint8List encode() {
    final buffer = BytesBuilder();

    // Encode the version (2 bytes)
    buffer.addByte(version.major);
    buffer.addByte(version.minor);

    // Encode the random (32 bytes)
    // buffer.add(convertTo4Bytes(
    //     clientHello.random.gmtUnixTime.millisecondsSinceEpoch ~/ 1000));
    buffer.add(random.encode());

    // Encode the session ID (1 byte for length, then the session ID)
    final sessionIDLength = sessionId.length;
    buffer.addByte(sessionIDLength);
    buffer.add(sessionId);

    // Encode the cookie (1 byte for length, then the cookie)
    //final cookieLength = cookie;
    //buffer.addByte(cookieLength);
    //buffer.add(cookie);

    // Encode the cipher suites (2 bytes for the length, then the cipher suites)
    final cipherSuiteIDs = encodeCipherSuiteIDs(cipherSuiteId);
    buffer.add(Uint8List.fromList(
        [cipherSuiteIDs.length ~/ 2])); // Length of cipher suites list
    buffer.add(cipherSuiteIDs);

    // Encode the compression methods (1 byte for the length, then the methods)
    final encodedCompressionMethodIDs =
        encodeCompressionMethodIDs(compressionMethodIDs);
    buffer.addByte(encodedCompressionMethodIDs.length);
    buffer.add(encodedCompressionMethodIDs);

    // Encode the extensions (length of extensions and the extensions themselves)
    final extensionsEncoded = encodeExtensionMap(extensions!);
    buffer.add(Uint8List.fromList(
        [extensionsEncoded.length ~/ 2])); // Length of extensions
    buffer.add(extensionsEncoded);

    // Return the final encoded ClientHello message
    return buffer.toBytes();
  }

  static (ServerHello, int, Exception?) decode(
      Uint8List buf, int offset, int arrayLen) {
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

    // var cookieLength = buf[offset];
    //offset++;
    //var cookie = buf.sublist(offset, offset + cookieLength);
    //offset += cookieLength;

    var cipherSuiteIDs = decodeCipherSuiteIDs(buf, offset, arrayLen);
    offset += 2 + cipherSuiteIDs.length * 2;

    var compressionMethodIDs =
        decodeCompressionMethodIDs(buf, offset, arrayLen);
    offset += 1 + compressionMethodIDs.length;

    var (extensions, decodedOffset, err) =
        decodeExtensionMap(buf, offset, arrayLen);

    return (
      ServerHello(
        version: version,
        random: random,
        //cookie: cookie,
        sessionId: sessionID,
        cipherSuiteId: cipherSuiteIDs,
        compressionMethodIDs: compressionMethodIDs,
        extensions: extensions!,
      ),
      offset,
      null
    );
  }
}

  // static (ServerHello, int, Exception?) decode(
  //     Uint8List buf, int offset, int arrayLen) {
  //   DtlsVersion version =
  //       DtlsVersion.fromUint16((buf[offset] << 8) | buf[offset + 1]);
  //   offset += 2;

  //   Random random = Random.decode(buf, offset);
  //   offset += 32;

  //   var sessionIdLength = buf[offset];
  //   offset++;
  //   Uint8List sessionId =
  //       Uint8List.fromList(buf.sublist(offset, offset + sessionIdLength));
  //   offset += sessionIdLength;

  //   int cipherSuiteId = (buf[offset] << 8) | buf[offset + 1];
  //   offset += 2;

  //   int compressionMethodId = buf[offset];
  //   offset++;

  //   var (decodedExtensions, decodedOffset, err) =
  //       decodeExtensionMap(buf, offset, arrayLen);
  //   return (
  //     ServerHello(
  //         version: version,
  //         random: random,
  //         sessionId: sessionId,
  //         cipherSuiteId: cipherSuiteId,
  //         compressionMethodId: compressionMethodId,
  //         extensions: decodedExtensions),
  //     offset,
  //     null
  //   );
  //}

 

  // Uint8List encode() {
  //   var result = Uint8List(2 + 32 + 1 + sessionId.length + 2 + 1);
  //   result[0] = (version.toUint16() >> 8) & 0xff;
  //   result[1] = version.toUint16() & 0xff;
  //   result.setRange(2, 34, random.encode());
  //   result[34] = sessionId.length;
  //   result.setRange(35, 35 + sessionId.length, sessionId);
  //   result[35 + sessionId.length] = (cipherSuiteId >> 8) & 0xff;
  //   result[36 + sessionId.length] = cipherSuiteId & 0xff;
  //   result[37 + sessionId.length] = compressionMethodId;

  //   var encodedExtensions = encodeExtensionMap(extensions);
  //   return Uint8List.fromList(result + encodedExtensions);
  // }
//}

// Uint8List encodeExtensionMap(Map<ExtensionType, Extension> extensions) {
//   // var encoded = <int>[];
//   BytesBuilder bb = BytesBuilder();
//   // Implement the encoding logic for extensions
//   return Uint8List.fromList(extensions);
// }





