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
  CipherSuite cipherSuite;
  int compressionMethodID;
  Map<ExtensionType, dynamic>? extensions;

  ServerHello({
    required this.version,
    required this.random,
    required this.sessionId,
    required this.cipherSuite,
    required this.compressionMethodID,
    required this.extensions,
  });

  @override
  String toString() {
    var extensionsStr =
        extensions!.values.map((ext) => ext.toString()).join('\n');
    return '[ServerHello] Ver: $version, SessionID: ${sessionId.length}\n'
        'Cipher Suite ID: $cipherSuite\n'
        'Extensions:\n$extensionsStr';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerHello;
  }

  Uint8List encode() {
    // Calculate total length dynamically
    final randomBytesLength = random.randomBytes.length;
    final sessionIDLength = sessionId.length;

    // Encode extensions and get their length
    final extensionsEncoded = encodeExtensionMap(extensions!);
    final extensionsLength = extensionsEncoded.length;

    // Allocate buffer for all components
    final totalLength = 2 +
        (4 + randomBytesLength) +
        1 +
        sessionIDLength +
        2 +
        1 +
        extensionsLength;
    final byteData = BytesBuilder();

    // Write the protocol version (DtlsVersion) in big-endian order
    byteData.add(int16ToUint8List(version.toUint16()));

    // Encode and write the Random structure
    byteData.add(random.encode());

    // Write the Session ID length and value
    byteData.addByte(sessionIDLength);
    byteData.add(sessionId);

    // Write the Cipher Suite ID
    byteData.add(int16ToUint8List(cipherSuite.id.value));

    // Write the Compression Method ID
    byteData.addByte(compressionMethodID);

    // Write the encoded Extensions
    byteData.add(extensionsEncoded);

    // Return the final Uint8List
    return byteData.toBytes();
  }

  static (ServerHello, int, Exception?) decode(
      Uint8List buf, int offset, int arrayLen)
  //(int, error)
  {
    // https://github.com/pion/dtls/blob/680c851ed9efc926757f7df6858c82ac63f03a5d/pkg/protocol/handshake/message_client_hello.go#L66

    DtlsVersion version = DtlsVersion.fromUint16(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;

    var random = decodeRandom(buf, offset, arrayLen);
    offset += 4 + randomBytesLength;

    var sessionIDLength = buf[offset];
    offset++;
    var sessionID = buf.sublist(offset, offset + sessionIDLength);
    offset += sessionIDLength;

    CipherSuiteID cipherSuiteID = CipherSuiteID(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;

    var compressionMethodID = buf[offset];
    offset++;

    var (extensions, decodedOffset, err) =
        decodeExtensionMap(buf, offset, arrayLen);

    offset = offset + decodedOffset;
    return (
      ServerHello(
          version: version,
          random: random,
          sessionId: sessionID,
          cipherSuite: CipherSuite(
            id: cipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            keyExchangeAlgorithm: keyExchangeAlgorithmECDHE,
            certificateType: certificateTypeECDSASign,
            hashAlgorithm: hashAlgorithmSHA256,
            signatureAlgorithm: signatureAlgorithmECDSA,
          ),
          compressionMethodID: compressionMethodID,
          extensions: extensions),
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





