import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/simple_extensions.dart';

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
  Map<ExtensionType, dynamic>? extensions;

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
        extensions!.values.map((ext) => ext.toString()).join('\n');
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

    var (extensions, decodedOffset, err) =
        decodeExtensionMap(buf, offset, arrayLen);
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

  Uint8List encodeExtensionMap(Map<int, dynamic> extensions) {
    final buffer = BytesBuilder();
    extensions.forEach((type, ext) {
      buffer.addByte(type >> 8);
      buffer.addByte(type & 0xFF);

      buffer.addByte(ext.data.length >> 8);
      buffer.addByte(ext.data.length & 0xFF);

      buffer.add(ext.data);
    });
    return buffer.toBytes();
  }

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
}

// Uint8List encodeExtensionMap(Map<ExtensionType, Extension> extensions) {
//   // var encoded = <int>[];
//   BytesBuilder bb = BytesBuilder();
//   // Implement the encoding logic for extensions
//   return Uint8List.fromList(extensions);
// }

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

(Map<ExtensionType, dynamic>?, int, Exception?) decodeExtensionMap(
    Uint8List buf, int offset, int arrayLen) {
  // Implement decoding logic for extensions
  Map<ExtensionType, dynamic> result = {};
  var length =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
  offset += 2;
  var offsetBackup = offset;
  while (offset < offsetBackup + length) {
    var extensionType = ExtensionType(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;
    var extensionLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    var extension;
    //print("Extension runtime type: $extensionType");
    switch (extensionType.value) {
      case 23:
        //case ExtensionType.useExtendedMasterSecret:
        extension = ExtUseExtendedMasterSecret();
      case 14: //case ExtensionType.useSRTP:
        extension = ExtUseSRTP(protectionProfiles: [], mki: Uint8List(0));
      case 11: //case ExtensionType.supportedPointFormats:
        extension = ExtSupportedPointFormats(pointFormats: []);
      case 10: //case ExtensionType.supportedEllipticCurves:
        extension = ExtSupportedEllipticCurves(curves: []);
      default:
        extension =
            ExtUnknown(type: extensionType, dataLength: extensionLength);
    }
    if (extension != null) {
      var err = extension.decode(extensionLength, buf, offset, arrayLen);

      if (err != null) {
        return (null, offset, err);
      }
      result[extensionType] = extension;
    }
    offset += extensionLength;
  }
  return (result, offset, null);
}
