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
  Map<ExtensionType, dynamic> extensions;

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
    // Calculate the length of the encoded message
    // int length = 2 +
    //     32 +
    //     1 +
    //     sessionID.length +
    //     1 +
    //     cookie.length +
    //     2 +
    //     (cipherSuiteIDs.length * 2) +
    //     1 +
    //     compressionMethodIDs.length +
    //     2;
    // extensions.forEach((key, value) {
    //   length += 4 + value.encode().length;
    // });

    // // Create a buffer to hold the encoded message
    // Uint8List result = Uint8List(length);
    // ByteData writer = ByteData.sublistView(result);

    // int offset = 0;

    // // Encode version
    // writer.setUint16(offset, version.toUint16(), Endian.big);
    // offset += 2;

    // // Encode random
    // result.setRange(offset, offset + 32, random.bytes);
    // offset += 32;

    // // Encode session ID
    // result[offset] = sessionID.length;
    // offset++;
    // result.setRange(offset, offset + sessionID.length, sessionID);
    // offset += sessionID.length;

    // // Encode cookie
    // result[offset] = cookie.length;
    // offset++;
    // result.setRange(offset, offset + cookie.length, cookie);
    // offset += cookie.length;

    // // Encode cipher suite IDs
    // writer.setUint16(offset, cipherSuiteIDs.length * 2, Endian.big);
    // offset += 2;
    // for (var id in cipherSuiteIDs) {
    //   writer.setUint16(offset, id.toUint16(), Endian.big);
    //   offset += 2;
    // }

    // // Encode compression method IDs
    // result[offset] = compressionMethodIDs.length;
    // offset++;
    // result.setRange(
    //     offset, offset + compressionMethodIDs.length, compressionMethodIDs);
    // offset += compressionMethodIDs.length;

    // // Encode extensions
    // int extensionsLength = 0;
    // extensions.forEach((key, value) {
    //   extensionsLength += 4 + value.encode().length;
    // });
    // writer.setUint16(offset, extensionsLength, Endian.big);
    // offset += 2;
    // extensions.forEach((key, value) {
    //   writer.setUint16(offset, key.toUint16(), Endian.big);
    //   offset += 2;
    //   Uint8List encodedExtension = value.encode();
    //   writer.setUint16(offset, encodedExtension.length, Endian.big);
    //   offset += 2;
    //   result.setRange(
    //       offset, offset + encodedExtension.length, encodedExtension);
    //   offset += encodedExtension.length;
    // });

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

    var (extensions, decodedOffset, err) =
        decodeExtensionMap(buf, offset, arrayLen);

    return ClientHello(
      version: version,
      random: random,
      cookie: cookie,
      sessionID: sessionID,
      cipherSuiteIDs: cipherSuiteIDs,
      compressionMethodIDs: compressionMethodIDs,
      extensions: extensions!,
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
    print("Extension runtime type: $extensionType");
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
