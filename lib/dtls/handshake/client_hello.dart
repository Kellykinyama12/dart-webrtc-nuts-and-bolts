import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_random.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/simple_extensions.dart';

import 'package:convert/convert.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/utils.dart';

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

  Uint8List encode(ClientHello clientHello) {
    final buffer = BytesBuilder();

    // Encode the version (2 bytes)
    buffer.addByte(clientHello.version.major);
    buffer.addByte(clientHello.version.minor);

    // Encode the random (32 bytes)
    buffer.add(
        convertTo4Bytes(clientHello.random.gmtUnixTime.millisecondsSinceEpoch));
    buffer.add(clientHello.random.randomBytes);

    // Encode the session ID (1 byte for length, then the session ID)
    final sessionIDLength = clientHello.sessionID.length;
    buffer.addByte(sessionIDLength);
    buffer.add(clientHello.sessionID);

    // Encode the cookie (1 byte for length, then the cookie)
    final cookieLength = clientHello.cookie.length;
    buffer.addByte(cookieLength);
    buffer.add(clientHello.cookie);

    // Encode the cipher suites (2 bytes for the length, then the cipher suites)
    final cipherSuiteIDs = encodeCipherSuiteIDs(clientHello.cipherSuiteIDs);
    buffer.add(Uint8List.fromList(
        [cipherSuiteIDs.length ~/ 2])); // Length of cipher suites list
    buffer.add(cipherSuiteIDs);

    // Encode the compression methods (1 byte for the length, then the methods)
    final compressionMethodIDs =
        encodeCompressionMethodIDs(clientHello.compressionMethodIDs);
    buffer.addByte(compressionMethodIDs.length);
    buffer.add(compressionMethodIDs);

    // Encode the extensions (length of extensions and the extensions themselves)
    final extensionsEncoded = encodeExtensionMap(clientHello.extensions);
    buffer.add(Uint8List.fromList(
        [extensionsEncoded.length ~/ 2])); // Length of extensions
    buffer.add(extensionsEncoded);

    // Return the final encoded ClientHello message
    return buffer.toBytes();
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

Uint8List encodeCipherSuiteIDs(List<CipherSuiteID> cipherSuites) {
  final buffer = BytesBuilder();

  // First, encode the length of the cipher suites (2 bytes)
  final length = cipherSuites.length * 2; // Each CipherSuiteID is 2 bytes
  final lengthBytes = ByteData(2)..setUint16(0, length, Endian.big);
  buffer.add(lengthBytes.buffer.asUint8List());

  // Then, encode each CipherSuiteID (2 bytes each)
  for (var cipherSuite in cipherSuites) {
    final idBytes = ByteData(2)..setUint16(0, cipherSuite.value, Endian.big);
    buffer.add(idBytes.buffer.asUint8List());
  }

  return buffer.toBytes();
}

Uint8List decodeCompressionMethodIDs(Uint8List buf, int offset, int arrayLen) {
  var count = buf[offset];
  offset++;
  return buf.sublist(offset, offset + count);
}

Uint8List encodeCompressionMethodIDs(Uint8List compressionMethods) {
  final buffer = BytesBuilder();

  // First, encode the count of compression methods (1 byte)
  final count = compressionMethods.length;
  buffer.addByte(count);

  // Then, add the compression method IDs (each 1 byte)
  buffer.add(compressionMethods);

  return buffer.toBytes();
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

Uint8List encodeExtensionMap(Map<ExtensionType, dynamic> extensions) {
  final buffer = BytesBuilder();

  // Calculate the total length of all extensions to be encoded
  int totalLength = 0;
  List<List<int>> encodedExtensions = [];

  // Iterate over each extension
  extensions.forEach((extensionType, extension) {
    // Encode the extension type (2 bytes)
    final extensionTypeBytes = ByteData(2)
      ..setUint16(0, extensionType.value, Endian.big);

    // Encode the extension data
    Uint8List extensionData;
    if (extension is ExtUseExtendedMasterSecret) {
      extensionData = extension.encode();
    } else if (extension is ExtUseSRTP) {
      extensionData = extension.encode();
    } else if (extension is ExtSupportedPointFormats) {
      extensionData = extension.encode();
    } else if (extension is ExtSupportedEllipticCurves) {
      extensionData = extension.encode();
    } else if (extension is ExtUnknown) {
      extensionData = extension.encode();
    } else {
      throw Exception("Unknown extension type.");
    }

    // Extension length (2 bytes)
    final extensionLengthBytes = ByteData(2)
      ..setUint16(0, extensionData.length, Endian.big);

    // Add the encoded data for this extension to the list
    encodedExtensions.add(extensionTypeBytes.buffer.asUint8List());
    encodedExtensions.add(extensionLengthBytes.buffer.asUint8List());
    encodedExtensions.add(extensionData);

    // Accumulate total length
    totalLength += 2 +
        2 +
        extensionData.length; // 2 for type, 2 for length, and the data length
  });

  // First, encode the total length of the extensions (2 bytes)
  final lengthBytes = ByteData(2)..setUint16(0, totalLength, Endian.big);
  buffer.add(lengthBytes.buffer.asUint8List());

  // Then, encode each extension (type + length + data)
  for (var extension in encodedExtensions) {
    buffer.add(extension);
  }

  return buffer.toBytes();
}
