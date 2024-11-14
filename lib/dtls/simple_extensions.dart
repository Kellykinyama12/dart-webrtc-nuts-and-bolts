import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';

class ExtensionType {
  final int value;
  const ExtensionType(this.value);

  static const ExtensionType serverName = ExtensionType(0);
  static const ExtensionType supportedEllipticCurves = ExtensionType(10);
  static const ExtensionType supportedPointFormats = ExtensionType(11);
  static const ExtensionType supportedSignatureAlgorithms = ExtensionType(13);
  static const ExtensionType useSRTP = ExtensionType(14);
  static const ExtensionType alpn = ExtensionType(16);
  static const ExtensionType useExtendedMasterSecret = ExtensionType(23);
  static const ExtensionType renegotiationInfo = ExtensionType(65281);
  static const ExtensionType unknown = ExtensionType(65535);

  @override
  String toString() {
    return 'ExtensionType($value)';
  }
}

abstract class Extension {
  ExtensionType get extensionType;
  Uint8List encode();
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen);
  @override
  String toString();
}

class ExtUseExtendedMasterSecret implements Extension {
  @override
  ExtensionType get extensionType => ExtensionType.useExtendedMasterSecret;

  @override
  Uint8List encode() {
    return Uint8List(0);
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {}

  @override
  String toString() {
    return '[UseExtendedMasterSecret]';
  }
}

class ExtRenegotiationInfo implements Extension {
  @override
  ExtensionType get extensionType => ExtensionType.renegotiationInfo;

  @override
  Uint8List encode() {
    return Uint8List.fromList([0]);
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {}

  @override
  String toString() {
    return '[RenegotiationInfo]';
  }
}

class ExtUseSRTP implements Extension {
  late List<SRTPProtectionProfile> protectionProfiles;
  late Uint8List mki;

  ExtUseSRTP({required this.protectionProfiles, required this.mki});
  //ExtUseSRTP();

  @override
  ExtensionType get extensionType => ExtensionType.useSRTP;

  @override
  Uint8List encode() {
    final result =
        Uint8List(2 + (protectionProfiles.length * 2) + 1 + mki.length);
    var offset = 0;
    final byteData = ByteData.sublistView(result);
    byteData.setUint16(offset, protectionProfiles.length * 2, Endian.big);
    offset += 2;
    for (var profile in protectionProfiles) {
      byteData.setUint16(offset, profile.value, Endian.big);
      offset += 2;
    }
    result[offset] = mki.length;
    offset++;
    result.setRange(offset, offset + mki.length, mki);
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    final protectionProfilesLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    final protectionProfilesCount = protectionProfilesLength ~/ 2;
    protectionProfiles = List.generate(protectionProfilesCount, (i) {
      final profile = SRTPProtectionProfile(
          ByteData.sublistView(buf, offset, offset + 2)
              .getUint16(0, Endian.big));
      offset += 2;
      return profile;
    });
    final mkiLength = buf[offset];
    offset++;
    mki = Uint8List.fromList(buf.sublist(offset, offset + mkiLength));
  }

  @override
  String toString() {
    final protectionProfilesStr =
        protectionProfiles.map((p) => p.toString()).join('\n');
    return '[UseSRTP]\nProtection Profiles:\n$protectionProfilesStr';
  }
}

class ExtSupportedPointFormats implements Extension {
  late List<PointFormat> pointFormats;

  ExtSupportedPointFormats({required this.pointFormats});
  //ExtSupportedPointFormats();

  @override
  ExtensionType get extensionType => ExtensionType.supportedPointFormats;

  @override
  Uint8List encode() {
    final result = Uint8List(1 + pointFormats.length);
    var offset = 0;
    result[offset] = pointFormats.length;
    offset++;
    for (var format in pointFormats) {
      result[offset] = format.value;
      offset++;
    }
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    final pointFormatsCount = buf[offset];
    offset++;
    pointFormats = List.generate(pointFormatsCount, (i) {
      final format = PointFormat(buf[offset]);
      offset++;
      return format;
    });
  }

  @override
  String toString() {
    return '[SupportedPointFormats] Point Formats: $pointFormats';
  }
}

class ExtSupportedEllipticCurves implements Extension {
  late List<Curve> curves;

  ExtSupportedEllipticCurves({required this.curves});
  //ExtSupportedEllipticCurves();

  @override
  ExtensionType get extensionType => ExtensionType.supportedEllipticCurves;

  @override
  Uint8List encode() {
    final result = Uint8List(2 + (curves.length * 2));
    var offset = 0;
    final byteData = ByteData.sublistView(result);
    byteData.setUint16(offset, curves.length * 2, Endian.big);
    offset += 2;
    for (var curve in curves) {
      byteData.setUint16(offset, curve.value, Endian.big);
      offset += 2;
    }
    return result;
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {
    final curvesLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;
    final curvesCount = curvesLength ~/ 2;
    curves = List.generate(curvesCount, (i) {
      final curve = Curve(ByteData.sublistView(buf, offset, offset + 2)
          .getUint16(0, Endian.big));
      offset += 2;
      return curve;
    });
  }

  @override
  String toString() {
    final curvesStr = curves.map((c) => c.toString()).join('\n');
    return '[SupportedEllipticCurves]\nCurves:\n$curvesStr';
  }
}

class ExtUnknown implements Extension {
  final ExtensionType type;
  final int dataLength;

  ExtUnknown({required this.type, required this.dataLength});

  @override
  ExtensionType get extensionType => ExtensionType.unknown;

  @override
  Uint8List encode() {
    throw UnsupportedError('ExtUnknown cannot be encoded, it\'s readonly');
  }

  @override
  void decode(int extensionLength, Uint8List buf, int offset, int arrayLen) {}

  @override
  String toString() {
    return '[Unknown Extension Type] Ext Type: $type, Data: $dataLength bytes';
  }
}

// class SRTPProtectionProfile {
//   final int value;
//   const SRTPProtectionProfile(this.value);

//   @override
//   String toString() {
//     switch (value) {
//       case 0x0007:
//         return 'SRTP_AEAD_AES_128_GCM (0x${value.toRadixString(16)})';
//       default:
//         return 'Unknown SRTP Protection Profile (0x${value.toRadixString(16)})';
//     }
//   }
// }

// class PointFormat {
//   final int value;
//   const PointFormat(this.value);

//   @override
//   String toString() {
//     switch (value) {
//       case 0:
//         return 'Uncompressed (0x${value.toRadixString(16)})';
//       default:
//         return 'Unknown Point Format (0x${value.toRadixString(16)})';
//     }
//   }
// }

// class Curve {
//   final int value;
//   const Curve(this.value);

//   @override
//   String toString() {
//     switch (value) {
//       case 0x001d:
//         return 'X25519 (0x${value.toRadixString(16)})';
//       default:
//         return 'Unknown Curve (0x${value.toRadixString(16)})';
//     }
//   }
// }

Map<ExtensionType, Extension> decodeExtensionMap(
    Uint8List buf, int offset, int arrayLen) {
  final result = <ExtensionType, Extension>{};
  final length =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
  offset += 2;
  final offsetBackup = offset;

  while (offset < offsetBackup + length) {
    final extensionType = ExtensionType(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;
    final extensionLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;

    Extension extension;
    switch (extensionType.value) {
      case 23:
        extension = ExtUseExtendedMasterSecret();
        break;
      case 14:
        extension = ExtUseSRTP(protectionProfiles: [], mki: Uint8List(0));
        break;
      //case
      case 11:
        extension = ExtSupportedPointFormats(pointFormats: []);
        break;
      case 10:
        extension = ExtSupportedEllipticCurves(curves: []);
        break;
      default:
        extension =
            ExtUnknown(type: extensionType, dataLength: extensionLength);
    }

    extension.decode(extensionLength, buf, offset, arrayLen);
    addExtension(result, extension);
    offset += extensionLength;
  }

  return result;
}

Uint8List encodeExtensionMap(Map<ExtensionType, Extension> extensionMap) {
  final result = Uint8List(2);
  var encodedBody = <int>[];

  extensionMap.forEach((type, extension) {
    final encodedExtension = extension.encode();
    final encodedExtType = ByteData(2)..setUint16(0, type.value, Endian.big);
    encodedBody.addAll(encodedExtType.buffer.asUint8List());

    final encodedExtLen = ByteData(2)
      ..setUint16(0, encodedExtension.length, Endian.big);
    encodedBody.addAll(encodedExtLen.buffer.asUint8List());
    encodedBody.addAll(encodedExtension);
  });

  ByteData.sublistView(result).setUint16(0, encodedBody.length, Endian.big);
  return Uint8List.fromList(result + encodedBody);
}

void addExtension(
    Map<ExtensionType, Extension> extensionMap, Extension extension) {
  var extType = extension.extensionType;

  if (extType == ExtensionType.unknown) {
    while (extensionMap.containsKey(extType)) {
      extType = ExtensionType(extType.value - 1);
    }
  }

  extensionMap[extType] = extension;
}

void main() {
  // Example usage
  final buf = Uint8List.fromList(List.generate(50, (index) => index));
  final extensionMap = decodeExtensionMap(buf, 0, buf.length);
  final encodedMap = encodeExtensionMap(extensionMap);

  print('Decoded Extensions: $extensionMap');
  print('Encoded Extensions: $encodedMap');
}
