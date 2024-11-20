import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/algo_pair.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class ServerKeyExchange {
  CurveType ellipticCurveType;
  Curve namedCurve;
  Uint8List publicKey;
  AlgoPair algoPair;
  Uint8List signature;

  ServerKeyExchange({
    required this.ellipticCurveType,
    required this.namedCurve,
    required this.publicKey,
    required this.algoPair,
    required this.signature,
  });

  // @override
  // String toString() {
  //   return '[ServerKeyExchange] EllipticCurveType: $ellipticCurveType, NamedCurve: $namedCurve, AlgoPair: $algoPair, PublicKey: 0x${publicKey.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}';
  // }
  @override
  String toString() {
    return '[ServerKeyExchange] EllipticCurveType: $ellipticCurveType, NamedCurve: $namedCurve, AlgoPair: $algoPair, PublicKey: $publicKey';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerKeyExchange;
  }

  // static (ServerKeyExchange, int, Exception?) decode(
  //     Uint8List buf, int offset, int arrayLen) {
  //   CurveType ellipticCurveType = CurveType(buf[offset]);
  //   offset++;
  //   Curve namedCurve = Curve((buf[offset] << 8) | buf[offset + 1]);
  //   offset += 2;

  //   var publicKeyLength = buf[offset];
  //   offset++;
  //   Uint8List publicKey =
  //       Uint8List.fromList(buf.sublist(offset, offset + publicKeyLength));
  //   offset += publicKeyLength;

  //   var algoPair;
  //   (algoPair, offset) = AlgoPair.decode(buf, offset, buf.length);

  //   var signatureLength = (buf[offset] << 8) | buf[offset + 1];
  //   offset += 2;
  //   Uint8List signature =
  //       Uint8List.fromList(buf.sublist(offset, offset + signatureLength));
  //   offset += signatureLength;

  //   return (
  //     ServerKeyExchange(
  //         ellipticCurveType: ellipticCurveType,
  //         namedCurve: namedCurve,
  //         publicKey: publicKey,
  //         algoPair: algoPair,
  //         signature: signature),
  //     offset,
  //     null
  //   );
  // }

  // Method to decode the buffer
  static (ServerKeyExchange, int, Exception?) decode(
      Uint8List buf, int offset, int arrayLen) {
    CurveType ellipticCurveType = CurveType(buf[offset]);
    offset++;

    Curve namedCurve = Curve(
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big));
    offset += 2;

    int publicKeyLength = buf[offset];
    offset++;

    Uint8List publicKey = buf.sublist(offset, offset + publicKeyLength);
    offset += publicKeyLength;

    var (algoPair, decodedOffset) = AlgoPair.decode(buf, offset, arrayLen);
    offset = decodedOffset;

    int signatureLength =
        ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
    offset += 2;

    Uint8List signature = buf.sublist(offset, offset + signatureLength);
    offset += signatureLength;

    return (
      ServerKeyExchange(
          ellipticCurveType: ellipticCurveType,
          namedCurve: namedCurve,
          publicKey: publicKey,
          algoPair: algoPair,
          signature: signature),
      offset,
      null
    );
  }

  // Uint8List encode() {
  //   var result = Uint8List(4 + publicKey.length + 2 + signature.length);
  //   result[0] = ellipticCurveType.value;
  //   result[1] = (namedCurve.value >> 8) & 0xff;
  //   result[2] = namedCurve.value & 0xff;
  //   result[3] = publicKey.length;
  //   result.setRange(4, 4 + publicKey.length, publicKey);

  //   var algoPairEncoded = algoPair.encode();
  //   result.setRange(4 + publicKey.length,
  //       4 + publicKey.length + algoPairEncoded.length, algoPairEncoded);

  //   var signatureOffset = 4 + publicKey.length + algoPairEncoded.length;
  //   result[signatureOffset] = (signature.length >> 8) & 0xff;
  //   result[signatureOffset + 1] = signature.length & 0xff;
  //   result.setRange(
  //       signatureOffset + 2, signatureOffset + 2 + signature.length, signature);

  //   return result;
  // }

  // Method to encode the ServerKeyExchange object to bytes
  Uint8List encode() {
    BytesBuilder result = BytesBuilder();

    result.addByte(ellipticCurveType.value); // Add the elliptic curve type
    result.add(Uint8List(2)
      ..buffer
          .asByteData()
          .setUint16(0, namedCurve.value, Endian.big)); // Add the named curve
    result.addByte(publicKey.length); // Add the public key length
    result.add(publicKey); // Add the public key
    result.add(algoPair.encode()); // Add the encoded algoPair

    List<int> signatureLengthBytes = Uint8List(2)
      ..buffer.asByteData().setUint16(0, signature.length, Endian.big);
    result.add(signatureLengthBytes); // Add signature length
    result.add(signature); // Add signature

    return result.toBytes();
  }
}
