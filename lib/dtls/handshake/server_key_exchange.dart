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

  @override
  String toString() {
    return '[ServerKeyExchange] EllipticCurveType: $ellipticCurveType, NamedCurve: $namedCurve, AlgoPair: $algoPair, PublicKey: 0x${publicKey.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join()}';
  }

  ContentType getContentType() {
    return ContentType.Handshake;
  }

  HandshakeType getHandshakeType() {
    return HandshakeType.ServerKeyExchange;
  }

  int decode(Uint8List buf, int offset) {
    ellipticCurveType = CurveType(buf[offset]);
    offset++;
    namedCurve = Curve((buf[offset] << 8) | buf[offset + 1]);
    offset += 2;

    var publicKeyLength = buf[offset];
    offset++;
    publicKey =
        Uint8List.fromList(buf.sublist(offset, offset + publicKeyLength));
    offset += publicKeyLength;

    var algoPair;
    (algoPair, offset) = AlgoPair.decode(buf, offset, buf.length);

    var signatureLength = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    signature =
        Uint8List.fromList(buf.sublist(offset, offset + signatureLength));
    offset += signatureLength;

    return offset;
  }

  Uint8List encode() {
    var result = Uint8List(4 + publicKey.length + 2 + signature.length);
    result[0] = ellipticCurveType.value;
    result[1] = (namedCurve.value >> 8) & 0xff;
    result[2] = namedCurve.value & 0xff;
    result[3] = publicKey.length;
    result.setRange(4, 4 + publicKey.length, publicKey);

    var algoPairEncoded = algoPair.encode();
    result.setRange(4 + publicKey.length,
        4 + publicKey.length + algoPairEncoded.length, algoPairEncoded);

    var signatureOffset = 4 + publicKey.length + algoPairEncoded.length;
    result[signatureOffset] = (signature.length >> 8) & 0xff;
    result[signatureOffset + 1] = signature.length & 0xff;
    result.setRange(
        signatureOffset + 2, signatureOffset + 2 + signature.length, signature);

    return result;
  }
}
