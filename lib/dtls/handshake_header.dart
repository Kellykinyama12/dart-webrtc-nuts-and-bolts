import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_message.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/certificate.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/certificate_request.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/certificate_verify.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/client_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/client_key_exchange.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/finished.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_hello_done.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_key_exchange.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

enum HandshakeType {
  // https://github.com/eclipse/tinydtls/blob/706888256c3e03d9fcf1ec37bb1dd6499213be3c/dtls.h#L344
  HelloRequest(0),
  ClientHello(1),
  ServerHello(2),
  HelloVerifyRequest(3),
  Certificate(11),
  ServerKeyExchange(12),
  CertificateRequest(13),
  ServerHelloDone(14),
  CertificateVerify(15),
  ClientKeyExchange(16),
  Finished(20);

  const HandshakeType(this.value);

  final int value;

  factory HandshakeType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class IncompleteDtlsMessageException implements Exception {
  final String message;
  IncompleteDtlsMessageException(
      [this.message = 'Data contains incomplete DTLS message']);

  @override
  String toString() => 'IncompleteDtlsMessageException: $message';
}

class UnknownDtlsContentTypeException implements Exception {
  final String message;
  UnknownDtlsContentTypeException(
      [this.message = 'Data contains unknown DTLS content type']);

  @override
  String toString() => 'UnknownDtlsContentTypeException: $message';
}

class UnknownDtlsHandshakeTypeException implements Exception {
  final String message;
  UnknownDtlsHandshakeTypeException(
      [this.message = 'Data contains unknown DTLS handshake type']);

  @override
  String toString() => 'UnknownDtlsHandshakeTypeException: $message';
}

// void main() {
//   try {
//     throw IncompleteDtlsMessageException();
//   } catch (e) {
//     print(e);
//   }

//   try {
//     throw UnknownDtlsContentTypeException();
//   } catch (e) {
//     print(e);
//   }

//   try {
//     throw UnknownDtlsHandshakeTypeException();
//   } catch (e) {
//     print(e);
//   }
// }

class HandshakeHeader extends BaseDtlsHandshakeMessage {
  HandshakeType handshakeType;
  Uint24 length;
  int messageSequence;
  Uint24 fragmentOffset;
  Uint24 fragmentLength;

  HandshakeHeader({
    required this.handshakeType,
    required this.length,
    required this.messageSequence,
    required this.fragmentOffset,
    required this.fragmentLength,
  });

  @override
  ContentType getContentType() {
    // Implement this method based on your specific requirements
    return ContentType.Handshake; // Example return value
  }

  @override
  HandshakeType getHandshakeType() {
    return handshakeType;
  }

  @override
  List<int> encode() {
    // Implement encoding logic here
    return [];
  }

  @override
  int decode(List<int> buf, int offset, int arrayLen) {
    // Implement decoding logic here
    return 0;
  }

  @override
  String toString() {
    return 'HandshakeHeader(handshakeType: $handshakeType, length: ${length.toUint32()}, messageSequence: $messageSequence, fragmentOffset: ${fragmentOffset.toUint32()}, fragmentLength: ${fragmentLength.toUint32()})';
  }
}

(HandshakeHeader, int, Exception?) DecodeHandshakeHeader(
    Uint8List buf, int offset, int arrayLen,
    {Uint8List? data}) {
  //result := new(HandshakeHeader)

  HandshakeType handshakeType = HandshakeType.fromInt(buf[offset]);
  offset++;
  Uint24 length = Uint24.fromBytes(buf.sublist(offset, offset + 3));
  offset += 3;

  int messageSequence =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);

  offset += 2;

  Uint24 fragmentOffset = Uint24.fromBytes(buf.sublist(offset, offset + 3));
  offset += 3;

  Uint24 fragmentLength = Uint24.fromBytes(buf.sublist(offset, offset + 3));
  offset += 3;

  print('handshakeType: ${handshakeType}');
  print('Length: ${length}');
  print('messageSequence: $messageSequence');
  print('fragmentOffset: $fragmentOffset');
  print('fragmentLength: $fragmentLength');

  return (
    HandshakeHeader(
      handshakeType: handshakeType,
      length: length,
      messageSequence: messageSequence,
      fragmentOffset: fragmentOffset,
      fragmentLength: fragmentLength,
    ),
    offset,
    null
  );

  // return result, offset, nil
}

(dynamic, int, Exception?) decodeHandshake(RecordHeader header,
    HandshakeHeader handshakeHeader, Uint8List buf, int offset, int arrayLen) {
  var result;
  switch (handshakeHeader.handshakeType) {
    case HandshakeType.ClientHello:
      result = ClientHello.decode(buf, offset, arrayLen);
    case HandshakeType.ServerHello:
      result = ServerHello.decode(buf, offset, arrayLen);
    case HandshakeType.Certificate:
      result = Certificate.decode(buf, offset, arrayLen);
    case HandshakeType.ServerKeyExchange:
      result = ServerKeyExchange.decode(buf, offset, arrayLen);
    case HandshakeType.CertificateRequest:
      result = CertificateRequest.decode(buf, offset, arrayLen);
    case HandshakeType.ServerHelloDone:
      result = ServerHelloDone.decode(buf, offset, arrayLen);
    case HandshakeType.ClientKeyExchange:
      result = ClientKeyExchange.decode(buf, offset, arrayLen);
    case HandshakeType.CertificateVerify:
      result = CertificateVerify.decode(buf, offset, arrayLen);
    case HandshakeType.Finished:
      result = Finished.decode(buf, offset, arrayLen);
    default:
      return (null, offset, UnknownDtlsContentTypeException());
  }
  var err;
  //(offset, err) = result.Decode(buf, offset, arrayLen);
  return (result, offset, err);
}
