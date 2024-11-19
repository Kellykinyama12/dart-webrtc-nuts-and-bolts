import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/alert.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/handshake_context.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

class Uint24 {
  final Uint8List _bytes = Uint8List(3);

  Uint24.fromUint32(int i) {
    var buffer = ByteData(4);
    buffer.setUint32(0, i, Endian.big);
    _bytes.setAll(0, buffer.buffer.asUint8List().sublist(1, 4));
  }

  Uint24.fromBytes(Uint8List buf) {
    if (buf.length != 3) {
      throw ArgumentError('Buffer must be exactly 3 bytes long');
    }
    _bytes.setAll(0, buf);
  }

  int toUint32() {
    return (_bytes[2]) | (_bytes[1] << 8) | (_bytes[0] << 16);
  }

  Uint8List get bytes => _bytes;

  @override
  String toString() {
    // TODO: implement toString
    return "{Uint24: $_bytes}";
  }
}

abstract class BaseDtlsMessage {
  ContentType getContentType();
  List<int> encode();
  int decode(List<int> buf, int offset, int arrayLen);
  @override
  String toString();
}

abstract class BaseDtlsHandshakeMessage extends BaseDtlsMessage {
  HandshakeType getHandshakeType();
}

class DecodeDtlsMessageResult {
  final RecordHeader? recordHeader;
  final HandshakeHeader? handshakeHeader;
  final dynamic message;
  final int offset;

  DecodeDtlsMessageResult(
      this.recordHeader, this.handshakeHeader, this.message, this.offset);

  @override
  String toString() {
    // TODO: implement toString
    return "{record header: $recordHeader, handshake header: $handshakeHeader, message: $message}";
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

bool isDtlsPacket(Uint8List buf, int offset, int arrayLen) {
  return arrayLen > 0 && buf[offset] >= 20 && buf[offset] <= 63;
}

Future<DecodeDtlsMessageResult> decodeDtlsMessage(
    HandshakeContext context, Uint8List buf, int offset, int arrayLen) async {
  //print("message: $buf");

  if (arrayLen < 1) {
    return DecodeDtlsMessageResult(null, null, null, offset);
  }
  var (header, decodedOffset, err) = decodeRecordHeader(buf, offset, arrayLen);

  offset = decodedOffset;

  if (err != null) {
    return DecodeDtlsMessageResult(null, null, null, offset);
  }
  //print("Raw record header: ${header.raw}");
  //print("encoded record header: ${header.encode()}");

  if (header.epoch < context.clientEpoch) {
    // Ignore incoming message
    offset += header.length;
    return DecodeDtlsMessageResult(null, null, null, offset);
  }

  context.clientEpoch = header.epoch;

  Uint8List? decryptedBytes;
  Uint8List? encryptedBytes;
  if (header.epoch > 0) {
    // Data arrives encrypted, we should decrypt it before.
    // if context.IsCipherSuiteInitialized {
    // 	encryptedBytes = buf[offset : offset+int(header.Length)]
    // 	offset += int(header.Length)
    // 	decryptedBytes, err = context.GCM.Decrypt(header, encryptedBytes)
    // 	if err != nil {
    // 		return nil, nil, nil, offset, err
    // 	}
    // }
  }

  switch (header.contentType) {
    case ContentType.Handshake:
      if (decryptedBytes == null) {
        final offsetBackup = offset;
        var (handshakeHeader, decodedOffset, err) =
            DecodeHandshakeHeader(buf, offset, arrayLen);
        offset = decodedOffset;
        if (err != null) {
          return DecodeDtlsMessageResult(null, null, null, offset);
        }
        if (handshakeHeader.length.toUint32() !=
            handshakeHeader.fragmentLength.toUint32()) {
          // Ignore fragmented packets
          //print("Handshake header content type: ${header.contentType}");
          return DecodeDtlsMessageResult(null, null, null,
              offset + handshakeHeader.fragmentLength.toUint32());
        }
        var result;
        (result, offset, err) =
            decodeHandshake(header, handshakeHeader, buf, offset, arrayLen);
        if (err != null) {
          return DecodeDtlsMessageResult(null, null, null, offset);
        }
        //print("handshake: $result");
        // Uint8List	copyArray = make([]byte, offset-offsetBackup);
        // 	copy(copyArray, buf[offsetBackup:offset])

        // Create a new array with the specified length
        Uint8List copyArray = Uint8List(offset - offsetBackup);

        // Copy the specified range from the buffer to the new array
        copyArray.setRange(
            0, offset - offsetBackup, buf.sublist(offsetBackup, offset));
        //context.HandshakeMessagesReceived[handshakeHeader.HandshakeType] = copyArray

        return DecodeDtlsMessageResult(header, handshakeHeader, result, offset);
      } else {
        var (handshakeHeader, decryptedOffset, err) =
            DecodeHandshakeHeader(decryptedBytes, 0, decryptedBytes.length);
        offset = decryptedOffset = decryptedOffset;
        if (err != null) {
          return DecodeDtlsMessageResult(null, null, null, offset);
        }
        var result;
        (result, _, err) = decodeHandshake(
            header,
            handshakeHeader,
            decryptedBytes,
            decryptedOffset,
            decryptedBytes.length - decryptedOffset);

        Uint8List copyArray = Uint8List(decryptedBytes.length);

        // Copy the specified range from the buffer to the new array
        copyArray.setRange(
            0, decryptedBytes.length, buf.sublist(0, decryptedBytes.length));

        //context.HandshakeMessagesReceived[handshakeHeader.HandshakeType] = copyArray

        return DecodeDtlsMessageResult(header, handshakeHeader, result, offset);
      }
    case ContentType.ChangeCipherSpec:
    // changeCipherSpec := &ChangeCipherSpec{}
    // offset, err := changeCipherSpec.Decode(buf, offset, arrayLen)
    // if err != nil {
    // 	return nil, nil, nil, offset, err
    // }
    // return header, nil, changeCipherSpec, offset, nil
    case ContentType.Alert:
      Alert? alert; // = Alert();
      if (decryptedBytes == null) {
        var (alert, decodedOffset) = Alert.decode(buf, offset, arrayLen);
      } else {
        (alert, _) = Alert.decode(decryptedBytes, 0, decryptedBytes.length);
      }

      //context.serverSequenceNumber = 0;
      //context.flight = Flight.Flight0;
      return DecodeDtlsMessageResult(header, null, alert, offset);
    // return DecodeDtlsMessageResult(header, handshakeHeader, result, offset);
    // if decryptedBytes == nil {
    // 	offset, err = alert.Decode(buf, offset, arrayLen)
    // } else {
    // 	_, err = alert.Decode(decryptedBytes, 0, len(decryptedBytes))
    // }
    // if err != nil {
    // 	return nil, nil, nil, offset, err
    // }
    // return header, nil, alert, offset, nil

    default:
      print("Unhandled content type: ${header.contentType}");
      return DecodeDtlsMessageResult(null, null, null, offset);
  }
  //return (null, null, null, null, null);
}
