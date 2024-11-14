import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/utils.dart';

//dart test\dtls\handshake\record_header_test.dart

recordHeaderTest() {
  "Change Cipher Spec, single packet";
  var (recordHeader, offset, err) =
      decodeRecordHeader(recordHeaderBytes, 0, recordHeaderBytes.length);
  //print("Record header: $recordHeader");

  // RecordLayer {
  //           record_layer_header: RecordLayerHeader {
  //               content_type: ContentType::ChangeCipherSpec,
  //               protocol_version: ProtocolVersion {
  //                   major: 0xfe,
  //                   minor: 0xff,
  //               },
  //               epoch: 0,
  //               sequence_number: 18,
  //               content_len: 1,
  //           },
  //           content: Content::ChangeCipherSpec(ChangeCipherSpec {}),
  //       },
  print(
      "Content type decoded: ${recordHeader.contentType}, wanted: ${ContentType.ChangeCipherSpec}");

  print(
      "version decoded:{major: ${recordHeader.version.major}, minor:${recordHeader.version.minor}}, wanted: {major: 254, minor:255}");
  print("epoch: ${recordHeader.epoch}, wanted: 0");
  print(
      "Sequence number: ${uint8ListToUint(recordHeader.sequenceNumber)}, wanted: 18");
  print("content length: ${recordHeader.length}, wanted: 1");

  print("Data:    $recordHeaderBytes");
  print("Encoded: ${recordHeader.encode()}");
}

void main() {
  recordHeaderTest();
}

Uint8List recordHeaderBytes = Uint8List.fromList([
  0x14,
  0xfe,
  0xff,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x12,
  0x00,
  0x01,
  0x01,
]);
