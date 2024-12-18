import 'dart:typed_data';

//import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
//import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_random.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/client_hello.dart';
//import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

//dart test\dtls\handshake\client_hello_test.dart
void clientHelloTest() {
  ClientHello clientHello =
      ClientHello.decode(raw_client_hello, 0, raw_client_hello.length);
  print("Client hello: $clientHello");

  // ClientHello parsed_client_hello = ClientHello(
  //     version: DtlsVersion(0xFE, 0xFD),
  //     random: Random(
  //         gmtUnixTime: DateTime.now(),
  //         randomBytes: Uint8List.fromList([
  //           0x42,
  //           0x54,
  //           0xff,
  //           0x86,
  //           0xe1,
  //           0x24,
  //           0x41,
  //           0x91,
  //           0x42,
  //           0x62,
  //           0x15,
  //           0xad,
  //           0x16,
  //           0xc9,
  //           0x15,
  //           0x8d,
  //           0x95,
  //           0x71,
  //           0x8a,
  //           0xbb,
  //           0x22,
  //           0xd7,
  //           0x47,
  //           0xec,
  //           0xd8,
  //           0x3d,
  //           0xdc,
  //           0x4b,
  //         ])),
  //     cookie: Uint8List.fromList([
  //       0xe6,
  //       0x14,
  //       0x3a,
  //       0x1b,
  //       0x04,
  //       0xea,
  //       0x9e,
  //       0x7a,
  //       0x14,
  //       0xd6,
  //       0x6c,
  //       0x57,
  //       0xd0,
  //       0x0e,
  //       0x32,
  //       0x85,
  //       0x76,
  //       0x18,
  //       0xde,
  //       0xd8,
  //     ]),
  //     sessionID: Uint8List(0),
  //     cipherSuiteIDs: [CipherSuiteID(0xc02b)],
  //     compressionMethodIDs: [],
  //     extensions: {});

  print(
      "Decoded version:{major: ${clientHello.version.major}, minor: ${clientHello.version.minor}}, Wanted: {major: ${0xFE}, minor: ${0xFD}}");
  print("Decoded random bytes: ${clientHello.random.randomBytes}");
  print("Wanted              : $randomBytes");

  print("Decoded cookie: ${clientHello.cookie}");
  print("Wanted        : $cookie");

  print("Decoded ciphersuite Ids: ${clientHello.cipherSuiteIDs}");
  print("Decoded extensions: ${clientHello.extensions}");
}

void main() {
  clientHelloTest();
}

// ignore: non_constant_identifier_names
Uint8List raw_client_hello = Uint8List.fromList([
  0xfe,
  0xfd,
  0xb6,
  0x2f,
  0xce,
  0x5c,
  0x42,
  0x54,
  0xff,
  0x86,
  0xe1,
  0x24,
  0x41,
  0x91,
  0x42,
  0x62,
  0x15,
  0xad,
  0x16,
  0xc9,
  0x15,
  0x8d,
  0x95,
  0x71,
  0x8a,
  0xbb,
  0x22,
  0xd7,
  0x47,
  0xec,
  0xd8,
  0x3d,
  0xdc,
  0x4b,
  0x00,
  0x14,
  0xe6,
  0x14,
  0x3a,
  0x1b,
  0x04,
  0xea,
  0x9e,
  0x7a,
  0x14,
  0xd6,
  0x6c,
  0x57,
  0xd0,
  0x0e,
  0x32,
  0x85,
  0x76,
  0x18,
  0xde,
  0xd8,
  0x00,
  0x04,
  0xc0,
  0x2b,
  0xc0,
  0x0a,
  0x01,
  0x00,
  0x00,
  0x08,
  0x00,
  0x0a,
  0x00,
  0x04,
  0x00,
  0x02,
  0x00,
  0x1d,
]);

Uint8List randomBytes = Uint8List.fromList([
  0x42,
  0x54,
  0xff,
  0x86,
  0xe1,
  0x24,
  0x41,
  0x91,
  0x42,
  0x62,
  0x15,
  0xad,
  0x16,
  0xc9,
  0x15,
  0x8d,
  0x95,
  0x71,
  0x8a,
  0xbb,
  0x22,
  0xd7,
  0x47,
  0xec,
  0xd8,
  0x3d,
  0xdc,
  0x4b,
]);

Uint8List cookie = Uint8List.fromList([
  0xe6,
  0x14,
  0x3a,
  0x1b,
  0x04,
  0xea,
  0x9e,
  0x7a,
  0x14,
  0xd6,
  0x6c,
  0x57,
  0xd0,
  0x0e,
  0x32,
  0x85,
  0x76,
  0x18,
  0xde,
  0xd8,
]);
