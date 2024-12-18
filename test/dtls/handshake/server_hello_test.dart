import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_hello.dart';

//dart test\dtls\handshake\server_hello_test.dart

void test_handshake_message_server_hello() {
  var (serverHello, _, _) =
      ServerHello.decode(raw_server_hello, 0, raw_server_hello.length);
  print("decoded server hello: $serverHello");

  print("raw server hello    : $raw_server_hello");
  print("encoded server hello: ${serverHello.encode()}");
}

void main() {
  test_handshake_message_server_hello();
}

Uint8List raw_server_hello = Uint8List.fromList([
  0xfe,
  0xfd,
  0x21,
  0x63,
  0x32,
  0x21,
  0x81,
  0x0e,
  0x98,
  0x6c,
  0x85,
  0x3d,
  0xa4,
  0x39,
  0xaf,
  0x5f,
  0xd6,
  0x5c,
  0xcc,
  0x20,
  0x7f,
  0x7c,
  0x78,
  0xf1,
  0x5f,
  0x7e,
  0x1c,
  0xb7,
  0xa1,
  0x1e,
  0xcf,
  0x63,
  0x84,
  0x28,
  0x00,
  0xc0,
  0x2b,
  0x00,
  0x00,
  0x00,
]);
