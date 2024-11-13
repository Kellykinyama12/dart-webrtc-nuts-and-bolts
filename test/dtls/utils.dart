import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_message.dart';

void main() {
  // Example usage for fromUint32
  int i = 123456; // Example uint32 value
  Uint24 uint24FromUint32 = Uint24.fromUint32(i);
  print(uint24FromUint32.bytes); // Output: [1, 226, 64]

  // Example usage for fromBytes
  Uint8List buf = Uint8List.fromList([1, 226, 64]);
  Uint24 uint24FromBytes = Uint24.fromBytes(buf);
  print(uint24FromBytes.bytes); // Output: [1, 226, 64]
}
