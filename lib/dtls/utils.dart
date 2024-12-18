import 'dart:typed_data';

int uint48ListToUint(Uint8List bytes) {
  if (bytes.length != 6) {
    throw ArgumentError('Uint8List must be of length 6');
  }

  int result = 0;
  for (int i = 0; i < bytes.length; i++) {
    result |= bytes[i] << (8 * (5 - i));
  }

  return result;
}

Uint8List uint48ToUint8List(int value) {
  final buffer = ByteData(6);
  buffer.setUint32(2, value, Endian.big); // Start at byte 2 to fit 6 bytes
  return buffer.buffer.asUint8List();
}

Uint8List convertTo4Bytes(int millisecondsSinceEpoch) {
  final byteData = ByteData(4);
  
  // Ensure that the milliseconds fit within the 4-byte range (0 to 4GB)
  byteData.setUint32(0, millisecondsSinceEpoch & 0xFFFFFFFF, Endian.big);
  
  return byteData.buffer.asUint8List();
}

// void main() {
//   Uint8List bytes = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
//   int value = uint8ListToUint(bytes);
//   print('Converted value: $value'); // Output: 1108152157446
// }

// Uint8List uintToUint8List(int value) {
//   if (value < 0 || value > 0xFFFFFFFFFFFF) {
//     throw ArgumentError('Value must be a 48-bit unsigned integer');
//   }

//   Uint8List bytes = Uint8List(6);
//   for (int i = 0; i < 6; i++) {
//     bytes[5 - i] = (value >> (8 * i)) & 0xFF;
//   }

//   return bytes;
// }

Uint8List int16ToUint8List(int value) {
  final byteData = ByteData(2); // int16 is 2 bytes
  byteData.setInt16(
      0, value, Endian.big); // You can use Endian.little if needed
  return byteData.buffer.asUint8List();
}

// void main() {
//   int value = 1108152157446;
//   Uint8List bytes = uintToUint8List(value);
//   print('Converted bytes: $bytes'); // Output: [1, 2, 3, 4, 5, 6]
// }
