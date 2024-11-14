import 'dart:typed_data';

int uint8ListToUint(Uint8List bytes) {
  if (bytes.length != 6) {
    throw ArgumentError('Uint8List must be of length 6');
  }

  int result = 0;
  for (int i = 0; i < bytes.length; i++) {
    result |= bytes[i] << (8 * (5 - i));
  }

  return result;
}

// void main() {
//   Uint8List bytes = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
//   int value = uint8ListToUint(bytes);
//   print('Converted value: $value'); // Output: 1108152157446
// }

Uint8List uintToUint8List(int value) {
  if (value < 0 || value > 0xFFFFFFFFFFFF) {
    throw ArgumentError('Value must be a 48-bit unsigned integer');
  }

  Uint8List bytes = Uint8List(6);
  for (int i = 0; i < 6; i++) {
    bytes[5 - i] = (value >> (8 * i)) & 0xFF;
  }

  return bytes;
}

// void main() {
//   int value = 1108152157446;
//   Uint8List bytes = uintToUint8List(value);
//   print('Converted bytes: $bytes'); // Output: [1, 2, 3, 4, 5, 6]
// }
