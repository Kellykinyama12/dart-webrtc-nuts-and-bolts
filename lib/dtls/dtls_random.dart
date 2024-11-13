import 'dart:typed_data';

const int randomBytesLength = 28;

class Random {
  DateTime gmtUnixTime;
  Uint8List randomBytes;

  Random({
    required this.gmtUnixTime,
    required this.randomBytes,
  }) {
    if (randomBytes.length != randomBytesLength) {
      throw ArgumentError(
          'randomBytes must be exactly $randomBytesLength bytes long');
    }
  }
}

Random decodeRandom(Uint8List buf, int offset, int arrayLen) {
  if (arrayLen < offset + 4 + randomBytesLength) {
    throw ArgumentError('Buffer too small to contain a valid Random structure');
  }

  int gmtUnixTimeValue = ByteData.sublistView(buf, offset, offset + 4).getUint32(0, Endian.big);
  DateTime gmtUnixTime = DateTime.fromMillisecondsSinceEpoch(gmtUnixTimeValue * 1000, isUtc: true);
  offset += 4;

  Uint8List randomBytes = buf.sublist(offset, offset + randomBytesLength);
  offset += randomBytesLength;

  return Random(
    gmtUnixTime: gmtUnixTime,
    randomBytes: randomBytes,
  );
}