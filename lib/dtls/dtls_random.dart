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

  Uint8List encode() {
    // Convert the DateTime (gmtUnixTime) to the number of seconds since epoch
    int gmtUnixTimeValue = gmtUnixTime.millisecondsSinceEpoch ~/
        1000; // Convert milliseconds to seconds

    // Create a ByteData buffer to store the encoded values
    final byteData = ByteData(4 + randomBytesLength);

    // Write the gmtUnixTime in big-endian byte order
    byteData.setUint32(0, gmtUnixTimeValue, Endian.big);

    // Add the randomBytes after the gmtUnixTime part
    byteData.buffer
        .asUint8List()
        .setRange(4, 4 + randomBytesLength, randomBytes);

    return byteData.buffer.asUint8List();
  }
}

Random decodeRandom(Uint8List buf, int offset, int arrayLen) {
  if (arrayLen < offset + 4 + randomBytesLength) {
    throw ArgumentError('Buffer too small to contain a valid Random structure');
  }

  int gmtUnixTimeValue =
      ByteData.sublistView(buf, offset, offset + 4).getUint32(0, Endian.big);
  DateTime gmtUnixTime =
      DateTime.fromMillisecondsSinceEpoch(gmtUnixTimeValue * 1000, isUtc: true);
  offset += 4;

  Uint8List randomBytes = buf.sublist(offset, offset + randomBytesLength);
  offset += randomBytesLength;

  return Random(
    gmtUnixTime: gmtUnixTime,
    randomBytes: randomBytes,
  );
}
