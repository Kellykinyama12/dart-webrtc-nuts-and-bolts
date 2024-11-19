import 'dart:typed_data';

enum ContentType {
  ChangeCipherSpec(20),
  Alert(21),
  Handshake(22),
  ApplicationData(23),
  unknown(255);

  const ContentType(this.value);

  final int value;

  factory ContentType.fromInt(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class DtlsVersion {
  final int major;
  final int minor;

  DtlsVersion(this.major, this.minor);

  int toUint16() {
    return (major << 8) | minor;
  }

  factory DtlsVersion.fromUint16(int value) {
    return DtlsVersion((value >> 8) & 0xFF, value & 0xFF);
  }

  @override
  String toString() {
    // TODO: implement toString
    return "{DtlsVersion: {magor: $major, minor: $minor}}";
  }
}

const int SequenceNumberSize = 6; // Define the size of the sequence number

class RecordHeader {
  ContentType contentType;
  DtlsVersion version;
  int epoch;
  Uint8List sequenceNumber;
  int length;

  Uint8List? raw;

  RecordHeader(
      {required this.contentType,
      required this.version,
      required this.epoch,
      required this.sequenceNumber,
      required this.length,
      this.raw});

  Uint8List encode() {
    final result = Uint8List(7 + SequenceNumberSize);
    result[0] = contentType.value;
    final byteData = ByteData.sublistView(result);
    byteData.setUint16(1, version.toUint16(), Endian.big);
    byteData.setUint16(3, epoch, Endian.big);
    result.setRange(5, 5 + SequenceNumberSize, sequenceNumber);
    byteData.setUint16(5 + SequenceNumberSize, length, Endian.big);
    return result;
  }

  @override
  String toString() {
    // TODO: implement toString
    return ("""{ContentType: ${contentType},
  Version: [${version.major},${version.minor}],
Epoch: ${epoch},
  SequenceNumber: ${sequenceNumber}
  Length: ${length}}""");
  }

  // Add methods for encoding/decoding if needed
}

(RecordHeader, int, Exception?) decodeRecordHeader(
  Uint8List buf,
  int offset,
  int arrayLen,
) {
  int offsetBackup = offset;
  ContentType contentType = ContentType.fromInt(buf[offset]);
  offset++;

  int versionValue =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
  DtlsVersion version = DtlsVersion.fromUint16(versionValue);
  offset += 2;

  int epoch =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
  offset += 2;

  Uint8List sequenceNumber = buf.sublist(offset, offset + SequenceNumberSize);
  offset += SequenceNumberSize;

  int length =
      ByteData.sublistView(buf, offset, offset + 2).getUint16(0, Endian.big);
  offset += 2;

  // print('ContentType: ${contentType}');
  // print('Version: ${version.major}.${version.minor}');
  // print('Epoch: ${epoch}');
  // print('SequenceNumber: ${sequenceNumber}');
  // print('Length: ${length}');

  return (
    RecordHeader(
        contentType: contentType,
        version: version,
        epoch: epoch,
        sequenceNumber: sequenceNumber,
        length: length,
        raw: buf.sublist(offsetBackup, offset)),
    offset,
    null
  );
}
