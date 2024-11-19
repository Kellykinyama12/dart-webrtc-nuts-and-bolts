import 'dart:collection';
import 'dart:typed_data';
import 'dart:convert';

import 'package:dart_webrtc_nuts_and_bolts/dtls2/protocol_version.dart';

class ClientHello {
  final ProtocolVersion version;
  final Uint8List random;
  final Uint8List? sessionID;
  final Uint8List? cookie;
  final List<int> cipherSuites;
  final Map<int, dynamic>? extensions;

  ClientHello({
    required this.version,
    required this.random,
    this.sessionID,
    this.cookie,
    required this.cipherSuites,
    this.extensions,
  });

  /// Encode this [ClientHello] to a [ByteData] or similar output format.
  void encode(dynamic output) {
    // Replace `dynamic` with the actual type used for your output stream
    // e.g., `ByteSink`, `Sink<Uint8List>`, etc.

    _writeVersion(output, version);

    output.add(random);

    _writeOpaque8(output, sessionID);

    if (cookie != null) {
      _writeOpaque8(output, cookie!);
    }

    _writeUint16ArrayWithUint16Length(output, cipherSuites);

    // Compression method is hardcoded to "null" (0x00).
    output.add(Uint8List.fromList([1, 0]));

    if (extensions != null) {
      _writeExtensions(output, extensions!);
    }
  }

  /// Parse a [ClientHello] from the provided input data.
  static ClientHello parse(ByteBuffer input) {
    // Add parsing logic, similar to the `implParse` in Java
    throw UnimplementedError("parse not implemented yet");
  }

  static void _writeVersion(dynamic output, ProtocolVersion version) {
    // Implement the logic for writing the ProtocolVersion to output.
  }

  static void _writeOpaque8(dynamic output, Uint8List? data) {
    if (data != null) {
      output.add(Uint8List.fromList([data.length]));
      output.add(data);
    } else {
      output.add(Uint8List.fromList([0]));
    }
  }

  static void _writeUint16ArrayWithUint16Length(
      dynamic output, List<int> array) {
    final length = array.length * 2;
    output.add(Uint8List.fromList([length >> 8, length & 0xFF]));
    output.add(
        Uint8List.fromList(array.expand((e) => [e >> 8, e & 0xFF]).toList()));
  }

  static void _writeExtensions(dynamic output, Map<int, dynamic> extensions) {
    // Convert and write extensions in the appropriate format.
    // Adjust to match your extensions structure.
  }
}
