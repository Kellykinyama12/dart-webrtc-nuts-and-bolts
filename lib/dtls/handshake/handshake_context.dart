import 'dart:io';

enum Flight {
  Flight0,
  Flight2,
  Flight4,
  Flight6,
}

class HandshakeContext {
  int clientEpoch = 0;
  InternetAddress addr;
  int port;

  int serverSequenceNumber = 0;
  // Server UDP listener connection
  RawDatagramSocket conn;
  Flight flight = Flight.Flight0;

  HandshakeContext(
      {required this.conn, required this.addr, required this.port});

  void increaseSeverSequenceNumber() {
    serverSequenceNumber++;
  }
}
