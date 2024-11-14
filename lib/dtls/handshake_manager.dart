import 'dart:typed_data';
import 'dart:math' as dmath;

import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_message.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/client_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/handshake_context.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/hello_verify_request.dart';

class HandshakeManager {
  // HandshakeContext newContext(InternetAddress addr, RawDatagramSocket conn,
  //     String clientUfrag, String expectedFingerprintHash) {
  //   return HandshakeContext();
  // }

  Future<void> processIncomingMessage(
      HandshakeContext context, dynamic incomingMessage) async {
    final decodedMessage = await decodeDtlsMessage(
        context, incomingMessage, 0, incomingMessage.length);
    switch (decodedMessage.message.runtimeType) {
      case ClientHello:
        {
          final message = decodedMessage.message as ClientHello;
          switch (context.flight) {
            case Flight.Flight0:
              print("Message result: ${decodedMessage.message.runtimeType}");
              HelloVerifyRequest hvr = HelloVerifyRequest(
                  version: decodedMessage.message.version,
                  cookie: generateDtlsCookie());
              print("Hello verify request: ${hvr}");

              final int contentType = 22; // Handshake
              final int version = 0xFEFF; // DTLS version
              final int epoch = 0; // Initial epoch
              final int sequenceNumber; // Initial sequence number
              final Uint8List handshakeMessage = hvr.encode();

              // DTLSRecord(this.handshakeMessage, this.sequenceNumber);

              //Uint8List toBytes() {
              final buffer = BytesBuilder();

              Uint8List serverSequenceNumber = Uint8List(6);
              serverSequenceNumber[serverSequenceNumber.length - 1] =
                  context.serverSequenceNumber;

              context.increaseSeverSequenceNumber();

              buffer.addByte(contentType);
              buffer.addByte(version >> 8);
              buffer.addByte(version & 0xFF);
              buffer.addByte(epoch >> 8);
              buffer.addByte(epoch & 0xFF);
              buffer.add(serverSequenceNumber); // 6 bytes for sequence number
              buffer.addByte(handshakeMessage.length >> 8);
              buffer.addByte(handshakeMessage.length & 0xFF);
              buffer.add(handshakeMessage);

              context.conn.send(buffer.toBytes(), context.addr, context.port);
              context.flight = Flight.Flight2;
              break;
            case Flight.Flight2:
              // TODO: Handle this case.
              if (message.cookie.isEmpty) {
                print("Receive empty cookie ${message.cookie}");
                context.flight = Flight.Flight0;
                break;
              } else {
                print("Receive cookie ${message.cookie}");
              }
            //throw UnimplementedError();
            case Flight.Flight4:
              // TODO: Handle this case.
              throw UnimplementedError();
            case Flight.Flight6:
              // TODO: Handle this case.
              throw UnimplementedError();
          }
        }
    }
  }
  // }

  Uint8List generateDtlsCookie() {
    final cookie = Uint8List(20);
    final random = dmath.Random.secure();
    for (int i = 0; i < cookie.length; i++) {
      cookie[i] = random.nextInt(256);
    }
    return cookie;
  }
}
