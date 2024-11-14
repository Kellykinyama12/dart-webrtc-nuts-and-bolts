import 'package:dart_webrtc_nuts_and_bolts/dart_webrtc_nuts_and_bolts.dart'
    as dart_webrtc_nuts_and_bolts;

import 'dart:io';

import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_message.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/handshake_context.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_manager.dart';

void main() async {
  // Bind the UDP server to an address and port
  var server = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 4444);
  print('UDP server listening on port 4444');
  //HandshakeContext handshakeContext = HandshakeContext();

  HandshakeManager handshakeManager = HandshakeManager();
  HandshakeContext? context;

  // Listen for incoming datagrams
  server.listen((RawSocketEvent event) {
    if (event == RawSocketEvent.read) {
      Datagram? datagram = server.receive();
      if (datagram != null) {
        //String message = String.fromCharCodes(datagram.data);
        print('Received from ${datagram.address.address}:${datagram.port}');

        // Optionally, send a response back to the client
        // server.send(
        //     'Message received'.codeUnits, datagram.address, datagram.port);

        if (context == null) {
          context = HandshakeContext(
              conn: server, addr: datagram.address, port: datagram.port);

          handshakeManager.processIncomingMessage(context!, datagram.data);
        } else {
          handshakeManager.processIncomingMessage(context!, datagram.data);
        }
      }
    }
  });
}
