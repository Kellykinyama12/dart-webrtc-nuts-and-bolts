import 'dart:io';

import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_message.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/handshake_context.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/hello_verify_request.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_manager.dart';

void main() async {
  // Bind the UDP server to an address and port
  // Bind the UDP server to an address and port
  InternetAddress clientIP = InternetAddress("127.0.0.1");
  int? clientPort;
  InternetAddress serverIP = InternetAddress("127.0.0.1");
  int serverPort = 5555;
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

        // if (context == null) {
        //   context = HandshakeContext(
        //       conn: server, addr: datagram.address, port: datagram.port);

        //   handshakeManager.processIncomingMessage(context!, datagram.data);
        // } else {
        //   handshakeManager.processIncomingMessage(context!, datagram.data);
        //}
        if (context == null) {
          context = HandshakeContext(
              conn: server, addr: datagram.address, port: datagram.port);
          decodeDtlsMessage(context!, datagram.data, 0, datagram.data.length)
              .then((decodedMessage) {
            // if (decodedMessage.message.runtimeType == HelloVerifyRequest) {
            print("Message: ${decodedMessage}");
            // }
          });
        } else {
          decodeDtlsMessage(context!, datagram.data, 0, datagram.data.length)
              .then((decodedMessage) {
            //if (decodedMessage.message.runtimeType == HelloVerifyRequest) {
            print("Message: ${decodedMessage}");
            // }
          });
        }

        if (clientPort == null) {
          clientPort = datagram.port;
        } else {
          if (datagram.port == clientPort) {
            server.send(datagram.data, serverIP, serverPort);
          } else {
            server.send(datagram.data, clientIP, clientPort!);
          }
        }
      }
    }
  });
}
