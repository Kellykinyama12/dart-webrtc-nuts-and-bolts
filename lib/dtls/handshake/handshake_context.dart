import 'dart:io';
import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto_gcm.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/dtls_state.dart';
//import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/handshake_context.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/simple_extensions.dart';

enum Flight {
  Flight0,
  Flight2,
  Flight4,
  Flight6,
}

class HandshakeContext {
  //int clientEpoch = 0;
  InternetAddress addr;
  int port;

  //int serverSequenceNumber = 0;
  // Server UDP listener connection
  RawDatagramSocket conn;
  Flight flight = Flight.Flight0;

  late String ClientUfrag; //             string
  late String ExpectedFingerprintHash; // string

  late DTLSState dtlsState;
  //OnDTLSStateChangeHandler func(DTLSState)
  late Uint8List sessionId;
  late int cipherSuiteId;
  late int compressionMethodId;
  late Map<ExtensionType, Extension> extensions;
  late List<PointFormat> pointFormats;

  late DtlsVersion protocolVersion;
  late CipherSuite cipherSuite;
  late CurveType curveType;
  late Curve curve;
  late SRTPProtectionProfile srtpProtectionProfile;
  late Random clientRandom;
  late Uint8List ClientKeyExchangePublic; // []byte

  late Random serverRandom;
  late Uint8List serverMasterSecret; // []byte
  late Uint8List serverPublicKey; //    []byte
  late Uint8List serverPrivateKey; //   []byte
  late Uint8List serverKeySignature; // []byte
  List<Uint8List> slientCertificates = []; // [][]byte

  late bool IsCipherSuiteInitialized; // bool
  //GCM                      *GCM

  late bool UseExtendedMasterSecret; // bool

  Map<HandshakeType, Uint8List> HandshakeMessagesReceived =
      {}; // map[HandshakeType][]byte
  Map<HandshakeType, Uint8List> HandshakeMessagesSent =
      {}; //     map[HandshakeType][]byte

  int clientEpoch = 0; //                   uint16
  late int clientSequenceNumber; //          uint16
  int ServerEpoch = 0; //                   uint16
  int serverSequenceNumber = 0; //          uint16
  int serverHandshakeSequenceNumber = 0; // uint16

  late Uint8List Cookie; // []byte
//	Flight Flight

  late Uint8List KeyingMaterialCache; // []byte

  late GCM gcm;

  HandshakeContext(
      {required this.conn, required this.addr, required this.port});

  void increaseServerSequenceNumber() {
    serverSequenceNumber++;
  }

  void increaseServerHandshakeSequence() {
    serverHandshakeSequenceNumber++;
  }
}
