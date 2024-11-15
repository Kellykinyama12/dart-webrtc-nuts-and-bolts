import 'dart:typed_data';
import 'dart:math' as dmath;

import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto_gcm.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_message.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/algo_pair.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/certificate.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/certificate_request.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/change_cipher_spec.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/client_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/finished.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/handshake_context.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/hello_verify_request.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_hello_done.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/init.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/simple_extensions.dart';

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

  HelloVerifyRequest createDtlsHelloVerifyRequest(HandshakeContext context) {
    // result := HelloVerifyRequest{
    // 	// TODO: Before sending a ServerHello, we should negotiate on same protocol version which client supported and server supported protocol versions.
    // 	// But for now, we accept the version directly came from client.
    // 	Version: context.ProtocolVersion,
    // 	Cookie:  context.Cookie,
    // }
    // return result
    return HelloVerifyRequest(
        version: context.protocolVersion, cookie: context.Cookie);
  }

  ServerHello createDtlsServerHello(HandshakeContext context) {
    // if (context.useExtendedMasterSecret) {
    // 	AddExtension(result.Extensions, new(ExtUseExtendedMasterSecret))
    // }
    // AddExtension(result.Extensions, new(ExtRenegotiationInfo))

    if (context.srtpProtectionProfile != 0) {
      ExtUseSRTP useSRTP = ExtUseSRTP(
          protectionProfiles: [context.srtpProtectionProfile],
          mki: Uint8List(0));
      // useSRTP.ProtectionProfiles = []SRTPProtectionProfile{context.SRTPProtectionProfile} // SRTPProtectionProfile_AEAD_AES_128_GCM 0x0007
      // AddExtension(result.Extensions, useSRTP)
    }
    ExtSupportedPointFormats supportedPointFormats =
        ExtSupportedPointFormats(pointFormats: context.pointFormats);
    // TODO: For now, we choose one point format hardcoded. It should be choosen by a negotiation process.
    // supportedPointFormats.PointFormats = []PointFormat{PointFormatUncompressed} // 0x00
    // AddExtension(result.Extensions, supportedPointFormats)

    return ServerHello(
      version: context.protocolVersion,
      random: context.serverRandom,
      sessionId: context.sessionId,
      cipherSuiteId: context.cipherSuiteId,
      compressionMethodId: context.compressionMethodId,
      extensions: context.extensions,
    );
  }

  Certificate createDtlsCertificate() {
    // logging.Descf(logging.ProtoDTLS, "Sending Server certificate (<u>%d bytes</u>) to the client.", len(ServerCertificate.Certificate))
    // result := Certificate{
    // 	Certificates: ServerCertificate.Certificate,
    // }
    // return result
    return Certificate(certificates: [serverCertificate]);
  }

  CertificateRequest createDtlsCertificateRequest(HandshakeContext context) {
    // result := CertificateRequest{
    // 	// TODO: For now, we choose one certificate type hardcoded. It should be choosen by a negotiation process.
    // 	CertificateTypes: []CertificateType{
    // 		CertificateTypeECDSASign, //0x40
    // 	},
    // 	AlgoPairs: []AlgoPair{
    // 		{
    // 			HashAlgorithm:      context.CipherSuite.HashAlgorithm,      //HashAlgorithmSHA256 4
    // 			SignatureAlgorithm: context.CipherSuite.SignatureAlgorithm, //SignatureAlgorithmECDSA 3
    // 		},
    // 		/*{
    // 			HashAlgorithm:      2, //SHA1
    // 			SignatureAlgorithm: 1, //RSA
    // 		},*/
    // 	},
    // }

    // return result

    List<CertificateType> certificateTypes = [
      CertificateType(64)
    ]; // 		CertificateTypeECDSASign, //0x40
    HashAlgorithm hashAlgorithm = HashAlgorithm(4); //HashAlgorithmSHA256 4
    SignatureAlgorithm signatureAlgorithm =
        SignatureAlgorithm(3); //SignatureAlgorithmECDSA 3
    List<AlgoPair> algoPairs = [
      AlgoPair(
          hashAlgorithm: hashAlgorithm, signatureAlgorithm: signatureAlgorithm)
    ];
    return CertificateRequest(
        certificateTypes: certificateTypes, algoPairs: algoPairs);
  }

  ServerHelloDone createDtlsServerHelloDone() {
// 	result := ServerHelloDone{}

// 	return result
    return ServerHelloDone();
  }

  Finished createDtlsFinished(Uint8List calculatedVerifyData) {
// 	result := Finished{
// 		VerifyData: calculatedVerifyData,
// 	}

// 	return result
    return Finished(verifyData: calculatedVerifyData);
  }

  ChangeCipherSpec createDtlsChangeCipherSpec(HandshakeContext context) {
    // result := ChangeCipherSpec{}

    // return result
    return ChangeCipherSpec();
  }

  Future<Exception?> initCipherSuite(HandshakeContext context) async {
    var (preMasterSecret, err) = await generatePreMasterSecret(
        context.ClientKeyExchangePublic,
        context.serverPrivateKey,
        context.curve);
    if (err != null) {
      return err;
    }
    Uint8List clientRandomBytes = context.clientRandom.encode();
    Uint8List serverRandomBytes = context.serverRandom.encode();

    if (context.UseExtendedMasterSecret) {
      var (handshakeMessages, handshakeMessageTypes, ok) =
          concatHandshakeMessages(context, false, false);
      if (!ok) {
        return Exception("error while concatenating handshake messages");
      }
      // logging.Descf(logging.ProtoDTLS,
      // 	common.JoinSlice("\n", false,
      // 		common.ProcessIndent("Initializing cipher suite...", "+", []string{
      // 			fmt.Sprintf("Concatenating messages in single byte array: \n<u>%s</u>", common.JoinSlice("\n", true, handshakeMessageTypes...)),
      // 			fmt.Sprintf("Generating hash from the byte array (<u>%d bytes</u>) via <u>%s</u>.", len(handshakeMessages), context.CipherSuite.HashAlgorithm),
      // 		})))
      Uint8List handshakeHash =
          context.cipherSuite.hashAlgorithm.execute(handshakeMessages);
      //logging.Descf(logging.ProtoDTLS, "Calculated Hanshake Hash: 0x%x (%d bytes). This data will be used to generate Extended Master Secret further.", handshakeHash, len(handshakeHash))
      //(context.serverMasterSecret, err)

      var (serverMasterSecret, err) = await generateExtendedMasterSecret(
          preMasterSecret, handshakeHash, context.cipherSuite.hashAlgorithm);
      context.serverMasterSecret = serverMasterSecret;
      // logging.Descf(logging.ProtoDTLS, "Generated ServerMasterSecret (Extended): <u>0x%x</u> (<u>%d bytes</u>), using Pre-Master Secret and Hanshake Hash. Client Random and Server Random was not used.", context.ServerMasterSecret, len(context.ServerMasterSecret))
    } else {
      var (serverMasterSecret, err) = await generateMasterSecret(
          preMasterSecret,
          clientRandomBytes,
          serverRandomBytes,
          context.cipherSuite.hashAlgorithm);
      context.serverMasterSecret = serverMasterSecret;
      // logging.Descf(logging.ProtoDTLS, "Generated ServerMasterSecret (Not Extended): <u>0x%x</u> (<u>%d bytes</u>), using Pre-Master Secret, Client Random and Server Random.", context.ServerMasterSecret, len(context.ServerMasterSecret))
    }
    if (err != null) {
      return err;
    }
    GCM gcm = await GCM.create(context.serverMasterSecret, clientRandomBytes,
        serverRandomBytes, Uint8List(0));
    //(gcm, err) = initGCM(context.serverMasterSecret, clientRandomBytes, serverRandomBytes, context.cipherSuite);
    // if err != nil {
    // 	return err
    // }
    // context.GCM = gcm
    // context.IsCipherSuiteInitialized = true
    // return nil
  }

  (CipherSuite?, Exception?) negotiateOnCipherSuiteIDs(
      List<CipherSuiteID> clientCipherSuiteIDs)
//  (*CipherSuite, error)
  {
    // for _, clientCipherSuiteID := range clientCipherSuiteIDs {
    // 	foundCipherSuite, ok := SupportedCipherSuites[clientCipherSuiteID]
    // 	if ok {
    // 		return &foundCipherSuite, nil
    // 	}
    // }
    // return nil, errors.New("cannot find mutually supported cipher suite between client and server")
    return (
      null,
      Exception(
          "cannot find mutually supported cipher suite between client and server")
    );
  }

  (Curve?, Exception?) negotiateOnCurves(List<Curve> clientCurves)
//  (Curve, error)
  {
    // for _, clientCurve := range clientCurves {
    // 	_, ok := SupportedCurves[Curve(clientCurve)]
    // 	if ok {
    // 		return Curve(clientCurve), nil
    // 	}
    // }
    // return 0, errors.New("cannot find mutually supported curve between client and server")
    return (
      null,
      Exception(
          "cannot find mutually supported curve between client and server")
    );
  }

  (SRTPProtectionProfile?, Exception?) negotiateOnSRTPProtectionProfiles(
      List<SRTPProtectionProfile> protectionProfiles)
// (SRTPProtectionProfile, error)
  {
    // for _, clientProtectionProfile := range protectionProfiles {
    // 	_, ok := SupportedSRTPProtectionProfiles[SRTPProtectionProfile(clientProtectionProfile)]
    // 	if ok {
    // 		return SRTPProtectionProfile(clientProtectionProfile), nil
    // 	}
    // }
    // return 0, errors.New("cannot find mutually supported SRTP protection profile between client and server")
    return (
      null,
      Exception(
          "cannot find mutually supported SRTP protection profile between client and server")
    );
  }

//(Uint8List,String,bool) concatHandshakeMessageTo( Uint8List result, String resultTypes,Map<HandshakeType,Uint8List> messagesMap, String mapType, HandshakeType handshakeType)
// ([]byte, []string, bool)
//{
  // item, ok := messagesMap[handshakeType]
  // if !ok {
  // 	return result, resultTypes, false
  // }
  // result = append(result, item...)
  // resultTypes = append(resultTypes, fmt.Sprintf("%s (%s)", handshakeType, mapType))
  // return result, resultTypes, true
//}

  (Uint8List, String, bool) concatHandshakeMessages(HandshakeContext context,
      bool includeReceivedCertificateVerify, bool includeReceivedFinished)
// ([]byte, []string, bool)
  {
    // result := make([]byte, 0)
    // resultTypes := make([]string, 0)
    // var ok bool
    // result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeClientHello)
    // if !ok {
    // 	return nil, nil, false
    // }
    // result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeServerHello)
    // if !ok {
    // 	return nil, nil, false
    // }
    // result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeCertificate)
    // if !ok {
    // 	return nil, nil, false
    // }
    // result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeServerKeyExchange)
    // if !ok {
    // 	return nil, nil, false
    // }
    // result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeCertificateRequest)
    // if !ok {
    // 	return nil, nil, false
    // }
    // result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesSent, "sent", HandshakeTypeServerHelloDone)
    // if !ok {
    // 	return nil, nil, false
    // }
    // result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeCertificate)
    // if !ok {
    // 	return nil, nil, false
    // }
    // result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeClientKeyExchange)
    // if !ok {
    // 	return nil, nil, false
    // }
    // if includeReceivedCertificateVerify {
    // 	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeCertificateVerify)
    // 	if !ok {
    // 		return nil, nil, false
    // 	}
    // }
    // if includeReceivedFinished {
    // 	result, resultTypes, ok = m.concatHandshakeMessageTo(result, resultTypes, context.HandshakeMessagesReceived, "recv", HandshakeTypeFinished)
    // 	if !ok {
    // 		return nil, nil, false
    // 	}
    // }

    // return result, resultTypes, true
    return (Uint8List(0), "", false);
  }
}
