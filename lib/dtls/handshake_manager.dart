import 'dart:io' as io;
import 'dart:typed_data';
import 'dart:math' as dmath;

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:dart_webrtc_nuts_and_bolts/dtls/cipher_suites.dart';
//import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto_final.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto_gcm.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_message.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/dtls_random.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/alert.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/algo_pair.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/certificate.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/certificate_request.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/certificate_verify.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/change_cipher_spec.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/client_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/client_key_exchange.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/finished.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/handshake_context.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/hello_verify_request.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_hello.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_hello_done.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake/server_key_exchange.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/handshake_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/init.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/simple_extensions.dart';
import 'package:dart_webrtc_nuts_and_bolts/dtls/utils.dart';

class HandshakeManager {
  // HandshakeContext newContext(InternetAddress addr, RawDatagramSocket conn,
  //     String clientUfrag, String expectedFingerprintHash) {
  //   return HandshakeContext();
  // }

  Future<void> processIncomingMessage(
      HandshakeContext context, Uint8List incomingMessage) async {
    final decodedMessage = await decodeDtlsMessage(
        context, incomingMessage, 0, incomingMessage.length);

    //context.protocolVersion = decodedMessage.recordHeader!.version;

    switch (decodedMessage.message.runtimeType) {
      case ClientHello:
        {
          //print("Protocol version: ${context.protocolVersion}");
          context.protocolVersion = decodedMessage.recordHeader!.version;
          //print("Protocol version: ${context.protocolVersion}");
          final message = decodedMessage.message as ClientHello;
          //print("Client hello Protocol version: ${message.version}");
          switch (context.flight) {
            case Flight.Flight0:
              // print("Message result: ${decodedMessage.message.runtimeType}");
              // HelloVerifyRequest hvr = HelloVerifyRequest(
              //     version: decodedMessage.message.version,
              //     cookie: generateDtlsCookie());
              // print("Hello verify request: ${hvr}");

              // ContentType contentType = ContentType.Handshake; // Handshake
              // final int version = 0xFEFF; // DTLS version
              // final int epoch = 0; // Initial epoch
              // final int sequenceNumber; // Initial sequence number
              // final Uint8List handshakeMessage = hvr.encode();

              // // DTLSRecord(this.handshakeMessage, this.sequenceNumber);

              // //Uint8List toBytes() {
              // final buffer = BytesBuilder();

              // Uint8List serverSequenceNumber = Uint8List(6);
              // serverSequenceNumber[serverSequenceNumber.length - 1] =
              //     context.serverSequenceNumber;

              // context.increaseSeverSequenceNumber();

              // buffer.addByte(contentType.value);
              // buffer.addByte(version >> 8);
              // buffer.addByte(version & 0xFF);
              // buffer.addByte(epoch >> 8);
              // buffer.addByte(epoch & 0xFF);
              // buffer.add(serverSequenceNumber); // 6 bytes for sequence number
              // buffer.addByte(handshakeMessage.length >> 8);
              // buffer.addByte(handshakeMessage.length & 0xFF);
              // buffer.add(handshakeMessage);
              context.clientSequenceNumber =
                  uint48ListToUint(decodedMessage.recordHeader!.sequenceNumber);

              // Create the HelloVerifyRequest object
              //print("Create the HelloVerifyRequest object");
              final HelloVerifyRequest hvr =
                  createDtlsHelloVerifyRequest(context);
              //print("created hvr: $hvr");
              await sendMessage(context, hvr);
              context.flight = Flight.Flight2;
              break;
              //print("Hello verify request: ${hvr}");

              // DTLS message details
              final ContentType contentType =
                  ContentType.Handshake; // Handshake type
              //const int version = 0xFEFD; // DTLS 1.2 version
              const int epoch = 0; // Initial epoch
              //int sequenceNumber = 0; // Initial sequence number
              final Uint8List handshakeMessage = hvr.encode();

              // Create a DTLS record
              //final buffer = BytesBuilder();

              // Server sequence number (6 bytes)
              Uint8List serverSequenceNumber =
                  uint48ToUint8List(context.clientSequenceNumber);
              // Debugging output
              //print("Server sequence number: ${serverSequenceNumber}");

              // Increment server sequence number in the context
              context.increaseServerSequenceNumber();

              // Build the DTLS record
              //buffer.addByte(22);
              //const int intVersion = 0xFEFD; // DTLS 1.2 version
              // buffer
              //     .addByte(decodedMessage.message.version.major); // Version MSB
              // buffer
              //     .addByte(decodedMessage.message.version.minor); // Version LSB

              // buffer.addByte(254); // Version MSB
              // buffer.addByte(253); // Version LSB
              // // [0xFE, 0xFF]
              // buffer.add(int16ToUint8List(epoch));
              // buffer.add(serverSequenceNumber); // 6 bytes of sequence number
              // buffer.add(int16ToUint8List(
              //     buffer.toBytes().length + handshakeMessage.length));
              // buffer.add(handshakeMessage); // Handshake message content

              // Final DTLS record
              //Uint8List dtlsRecord = buffer.toBytes();
              // var (rh, _, _) = decodeRecordHeader(
              //     buffer.toBytes(), 0, buffer.toBytes().length);
              // print("Encoded record header: $rh");

              // // Debugging output
              // print("Handshake message length: ${handshakeMessage.length}");

              // Uint8List encode() {
              final result = Uint8List(7 + SequenceNumberSize);
              result[0] = contentType.value;
              final byteData = ByteData.sublistView(result);
              byteData.setUint16(
                  1, context.protocolVersion.toUint16(), Endian.big);
              byteData.setUint16(3, epoch, Endian.big);
              result.setRange(5, 5 + SequenceNumberSize, serverSequenceNumber);
              byteData.setUint16(
                  5 + SequenceNumberSize, handshakeMessage.length, Endian.big);

              final handshakeHeader = Uint8List(12);
              final byteDataHH = ByteData.sublistView(handshakeHeader);

              // Set handshake type (1 byte)
              handshakeHeader[0] = HandshakeType.HelloVerifyRequest.value;

              // Copy length (3 bytes)
              handshakeHeader.setRange(1, 4, [0, 0, 12]);

              // Set message sequence (2 bytes, big-endian)
              byteDataHH.setUint16(4, 0, Endian.big);

              // Copy fragment offset (3 bytes)
              handshakeHeader.setRange(6, 9, [0, 0, 0]);

              // Copy fragment length (3 bytes)
              handshakeHeader.setRange(9, 12, [0, 0, 0]);
              List<int> dtlsRecord =
                  result + handshakeHeader + (handshakeMessage.toList());

              var (rh, _, _) = decodeRecordHeader(
                  Uint8List.fromList(dtlsRecord), 0, dtlsRecord.length);
              print("Encoded record header: $rh");

              // Debugging output
              print("Handshake message length: ${handshakeMessage.length}");

              final decodedMessage2 = await decodeDtlsMessage(
                  context,
                  Uint8List.fromList(dtlsRecord),
                  0,
                  Uint8List.fromList(dtlsRecord).length);
              print(decodedMessage2);

              // return result;
              //}
              //print("encode length: ${hvr.encode().length}");

              // print("DTLS record length: ${dtlsRecord.length}");
              // print("DTLS record content: ${dtlsRecord}");

//               handshakeType: HandshakeType.HelloVerifyRequest
// Length: {Uint24: [0, 0, 23]}
// messageSequence: 0
// fragmentOffset: {Uint24: [0, 0, 0]}
// fragmentLength: {Uint24: [0, 0, 23]}

              // context.conn.send(dtlsRecord, context.addr, context.port);

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

// if !bytes.Equal(context.Cookie, message.Cookie) {
// 				return m.setStateFailed(context, errors.New("client hello cookie is invalid"))
// 			}
              var (negotiatedCipherSuite, err) =
                  negotiateOnCipherSuiteIDs(message.cipherSuiteIDs);
              if (err != null) {
                //return setStateFailed(context, err);
              }
              context.cipherSuite = negotiatedCipherSuite!;
// 			logging.Descf(logging.ProtoDTLS, "Negotiation on cipher suites: Client sent a list of cipher suites, server selected one of them (mutually supported), and assigned in handshake context: %s", negotiatedCipherSuite)

              message.extensions.forEach((key, extensionItem) {
                if (extensionItem.runtimeType == ExtSupportedEllipticCurves) {
                  var (negotiatedCurve, err) =
                      negotiateOnCurves(extensionItem.curves);
                  context.curve = negotiatedCurve!;
                  context.extensions[key] =
                      ExtSupportedEllipticCurves(curves: [negotiatedCurve]);
                } else if (extensionItem.runtimeType == ExtUseSRTP) {
                  var (negotiatedProtectionProfile, err) =
                      negotiateOnSRTPProtectionProfiles(
                          extensionItem.protectionProfiles);
                  context.srtpProtectionProfile = negotiatedProtectionProfile!;
                  context.extensions[key] = context.srtpProtectionProfile;
                  context.extensions[key] = ExtUseSRTP(
                      protectionProfiles: [context.srtpProtectionProfile],
                      mki: Uint8List(0));
                } else if (extensionItem.runtimeType ==
                    ExtUseExtendedMasterSecret) {
                  context.UseExtendedMasterSecret = true;
                  context.extensions[key] = ExtUseExtendedMasterSecret();
                }
              });

              context.clientRandom = message.random;
// 			logging.Descf(logging.ProtoDTLS, "Client sent Client Random, it set to <u>0x%x</u> in handshake context.", message.Random.Encode())
              context.serverRandom = Random(
                  gmtUnixTime: DateTime.now(),
                  randomBytes: generateRandomBytes(randomBytesLength));
// 			context.ServerRandom.Generate()
// 			logging.Descf(logging.ProtoDTLS, "We generated Server Random, set to <u>0x%x</u> in handshake context.", context.ServerRandom.Encode())

              final keyPair =
                  await generateCurveKeypair(cryptography.KeyPairType.ed25519);

// 			if err != nil {
// 				return m.setStateFailed(context, err)
// 			}

              context.serverPublicKey =
                  Uint8List.fromList((await keyPair.extractPublicKey()).bytes);
              context.serverPrivateKey =
                  Uint8List.fromList((await keyPair.extractPrivateKeyBytes()));
// 			logging.Descf(logging.ProtoDTLS, "We generated Server Public and Private Key pair via <u>%s</u>, set in handshake context. Public Key: <u>0x%x</u>", context.Curve, context.ServerPublicKey)

              final clientRandomBytes = context.clientRandom.encode();
              final serverRandomBytes = context.serverRandom.encode();

// 			logging.Descf(logging.ProtoDTLS, "Generating ServerKeySignature. It will be sent to client via ServerKeyExchange DTLS message further.")
              var serverKeySignature = await generateKeySignature(
                  clientRandomBytes,
                  serverRandomBytes,
                  context.serverPublicKey,
                  context.curve, //x25519
                  context.serverPrivateKey);
// 			if err != nil {
// 				return m.setStateFailed(context, err)
// 			}
// 			logging.Descf(logging.ProtoDTLS, "ServerKeySignature was generated and set in handshake context (<u>%d bytes</u>).", len(context.ServerKeySignature))

              context.serverKeySignature = serverKeySignature;

              ServerHello serverHelloResponse = createDtlsServerHello(context);
              sendMessage(context, serverHelloResponse);
              Certificate certificateResponse = await createDtlsCertificate();
              sendMessage(context, certificateResponse);
              ServerKeyExchange serverKeyExchangeResponse =
                  createDtlsServerKeyExchange(context);
              sendMessage(context, serverKeyExchangeResponse);
              CertificateRequest certificateRequestResponse =
                  createDtlsCertificateRequest(context);
              sendMessage(context, certificateRequestResponse);
              ServerHelloDone serverHelloDoneResponse =
                  createDtlsServerHelloDone(context);
              sendMessage(context, serverHelloDoneResponse);
              context.flight = Flight.Flight4;
              break;
            //throw UnimplementedError();
            case Flight.Flight4:
            // TODO: Handle this case.
            //throw UnimplementedError();
            case Flight.Flight6:
            // TODO: Handle this case.
            // throw UnimplementedError();
          }
        }

      case Certificate:
        print("message: ${decodedMessage.message}");

      case ClientKeyExchange:
        print("message: ${decodedMessage.message}");
      case CertificateVerify:
        print("message: ${decodedMessage.message}");
      case Alert:
        print("alert: ${decodedMessage.message}");

      case Finished:
        print("message: ${decodedMessage.message}");
      default:
      //print("unhandle runtime type: ${decodedMessage}");
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

  Future<Uint8List> generateHmacDtlsCookie(
      Uint8List clientIp, Uint8List clientPort, Uint8List secret) async {
    // Combine client IP and port
    final data = BytesBuilder()
      ..add(clientIp)
      ..add(clientPort)
      ..toBytes();

    // Create HMAC using SHA-256
    final hmac = cryptography.Hmac(cryptography.Sha256());

    // Generate the HMAC digest
    //final digest = hmac.(data.toBytes());
    final mac = await hmac.calculateMac(
      data.toBytes(),
      secretKey: cryptography.SecretKey(secret),
    );

    // Return the digest as Uint8List
    return Uint8List.fromList(mac.bytes);
  }

  Future<void> sendMessage(HandshakeContext context, dynamic message) async {
    Uint8List encodedMessageBody = message.encode();
    Uint8List? encodedMessage; // := make([]byte, 0);
    HandshakeHeader handshakeHeader;
    //print("sending message...");
    //print("message: $message}");
    switch (message.getContentType()) {
      case ContentType.Handshake:
        var handshakeMessage = message;
        handshakeHeader = HandshakeHeader(
            handshakeType: handshakeMessage.getHandshakeType(),
            length: Uint24.fromUint32(encodedMessageBody.length),
            messageSequence: context.serverHandshakeSequenceNumber,
            fragmentOffset: Uint24.fromUint32(0),
            fragmentLength: Uint24.fromUint32(encodedMessageBody.length));

        //print("Handshake header: $handshakeHeader");

        // handshakeHeader = &HandshakeHeader{
        // 	HandshakeType:   handshakeMessage.GetHandshakeType(),
        // 	Length:          NewUint24FromUInt32((uint32(len(encodedMessageBody)))),
        // 	MessageSequence: context.ServerHandshakeSequenceNumber,
        // 	FragmentOffset:  NewUint24FromUInt32(0),
        // 	FragmentLength:  NewUint24FromUInt32((uint32(len(encodedMessageBody)))),
        // }
        context.increaseServerHandshakeSequence();

        // Encode the handshake header and append it
        final Uint8List encodedHandshakeHeader = handshakeHeader.encode();

        var (hh, _, _) = DecodeHandshakeHeader(
            encodedHandshakeHeader, 0, encodedHandshakeHeader.length);
        //print("decoded handshake: $hh");
        encodedMessage = Uint8List.fromList([
          ...encodedHandshakeHeader,
          ...encodedMessageBody,
        ]);

        // Store the message
        //context.handshakeMessagesSent[handshakeMessage.getHandshakeType()] =
        //    encodedMessage;
        break;
      default:
      //print("unhandle content type: ${message.getContentType()}");
      //print("result: ${message.result}");
      //case ContentType.ChangeCipherSpec:
      //encodedMessage = append(encodedMessage, encodedMessageBody...)
    }

    // Create sequence number
    Uint8List sequenceNumber = uint48ToUint8List(context.serverSequenceNumber);

    // Create record header
    //print("encoded message length: ${encodedMessage!.length}");
    RecordHeader recordheader = RecordHeader(
        contentType: message.getContentType(),
        version: DtlsVersion(254, 255),
        epoch: context.ServerEpoch,
        sequenceNumber: sequenceNumber,
        length: encodedMessage!.length);
    // Encrypt if epoch > 0 and cipher suite is initialized
    // if (context.serverEpoch > 0 && context.isCipherSuiteInitialized) {
    //   encodedMessage = context.gcm.encrypt(header, encodedMessage);
    //   header.length = encodedMessage.length;
    // }

    // Encode the header and prepend it to the message
    final Uint8List encodedRecordHeader = recordheader.encode();
    var (rh, _, _) =
        decodeRecordHeader(encodedRecordHeader, 0, encodedRecordHeader.length);
    // print("record header: $rh");
    //print("encoded record header: $encodedRecordHeader");
    //print("encode record header: $rh");

    encodedMessage =
        Uint8List.fromList([...encodedRecordHeader, ...encodedMessage]);
    // print("encoded message: $encodedMessage");

    // Log the message (replace with your logging mechanism)
    //print("Sending message (Flight ${context.flight})");
    //print("header: $header");
    //if (handshakeHeader != null) print(handshakeHeader);
    // print(message);

    //sequenceNumber[len(sequenceNumber)-1] += byte(context.ServerSequenceNumber)

    //       if context.ServerEpoch > 0 {
    // 	// Epoch is greater than zero, we should encrypt it.
    // 	if context.IsCipherSuiteInitialized {
    // 		encryptedMessage, err := context.GCM.Encrypt(header, encodedMessage)
    // 		if err != nil {
    // 			panic(err)
    // 		}
    // 		encodedMessage = encryptedMessage
    // 		header.Length = uint16(len(encodedMessage))
    // 	}
    // }

    // logging.Infof(logging.ProtoDTLS, "Sending message (<u>Flight %d</u>)\n%s\n%s\n%s", context.Flight, header, handshakeHeader, message)
    // logging.LineSpacer(2)
    var dtlsMsg = await decodeDtlsMessage(
        context, encodedMessage, 0, encodedMessage.length);
    // print(
    //     "Encoded dtls message protocol version: ${encodedMessage.sublist(1, 3)}");
    //print("Encoded dtls message: ${dtlsMsg}");

    // context.Conn.WriteToUDP(encodedMessage, context.Addr)
    // print("Sending to: ${context.addr}:${context.port}");
    context.conn.send(encodedMessage, context.addr, context.port);
    context.increaseServerSequenceNumber();
  }

  HelloVerifyRequest createDtlsHelloVerifyRequest(HandshakeContext context) {
    // result := HelloVerifyRequest{
    // 	// TODO: Before sending a ServerHello, we should negotiate on same protocol version which client supported and server supported protocol versions.
    // 	// But for now, we accept the version directly came from client.
    // 	Version: context.ProtocolVersion,
    // 	Cookie:  context.Cookie,
    // }
    // return result
    // return HelloVerifyRequest(
    //     version: context.protocolVersion,
    //     cookie: generateHmacDtlsCookie(
    //         Uint8List.fromList([127, 0, 0, 1]),
    //         Uint8List.fromList([4, 4, 4, 4]),
    //         Uint8List.fromList("mysecret".codeUnits)));

    return HelloVerifyRequest(
        version: DtlsVersion(254, 253), cookie: generateDtlsCookie());
    // var (hvr, offset, err) = HelloVerifyRequest.decode(
    //     raw_hello_verify_request, 0, raw_hello_verify_request.length);
    // return hvr;
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
      cipherSuite: context.cipherSuite,
      compressionMethodID: context.compressionMethodId,
      extensions: context.extensions,
    );
  }

  Future<Certificate> createDtlsCertificate() async {
    // logging.Descf(logging.ProtoDTLS, "Sending Server certificate (<u>%d bytes</u>) to the client.", len(ServerCertificate.Certificate))
    // result := Certificate{
    // 	Certificates: ServerCertificate.Certificate,
    // }
    // return result
    return Certificate(certificates: [generateSelfSignedCertificate()]);
  }

  ServerKeyExchange createDtlsServerKeyExchange(HandshakeContext context) {
    //logging.Descf(logging.ProtoDTLS, "Sending Server key exchange data PublicKey <u>0x%x</u> and ServerKeySignature (<u>%d bytes</u>) to the client.", context.ServerPublicKey, len(context.ServerPublicKey))
    return ServerKeyExchange(
      ellipticCurveType: context.curveType, //CurveTypeNamedCurve 0x03
      namedCurve: context.curve, //CurveX25519 0x001d            //x25519
      publicKey: context.serverPublicKey,
      algoPair: AlgoPair(
        hashAlgorithm:
            context.cipherSuite.hashAlgorithm, //HashAlgorithmSHA256 4
        signatureAlgorithm:
            context.cipherSuite.signatureAlgorithm, //SignatureAlgorithmECDSA 3
      ),
      signature: context.serverKeySignature,
    );
    //return result
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

  ServerHelloDone createDtlsServerHelloDone(HandshakeContext context) {
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
    final preMasterSecret = await generatePreMasterSecret(
        context.ClientKeyExchangePublic,
        context.serverPrivateKey,
        context.curve);
    // if (err != null) {
    //   return err;
    // }
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

      final serverMasterSecret = await generateExtendedMasterSecret(
          preMasterSecret, handshakeHash, context.cipherSuite.hashAlgorithm);
      context.serverMasterSecret = serverMasterSecret;
      // logging.Descf(logging.ProtoDTLS, "Generated ServerMasterSecret (Extended): <u>0x%x</u> (<u>%d bytes</u>), using Pre-Master Secret and Hanshake Hash. Client Random and Server Random was not used.", context.ServerMasterSecret, len(context.ServerMasterSecret))
    } else {
      final serverMasterSecret = await generateMasterSecret(
          preMasterSecret,
          clientRandomBytes,
          serverRandomBytes,
          context.cipherSuite.hashAlgorithm);
      context.serverMasterSecret = serverMasterSecret;
      // logging.Descf(logging.ProtoDTLS, "Generated ServerMasterSecret (Not Extended): <u>0x%x</u> (<u>%d bytes</u>), using Pre-Master Secret, Client Random and Server Random.", context.ServerMasterSecret, len(context.ServerMasterSecret))
    }
    // if (err != null) {
    //   return err;
    // }
    GCM gcm = await GCM.create(context.serverMasterSecret, clientRandomBytes,
        serverRandomBytes, Uint8List(0));
    //(gcm, err) = initGCM(context.serverMasterSecret, clientRandomBytes, serverRandomBytes, context.cipherSuite);
    // if err != nil {
    // 	return err
    // }
    context.gcm = gcm;
    context.IsCipherSuiteInitialized = true;
    // return nil
  }

//   (CipherSuite?, Exception?) negotiateOnCipherSuiteIDs(
//       List<CipherSuiteID> clientCipherSuiteIDs)
// //  (*CipherSuite, error)
//   {
//     // for _, clientCipherSuiteID := range clientCipherSuiteIDs {
//     // 	foundCipherSuite, ok := SupportedCipherSuites[clientCipherSuiteID]
//     // 	if ok {
//     // 		return &foundCipherSuite, nil
//     // 	}
//     // }
//     // return nil, errors.New("cannot find mutually supported cipher suite between client and server")
//     return (
//       null,
//       Exception(
//           "cannot find mutually supported cipher suite between client and server")
//     );
//   }

  (CipherSuite?, Exception?) negotiateOnCipherSuiteIDs(
      List<CipherSuiteID> clientCipherSuiteIDs
      //, Map<CipherSuiteID, CipherSuite> supportedCipherSuites
      ) {
    //print("ciphers supported: $supportedCipherSuites");
    for (var clientCipherSuiteID in clientCipherSuiteIDs) {
      // print("ciphers from client: $clientCipherSuiteID");
      if (supportedCipherSuites.containsKey(clientCipherSuiteID)) {
        return (supportedCipherSuites[clientCipherSuiteID], null);
      }

      if (clientCipherSuiteID.value == 0xc02b) {
        print("found cipher: $clientCipherSuiteID");
        return (
          CipherSuite(
            id: cipherSuiteID_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            keyExchangeAlgorithm: keyExchangeAlgorithmECDHE,
            certificateType: certificateTypeECDSASign,
            hashAlgorithm: hashAlgorithmSHA256,
            signatureAlgorithm: signatureAlgorithmECDSA,
          ),
          null
        );
      }
    }

    //clientCipherSuiteIDs.forEach((value) {});
    throw Exception(
        "Cannot find mutually supported cipher suite between client and server");
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
    print("Client curves: $clientCurves");

    for (var curve in clientCurves) {
      if (curve.value == 0x001d) {
        return (curve, null);
      }
    }

    throw Exception(
        "cannot find mutually supported curve between client and server");
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

  (Uint8List, List<HandshakeType>, bool) concatHandshakeMessageTo(
      Uint8List result,
      //String resultTypes,
      Map<HandshakeType, Uint8List> messagesMap,
      String mapType,
      HandshakeType handshakeType)
// ([]byte, []string, bool)
  {
    List<HandshakeType> resultTypes = [];
    BytesBuilder message = BytesBuilder();
    messagesMap.forEach((key, value) {
      message.add(value);
      resultTypes.add(key);
    });
    // item, ok := messagesMap[handshakeType]
    // if !ok {
    // 	return result, resultTypes, false
    // }
    // result = append(result, item...)
    // resultTypes = append(resultTypes, fmt.Sprintf("%s (%s)", handshakeType, mapType))
    return (message.toBytes(), resultTypes, true);
  }

  (List<Uint8List>, String, bool) concatHandshakeMessages(
      HandshakeContext context,
      bool includeReceivedCertificateVerify,
      bool includeReceivedFinished)
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
    return ([Uint8List(0)], "", false);
  }
}

Uint8List raw_hello_verify_request = Uint8List.fromList([
  0xfe,
  0xff,
  0x14,
  0x25,
  0xfb,
  0xee,
  0xb3,
  0x7c,
  0x95,
  0xcf,
  0x00,
  0xeb,
  0xad,
  0xe2,
  0xef,
  0xc7,
  0xfd,
  0xbb,
  0xed,
  0xf7,
  0x1f,
  0x6c,
  0xcd,
]);
