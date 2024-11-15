import 'dart:typed_data';
import 'package:dart_webrtc_nuts_and_bolts/dtls/crypto.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/api.dart' as pc;
import 'package:asn1lib/asn1lib.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/pointycastle.dart';
//import 'config.dart'; // Assuming you have a config.dart file
import 'package:basic_utils/basic_utils.dart' as cryptoUtils;

final Logger logger = Logger('DTLS');

late Uint8List serverCertificate;
late String serverCertificateFingerprint;

void init() async {
  logger.info('Initializing self signed certificate for server...');
  try {
    serverCertificate = await generateServerCertificate("localhost");
    serverCertificateFingerprint =
        getCertificateFingerprint(serverCertificate!);
    logger.info(
        'Self signed certificate created with fingerprint $serverCertificateFingerprint');
    logger.info(
        'This certificate is stored in dtls.ServerCertificate variable globally, it will be used while DTLS handshake, sending SDP, SRTP, SRTCP packets, etc...');
  } catch (e) {
    logger.severe('Failed to generate server certificate: $e');
    rethrow;
  }
}
