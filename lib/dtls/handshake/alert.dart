import 'dart:typed_data';

import 'package:dart_webrtc_nuts_and_bolts/dtls/record_header.dart';

enum AlertLevel {
  warning(1),
  fatal(2);

  final int value;
  const AlertLevel(this.value);

  @override
  String toString() {
    switch (this) {
      case AlertLevel.warning:
        return 'Warning ($value)';
      case AlertLevel.fatal:
        return 'Fatal ($value)';
      default:
        return 'Unknown Alert Type ($value)';
    }
  }
}

enum AlertDescription {
  closeNotify(0),
  unexpectedMessage(10),
  badRecordMac(20),
  decryptionFailed(21),
  recordOverflow(22),
  decompressionFailure(30),
  handshakeFailure(40),
  noCertificate(41),
  badCertificate(42),
  unsupportedCertificate(43),
  certificateRevoked(44),
  certificateExpired(45),
  certificateUnknown(46),
  illegalParameter(47),
  unknownCA(48),
  accessDenied(49),
  decodeError(50),
  decryptError(51),
  exportRestriction(60),
  protocolVersion(70),
  insufficientSecurity(71),
  internalError(80),
  userCanceled(90),
  noRenegotiation(100),
  unsupportedExtension(110);

  final int value;
  const AlertDescription(this.value);

  @override
  String toString() {
    switch (this) {
      case AlertDescription.closeNotify:
        return 'CloseNotify ($value)';
      case AlertDescription.unexpectedMessage:
        return 'UnexpectedMessage ($value)';
      case AlertDescription.badRecordMac:
        return 'BadRecordMac ($value)';
      case AlertDescription.decryptionFailed:
        return 'DecryptionFailed ($value)';
      case AlertDescription.recordOverflow:
        return 'RecordOverflow ($value)';
      case AlertDescription.decompressionFailure:
        return 'DecompressionFailure ($value)';
      case AlertDescription.handshakeFailure:
        return 'HandshakeFailure ($value)';
      case AlertDescription.noCertificate:
        return 'NoCertificate ($value)';
      case AlertDescription.badCertificate:
        return 'BadCertificate ($value)';
      case AlertDescription.unsupportedCertificate:
        return 'UnsupportedCertificate ($value)';
      case AlertDescription.certificateRevoked:
        return 'CertificateRevoked ($value)';
      case AlertDescription.certificateExpired:
        return 'CertificateExpired ($value)';
      case AlertDescription.certificateUnknown:
        return 'CertificateUnknown ($value)';
      case AlertDescription.illegalParameter:
        return 'IllegalParameter ($value)';
      case AlertDescription.unknownCA:
        return 'UnknownCA ($value)';
      case AlertDescription.accessDenied:
        return 'AccessDenied ($value)';
      case AlertDescription.decodeError:
        return 'DecodeError ($value)';
      case AlertDescription.decryptError:
        return 'DecryptError ($value)';
      case AlertDescription.exportRestriction:
        return 'ExportRestriction ($value)';
      case AlertDescription.protocolVersion:
        return 'ProtocolVersion ($value)';
      case AlertDescription.insufficientSecurity:
        return 'InsufficientSecurity ($value)';
      case AlertDescription.internalError:
        return 'InternalError ($value)';
      case AlertDescription.userCanceled:
        return 'UserCanceled ($value)';
      case AlertDescription.noRenegotiation:
        return 'NoRenegotiation ($value)';
      case AlertDescription.unsupportedExtension:
        return 'UnsupportedExtension ($value)';
      default:
        return 'Unknown Alert Description ($value)';
    }
  }
}

class Alert {
  AlertLevel level;
  AlertDescription description;

  Alert({required this.level, required this.description});

  ContentType getContentType() {
    return ContentType.Alert;
  }

  @override
  String toString() {
    return 'Alert ${level.toString()} ${description.toString()}';
  }

  static (Alert, int) decode(Uint8List buf, int offset, int arrayLen) {
    AlertLevel level =
        AlertLevel.values.firstWhere((e) => e.value == buf[offset]);
    offset++;
    AlertDescription description =
        AlertDescription.values.firstWhere((e) => e.value == buf[offset]);
    offset++;
    return (Alert(level: level, description: description), offset);
  }

  Uint8List encode() {
    return Uint8List.fromList([level.value, description.value]);
  }
}
