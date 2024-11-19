import 'dart:collection';

class ProtocolVersion {
  final int version;
  final String name;

  static const SSLv3 = ProtocolVersion._(0x0300, "SSL 3.0");
  static const TLSv10 = ProtocolVersion._(0x0301, "TLS 1.0");
  static const TLSv11 = ProtocolVersion._(0x0302, "TLS 1.1");
  static const TLSv12 = ProtocolVersion._(0x0303, "TLS 1.2");
  static const TLSv13 = ProtocolVersion._(0x0304, "TLS 1.3");
  static const DTLSv10 = ProtocolVersion._(0xFEFF, "DTLS 1.0");
  static const DTLSv12 = ProtocolVersion._(0xFEFD, "DTLS 1.2");

  static const CLIENT_EARLIEST_SUPPORTED_DTLS = DTLSv10;
  static const CLIENT_EARLIEST_SUPPORTED_TLS = SSLv3;
  static const CLIENT_LATEST_SUPPORTED_DTLS = DTLSv12;
  static const CLIENT_LATEST_SUPPORTED_TLS = TLSv13;

  static const SERVER_EARLIEST_SUPPORTED_DTLS = DTLSv10;
  static const SERVER_EARLIEST_SUPPORTED_TLS = SSLv3;
  static const SERVER_LATEST_SUPPORTED_DTLS = DTLSv12;
  static const SERVER_LATEST_SUPPORTED_TLS = TLSv13;

  const ProtocolVersion._(this.version, this.name);

  int get majorVersion => version >> 8;
  int get minorVersion => version & 0xFF;

  bool isDTLS() => majorVersion == 0xFE;
  bool isTLS() => majorVersion == 0x03;
  bool isSSL() => this == SSLv3;

  bool isEqualOrEarlierVersionOf(ProtocolVersion other) {
    if (other == null || majorVersion != other.majorVersion) {
      return false;
    }
    final diff = minorVersion - other.minorVersion;
    return isDTLS() ? diff >= 0 : diff <= 0;
  }

  bool isEqualOrLaterVersionOf(ProtocolVersion other) {
    if (other == null || majorVersion != other.majorVersion) {
      return false;
    }
    final diff = minorVersion - other.minorVersion;
    return isDTLS() ? diff <= 0 : diff >= 0;
  }

  ProtocolVersion? getPreviousVersion() {
    if (isDTLS()) {
      if (this == DTLSv12) return DTLSv10;
    } else if (isTLS()) {
      switch (this) {
        case TLSv13:
          return TLSv12;
        case TLSv12:
          return TLSv11;
        case TLSv11:
          return TLSv10;
        case TLSv10:
          return SSLv3;
        default:
          return null;
      }
    }
    return null;
  }

  ProtocolVersion? getNextVersion() {
    if (isDTLS()) {
      if (this == DTLSv10) return DTLSv12;
    } else if (isTLS()) {
      switch (this) {
        case SSLv3:
          return TLSv10;
        case TLSv10:
          return TLSv11;
        case TLSv11:
          return TLSv12;
        case TLSv12:
          return TLSv13;
        default:
          return null;
      }
    }
    return null;
  }

  static ProtocolVersion? get(int major, int minor) {
    switch (major) {
      case 0x03:
        switch (minor) {
          case 0x00:
            return SSLv3;
          case 0x01:
            return TLSv10;
          case 0x02:
            return TLSv11;
          case 0x03:
            return TLSv12;
          case 0x04:
            return TLSv13;
        }
        return _unknownVersion(major, minor, "TLS");
      case 0xFE:
        switch (minor) {
          case 0xFF:
            return DTLSv10;
          case 0xFD:
            return DTLSv12;
        }
        return _unknownVersion(major, minor, "DTLS");
    }
    return _unknownVersion(major, minor, "UNKNOWN");
  }

  static ProtocolVersion _unknownVersion(int major, int minor, String prefix) {
    final hex =
        ((major << 8) | minor).toRadixString(16).padLeft(4, '0').toUpperCase();
    return ProtocolVersion._((major << 8) | minor, "$prefix 0x$hex");
  }

  @override
  bool operator ==(Object other) =>
      other is ProtocolVersion && version == other.version;

  @override
  int get hashCode => version;

  @override
  String toString() => name;

  static ProtocolVersion? getEarliest(
      List<ProtocolVersion> versions, bool Function(ProtocolVersion) filter) {
    return versions
        .where(filter)
        .reduce((a, b) => a.minorVersion < b.minorVersion ? a : b);
  }

  static ProtocolVersion? getLatest(
      List<ProtocolVersion> versions, bool Function(ProtocolVersion) filter) {
    return versions
        .where(filter)
        .reduce((a, b) => a.minorVersion > b.minorVersion ? a : b);
  }
}
