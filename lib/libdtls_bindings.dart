import 'dart:ffi';
import 'package:ffi/ffi.dart';

// Define GoSlice
class GoSlice extends Struct {
  external Pointer<Void> data;
  @IntPtr()
  external int len;
  @IntPtr()
  external int cap;
}

final class GoSlice extends ffi.Struct {
  external ffi.Pointer<ffi.Void> data;

  @GoInt()
  external int len;

  @GoInt()
  external int cap;
}

// Define GoString
class GoString extends Struct {
  external Pointer<Char> p;
  @IntPtr()
  external int n;
}

// Define GoInterface
class GoInterface extends Struct {
  external Pointer<Void> t;
  external Pointer<Void> v;
}

// Define return structures
class PHashReturn extends Struct {
  external GoSlice r0; // Resulting data
  external GoInterface r1; // Error or additional information
}

class VerifyFinishedDataReturn extends Struct {
  external GoSlice r0; // Resulting data
  external GoInterface r1; // Error or additional information
}

class GenerateServerCertificateReturn extends Struct {
  external GoSlice r0; // Certificate
  external GoSlice r1; // Additional data
  external GoInterface r2; // Error or additional information
}

class GenerateCurveKeypairReturn extends Struct {
  external GoSlice r0; // Public key
  external GoSlice r1; // Private key
  external GoInterface r2; // Error or additional information
}

class GenerateKeySignatureReturn extends Struct {
  external GoSlice r0; // Signature
  external GoInterface r1; // Error or additional information
}

class GeneratePreMasterSecretReturn extends Struct {
  external GoSlice r0; // Pre-master secret
  external GoInterface r1; // Error or additional information
}

// Load dynamic library
final dylib = DynamicLibrary.open('path/to/library.dll');

// Bindings for each function
typedef generateValueKeyMessage_native = GoSlice Function(
  GoSlice clientRandom,
  GoSlice serverRandom,
  GoSlice publicKey,
);
typedef generateValueKeyMessage_dart = GoSlice Function(
  GoSlice clientRandom,
  GoSlice serverRandom,
  GoSlice publicKey,
);

final generateValueKeyMessage = dylib.lookupFunction<
    generateValueKeyMessage_native,
    generateValueKeyMessage_dart>('generateValueKeyMessage');

typedef PHash_native = PHashReturn Function(
  GoSlice secret,
  GoSlice seed,
  Int64 requestedLength,
);
typedef PHash_dart = PHashReturn Function(
  GoSlice secret,
  GoSlice seed,
  int requestedLength,
);

final PHash = dylib.lookupFunction<PHash_native, PHash_dart>('PHash');

typedef VerifyFinishedData_native = VerifyFinishedDataReturn Function(
  GoSlice handshakeMessages,
  GoSlice serverMasterSecret,
);
typedef VerifyFinishedData_dart = VerifyFinishedDataReturn Function(
  GoSlice handshakeMessages,
  GoSlice serverMasterSecret,
);

final VerifyFinishedData = dylib.lookupFunction<
    VerifyFinishedData_native,
    VerifyFinishedData_dart>('VerifyFinishedData');

typedef GenerateServerCertificate_native = GenerateServerCertificateReturn
    Function(GoString cn);
typedef GenerateServerCertificate_dart = GenerateServerCertificateReturn
    Function(GoString cn);

final GenerateServerCertificate = dylib.lookupFunction<
    GenerateServerCertificate_native,
    GenerateServerCertificate_dart>('GenerateServerCertificate');

typedef GenerateCurveKeypair_native = GenerateCurveKeypairReturn Function();
typedef GenerateCurveKeypair_dart = GenerateCurveKeypairReturn Function();

final GenerateCurveKeypair = dylib.lookupFunction<
    GenerateCurveKeypair_native,
    GenerateCurveKeypair_dart>('GenerateCurveKeypair');

typedef GenerateKeySignature_native = GenerateKeySignatureReturn Function(
  GoSlice clientRandom,
  GoSlice serverRandom,
  GoSlice publicKey,
  GoSlice privateKey,
);
typedef GenerateKeySignature_dart = GenerateKeySignatureReturn Function(
  GoSlice clientRandom,
  GoSlice serverRandom,
  GoSlice publicKey,
  GoSlice privateKey,
);

final GenerateKeySignature = dylib.lookupFunction<
    GenerateKeySignature_native,
    GenerateKeySignature_dart>('GenerateKeySignature');

typedef GetCertificateFingerprintFromBytes_native = GoString Function(
  GoSlice certificate,
);
typedef GetCertificateFingerprintFromBytes_dart = GoString Function(
  GoSlice certificate,
);

final GetCertificateFingerprintFromBytes = dylib.lookupFunction<
    GetCertificateFingerprintFromBytes_native,
    GetCertificateFingerprintFromBytes_dart>(
  'GetCertificateFingerprintFromBytes',
);

typedef GeneratePreMasterSecret_native = GeneratePreMasterSecretReturn Function(
  GoSlice publicKey,
  GoSlice privateKey,
);
typedef GeneratePreMasterSecret_dart = GeneratePreMasterSecretReturn Function(
  GoSlice publicKey,
  GoSlice privateKey,
);

final GeneratePreMasterSecret = dylib.lookupFunction<
    GeneratePreMasterSecret_native,
    GeneratePreMasterSecret_dart>('GeneratePreMasterSecret');

typedef VerifyCertificate_native = GoInterface Function(
  GoSlice handshakeMessages,
  GoSlice clientSignature,
  GoSlice clientCertificates,
);
typedef VerifyCertificate_dart = GoInterface Function(
  GoSlice handshakeMessages,
  GoSlice clientSignature,
  GoSlice clientCertificates,
);

final VerifyCertificate = dylib.lookupFunction<
    VerifyCertificate_native,
    VerifyCertificate_dart>('VerifyCertificate');
