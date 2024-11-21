import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

final DynamicLibrary dtlsLib = Platform.isWindows
    ? DynamicLibrary.open('library/libdtls.dll')
    : throw UnsupportedError('Unsupported platform');

// Function signatures
typedef GetHashAlgorithmValueNative = Int32 Function(Uint8 alg);
typedef GetHashAlgorithmValueDart = int Function(int alg);

typedef GenerateValueKeyMessageNative = Pointer<Uint8> Function(
    Pointer<Uint8> clientRandom,
    IntPtr clientLen,
    Pointer<Uint8> serverRandom,
    IntPtr serverLen,
    Pointer<Uint8> publicKey,
    IntPtr publicLen);
typedef GenerateValueKeyMessageDart = Pointer<Uint8> Function(
    Pointer<Uint8> clientRandom,
    int clientLen,
    Pointer<Uint8> serverRandom,
    int serverLen,
    Pointer<Uint8> publicKey,
    int publicLen);

typedef PHashNative = Int32 Function(
    Pointer<Uint8> secret,
    IntPtr secretLen,
    Pointer<Uint8> seed,
    IntPtr seedLen,
    IntPtr requestedLength,
    Pointer<Pointer<Uint8>> out,
    Pointer<IntPtr> outLen);
typedef PHashDart = int Function(
    Pointer<Uint8> secret,
    int secretLen,
    Pointer<Uint8> seed,
    int seedLen,
    int requestedLength,
    Pointer<Pointer<Uint8>> out,
    Pointer<IntPtr> outLen);

typedef VerifyFinishedDataNative = Int32 Function(
    Pointer<Uint8> handshakeMessages,
    IntPtr handshakeLen,
    Pointer<Uint8> serverMasterSecret,
    IntPtr masterSecretLen,
    Pointer<Pointer<Uint8>> out,
    Pointer<IntPtr> outLen);
typedef VerifyFinishedDataDart = int Function(
    Pointer<Uint8> handshakeMessages,
    int handshakeLen,
    Pointer<Uint8> serverMasterSecret,
    int masterSecretLen,
    Pointer<Pointer<Uint8>> out,
    Pointer<IntPtr> outLen);

typedef GenerateServerCertificateNative = Int32 Function(
    Pointer<Utf8> cn,
    Pointer<Pointer<Uint8>> certPEM,
    Pointer<IntPtr> certPEMLen,
    Pointer<Pointer<Uint8>> privateKey,
    Pointer<IntPtr> privateKeyLen);
typedef GenerateServerCertificateDart = int Function(
    Pointer<Utf8> cn,
    Pointer<Pointer<Uint8>> certPEM,
    Pointer<IntPtr> certPEMLen,
    Pointer<Pointer<Uint8>> privateKey,
    Pointer<IntPtr> privateKeyLen);

typedef GenerateCurveKeypairNative = Int32 Function(
    Pointer<Pointer<Uint8>> publicKey,
    Pointer<IntPtr> publicKeyLen,
    Pointer<Pointer<Uint8>> privateKey,
    Pointer<IntPtr> privateKeyLen);
typedef GenerateCurveKeypairDart = int Function(
    Pointer<Pointer<Uint8>> publicKey,
    Pointer<IntPtr> publicKeyLen,
    Pointer<Pointer<Uint8>> privateKey,
    Pointer<IntPtr> privateKeyLen);

typedef GenerateKeySignatureNative = Int32 Function(
    Pointer<Uint8> clientRandom,
    IntPtr clientLen,
    Pointer<Uint8> serverRandom,
    IntPtr serverLen,
    Pointer<Uint8> publicKey,
    IntPtr publicLen,
    Pointer<Uint8> privateKey,
    IntPtr privateKeyLen,
    Pointer<Pointer<Uint8>> signed,
    Pointer<IntPtr> signedLen);
typedef GenerateKeySignatureDart = int Function(
    Pointer<Uint8> clientRandom,
    int clientLen,
    Pointer<Uint8> serverRandom,
    int serverLen,
    Pointer<Uint8> publicKey,
    int publicLen,
    Pointer<Uint8> privateKey,
    int privateKeyLen,
    Pointer<Pointer<Uint8>> signed,
    Pointer<IntPtr> signedLen);

typedef GetCertificateFingerprintFromBytesNative = Pointer<Utf8> Function(
    Pointer<Uint8> certificate, IntPtr certLen);
typedef GetCertificateFingerprintFromBytesDart = Pointer<Utf8> Function(
    Pointer<Uint8> certificate, int certLen);

typedef GeneratePreMasterSecretNative = Int32 Function(
    Pointer<Uint8> publicKey,
    IntPtr publicKeyLen,
    Pointer<Uint8> privateKey,
    IntPtr privateKeyLen,
    Pointer<Pointer<Uint8>> preMasterSecret,
    Pointer<IntPtr> preMasterSecretLen);
typedef GeneratePreMasterSecretDart = int Function(
    Pointer<Uint8> publicKey,
    int publicKeyLen,
    Pointer<Uint8> privateKey,
    int privateKeyLen,
    Pointer<Pointer<Uint8>> preMasterSecret,
    Pointer<IntPtr> preMasterSecretLen);

typedef VerifyCertificateNative = Int32 Function(
    Pointer<Uint8> handshakeMessages,
    IntPtr handshakeLen,
    Pointer<Uint8> clientSignature,
    IntPtr signatureLen,
    Pointer<Pointer<Uint8>> clientCertificates,
    IntPtr certCount);
typedef VerifyCertificateDart = int Function(
    Pointer<Uint8> handshakeMessages,
    int handshakeLen,
    Pointer<Uint8> clientSignature,
    int signatureLen,
    Pointer<Pointer<Uint8>> clientCertificates,
    int certCount);

// Function bindings
final GetHashAlgorithmValueDart getHashAlgorithmValue = dtlsLib.lookupFunction<
    GetHashAlgorithmValueNative,
    GetHashAlgorithmValueDart>('GetHashAlgorithmValue');

final GenerateValueKeyMessageDart generateValueKeyMessage = dtlsLib
    .lookupFunction<GenerateValueKeyMessageNative, GenerateValueKeyMessageDart>(
        'generateValueKeyMessage');

final PHashDart pHash = dtlsLib.lookupFunction<PHashNative, PHashDart>('PHash');

final VerifyFinishedDataDart verifyFinishedData =
    dtlsLib.lookupFunction<VerifyFinishedDataNative, VerifyFinishedDataDart>(
        'VerifyFinishedData');

final GenerateServerCertificateDart generateServerCertificate =
    dtlsLib.lookupFunction<GenerateServerCertificateNative,
        GenerateServerCertificateDart>('GenerateServerCertificate');

final GenerateCurveKeypairDart generateCurveKeypair = dtlsLib.lookupFunction<
    GenerateCurveKeypairNative,
    GenerateCurveKeypairDart>('GenerateCurveKeypair');

final GenerateKeySignatureDart generateKeySignature = dtlsLib.lookupFunction<
    GenerateKeySignatureNative,
    GenerateKeySignatureDart>('GenerateKeySignature');

final GetCertificateFingerprintFromBytesDart
    getCertificateFingerprintFromBytes = dtlsLib.lookupFunction<
            GetCertificateFingerprintFromBytesNative,
            GetCertificateFingerprintFromBytesDart>(
        'GetCertificateFingerprintFromBytes');

final GeneratePreMasterSecretDart generatePreMasterSecret = dtlsLib
    .lookupFunction<GeneratePreMasterSecretNative, GeneratePreMasterSecretDart>(
        'GeneratePreMasterSecret');

final VerifyCertificateDart verifyCertificate =
    dtlsLib.lookupFunction<VerifyCertificateNative, VerifyCertificateDart>(
        'VerifyCertificate');
