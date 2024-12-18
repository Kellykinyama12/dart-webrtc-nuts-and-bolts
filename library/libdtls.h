/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h>

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */




/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif

extern __declspec(dllexport) GoSlice generateValueKeyMessage(GoSlice clientRandom, GoSlice serverRandom, GoSlice publicKey);

/* Return type for PHash */
struct PHash_return {
	GoSlice r0;
	GoInterface r1;
};
extern __declspec(dllexport) struct PHash_return PHash(GoSlice secret, GoSlice seed, GoInt requestedLength);

/* Return type for VerifyFinishedData */
struct VerifyFinishedData_return {
	GoSlice r0;
	GoInterface r1;
};
extern __declspec(dllexport) struct VerifyFinishedData_return VerifyFinishedData(GoSlice handshakeMessages, GoSlice serverMasterSecret);

/* Return type for GenerateServerCertificate */
struct GenerateServerCertificate_return {
	GoSlice r0;
	GoSlice r1;
	GoInterface r2;
};
extern __declspec(dllexport) struct GenerateServerCertificate_return GenerateServerCertificate(GoString cn);

/* Return type for GenerateCurveKeypair */
struct GenerateCurveKeypair_return {
	GoSlice r0;
	GoSlice r1;
	GoInterface r2;
};
extern __declspec(dllexport) struct GenerateCurveKeypair_return GenerateCurveKeypair();

/* Return type for GenerateKeySignature */
struct GenerateKeySignature_return {
	GoSlice r0;
	GoInterface r1;
};
extern __declspec(dllexport) struct GenerateKeySignature_return GenerateKeySignature(GoSlice clientRandom, GoSlice serverRandom, GoSlice publicKey, GoSlice privateKey);

// Exported function to get certificate fingerprint from raw certificate bytes.
//
extern __declspec(dllexport) GoString GetCertificateFingerprintFromBytes(GoSlice certificate);

/* Return type for GeneratePreMasterSecret */
struct GeneratePreMasterSecret_return {
	GoSlice r0;
	GoInterface r1;
};
extern __declspec(dllexport) struct GeneratePreMasterSecret_return GeneratePreMasterSecret(GoSlice publicKey, GoSlice privateKey);
extern __declspec(dllexport) GoInterface VerifyCertificate(GoSlice handshakeMessages, GoSlice clientSignature, GoSlice clientCertificates);

#ifdef __cplusplus
}
#endif
