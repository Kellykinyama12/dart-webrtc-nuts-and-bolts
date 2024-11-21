import 'dart:ffi';
import 'dart:io';

import 'package:dart_webrtc_nuts_and_bolts/dtls/ffi.dart';
import 'package:ffi/ffi.dart';

void main() {
  // // Example usage of a function
  // final clientRandom = 'clientRandomExample'.toNativeUtf8();
  // final serverRandom = 'serverRandomExample'.toNativeUtf8();
  // final publicKey = 'publicKeyExample'.toNativeUtf8();

  // final result = generateValueKeyMessage(
  //     clientRandom.cast<Uint8>(),
  //     clientRandom.length,
  //     serverRandom.cast<Uint8>(),
  //     serverRandom.length,
  //     publicKey.cast<Uint8>(),
  //     publicKey.length);

  // print('Generated Value Key Message: ${result.cast<Utf8>().toDartString()}');

  // calloc.free(clientRandom);
  // calloc.free(serverRandom);
  // calloc.free(publicKey);

  final DynamicLibrary dtlsLib = Platform.isWindows
      ? DynamicLibrary.open('library/libdtls.dll')
      : throw UnsupportedError('Unsupported platform');
}
