unit libsodium;

{ * License: MIT
  * Copyright (c) fibodevy
  * https://github.com/fibodevy
  * This notice must remain at the top of the file
  * }

{$mode ObjFPC}{$H+}

interface

{$define STATICLINK}

{$ifndef STATICLINK}
  {$ifdef WIN32}
    const lib = 'libsodium.dll';
  {$elseif defined(WIN64)}
    const lib = 'libsodium64.dll';
  {$else}
    {$fatal dynamic lib for this target not defined}
  {$endif}
{$else}
  {$ifdef WIN32}
    {$linklib libsodium.a}
    {$linklib libkernel32.a}
    {$linklib libmsvcrt.a}
    {$linklib libgcc.a}
    {$linklib libadvapi32.a}
  {$elseif defined(WIN64)}
    {$linklib libsodium.a}
    {$linklib libkernel32.a}
    {$linklib libmsvcrt.a}
    {$linklib libgcc.a}
    {$linklib libadvapi32.a}
  {$else}
    {$fatal static libs for this target missing}
  {$endif}
{$endif}

const
  { SODIUM }
  _sodium_size_max = High(PtrUInt);
  _sodium_base64_VARIANT_ORIGINAL = 1;
  _sodium_base64_VARIANT_ORIGINAL_NO_PADDING = 3;
  _sodium_base64_VARIANT_URLSAFE = 5;
  _sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7;
  { AEAD }
  _crypto_aead_aegis128l_KEYBYTES = 16;
  _crypto_aead_aegis128l_NSECBYTES = 0;
  _crypto_aead_aegis128l_NPUBBYTES = 16;
  _crypto_aead_aegis128l_ABYTES = 32;
  _crypto_aead_aegis256_KEYBYTES = 32;
  _crypto_aead_aegis256_NSECBYTES = 0;
  _crypto_aead_aegis256_NPUBBYTES = 32;
  _crypto_aead_aegis256_ABYTES = 32;
  _crypto_aead_aes256gcm_KEYBYTES = 32;
  _crypto_aead_aes256gcm_NSECBYTES = 0;
  _crypto_aead_aes256gcm_NPUBBYTES = 12;
  _crypto_aead_aes256gcm_ABYTES = 16;
  _crypto_aead_aes256gcm_MESSAGEBYTES_MAX = 68719476704;
  _crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
  _crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0;
  _crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
  _crypto_aead_chacha20poly1305_ietf_ABYTES = 16;
  _crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX = 274877906880;
  _crypto_aead_chacha20poly1305_KEYBYTES = 32;
  _crypto_aead_chacha20poly1305_NSECBYTES = 0;
  _crypto_aead_chacha20poly1305_NPUBBYTES = 8;
  _crypto_aead_chacha20poly1305_ABYTES = 16;
  _crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX = _sodium_size_max - _crypto_aead_chacha20poly1305_ABYTES;
  _crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32;
  _crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0;
  _crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24;
  _crypto_aead_xchacha20poly1305_ietf_ABYTES = 16;
  _crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = _sodium_size_max - _crypto_aead_xchacha20poly1305_ietf_ABYTES;
  { AUTH }
  _crypto_auth_PRIMITIVE = 'hmacsha512256';
  _crypto_auth_hmacsha256_BYTES = 32;
  _crypto_auth_hmacsha256_KEYBYTES = 32;
  _crypto_auth_hmacsha512_BYTES = 64;
  _crypto_auth_hmacsha512_KEYBYTES = 32;
  _crypto_auth_hmacsha512256_BYTES = 32;
  _crypto_auth_hmacsha512256_KEYBYTES = 32;
  _crypto_auth_BYTES = _crypto_auth_hmacsha512256_BYTES;
  _crypto_auth_KEYBYTES = _crypto_auth_hmacsha512256_KEYBYTES;
  { STREAM }
  _crypto_stream_salsa20_KEYBYTES = 32;
  _crypto_stream_salsa20_NONCEBYTES = 8;
  _crypto_stream_salsa20_MESSAGEBYTES_MAX = _sodium_size_max;
  _crypto_stream_salsa2012_KEYBYTES = 32;
  _crypto_stream_salsa2012_NONCEBYTES = 8;
  _crypto_stream_salsa2012_MESSAGEBYTES_MAX = _sodium_size_max;
  _crypto_stream_salsa208_KEYBYTES = 32;
  _crypto_stream_salsa208_NONCEBYTES = 8;
  _crypto_stream_salsa208_MESSAGEBYTES_MAX = _sodium_size_max;
  _crypto_stream_xchacha20_KEYBYTES = 32;
  _crypto_stream_xchacha20_NONCEBYTES = 24;
  _crypto_stream_xchacha20_MESSAGEBYTES_MAX = _sodium_size_max;
  _crypto_stream_xsalsa20_KEYBYTES = 32;
  _crypto_stream_xsalsa20_NONCEBYTES = 24;
  _crypto_stream_xsalsa20_MESSAGEBYTES_MAX = _sodium_size_max;
  _crypto_stream_KEYBYTES = _crypto_stream_xsalsa20_KEYBYTES;
  _crypto_stream_NONCEBYTES = _crypto_stream_xsalsa20_NONCEBYTES;
  _crypto_stream_MESSAGEBYTES_MAX = _crypto_stream_xsalsa20_MESSAGEBYTES_MAX;
  _crypto_stream_PRIMITIVE = 'xsalsa20';
  _crypto_stream_chacha20_KEYBYTES = 32;
  _crypto_stream_chacha20_NONCEBYTES = 8;
  _crypto_stream_chacha20_MESSAGEBYTES_MAX = _sodium_size_max;
  _crypto_stream_chacha20_ietf_KEYBYTES = 32;
  _crypto_stream_chacha20_ietf_NONCEBYTES = 12;
  _crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX = _sodium_size_max;
  { BOX }
  _crypto_box_curve25519xchacha20poly1305_SEEDBYTES = 32;
  _crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES = 32;
  _crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES = 32;
  _crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES = 32;
  _crypto_box_curve25519xchacha20poly1305_NONCEBYTES = 24;
  _crypto_box_curve25519xchacha20poly1305_MACBYTES = 16;
  _crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX = _crypto_stream_xchacha20_MESSAGEBYTES_MAX -_crypto_box_curve25519xchacha20poly1305_MACBYTES;
  _crypto_box_curve25519xchacha20poly1305_SEALBYTES = _crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES + _crypto_box_curve25519xchacha20poly1305_MACBYTES;
  _crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = 32;
  _crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32;
  _crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
  _crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = 32;
  _crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = 24;
  _crypto_box_curve25519xsalsa20poly1305_MACBYTES = 16;
  _crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = 16;
  _crypto_box_SEEDBYTES = _crypto_box_curve25519xsalsa20poly1305_SEEDBYTES;
  _crypto_box_PUBLICKEYBYTES = _crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
  _crypto_box_SECRETKEYBYTES = _crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
  _crypto_box_NONCEBYTES = _crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
  _crypto_box_MACBYTES = _crypto_box_curve25519xsalsa20poly1305_MACBYTES;
  _crypto_box_PRIMITIVE = 'curve25519xsalsa20poly1305';
  _crypto_box_BEFORENMBYTES = _crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
  _crypto_box_BOXZEROBYTES = _crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
  { CORE }
  _crypto_core_ed25519_BYTES = 32;
  _crypto_core_ed25519_UNIFORMBYTES = 32;
  _crypto_core_ed25519_SCALARBYTES = 32;
  _crypto_core_ed25519_NONREDUCEDSCALARBYTES = 64;
  _crypto_core_ed25519_HASHBYTES = 64;
  _crypto_core_hchacha20_OUTPUTBYTES = 32;
  _crypto_core_hchacha20_INPUTBYTES = 16;
  _crypto_core_hchacha20_KEYBYTES = 32;
  _crypto_core_hchacha20_CONSTBYTES = 16;
  _crypto_core_hsalsa20_OUTPUTBYTES = 32;
  _crypto_core_hsalsa20_INPUTBYTES = 16;
  _crypto_core_hsalsa20_KEYBYTES = 32;
  _crypto_core_hsalsa20_CONSTBYTES = 16;
  _crypto_core_ristretto255_BYTES = 32;
  _crypto_core_ristretto255_SCALARBYTES = 32;
  _crypto_core_ristretto255_NONREDUCEDSCALARBYTES = 64;
  _crypto_core_ristretto255_HASHBYTES = 64;
  _crypto_core_salsa20_OUTPUTBYTES = 64;
  _crypto_core_salsa20_INPUTBYTES = 16;
  _crypto_core_salsa20_KEYBYTES = 32;
  _crypto_core_salsa20_CONSTBYTES = 16;
  _crypto_core_salsa2012_OUTPUTBYTES = 64;
  _crypto_core_salsa2012_INPUTBYTES = 16;
  _crypto_core_salsa2012_KEYBYTES = 32;
  _crypto_core_salsa2012_CONSTBYTES = 16;
  _crypto_core_salsa208_OUTPUTBYTES = 64;
  _crypto_core_salsa208_INPUTBYTES = 16;
  _crypto_core_salsa208_KEYBYTES = 32;
  _crypto_core_salsa208_CONSTBYTES = 16;
  { GENERICHASH }
  _crypto_generichash_blake2b_BYTES_MIN = 16;
  _crypto_generichash_blake2b_BYTES_MAX = 64;
  _crypto_generichash_blake2b_BYTES = 32;
  _crypto_generichash_blake2b_KEYBYTES_MIN = 16;
  _crypto_generichash_blake2b_KEYBYTES_MAX = 64;
  _crypto_generichash_blake2b_KEYBYTES = 32;
  _crypto_generichash_blake2b_SALTBYTES = 16;
  _crypto_generichash_blake2b_PERSONALBYTES = 16;
  _crypto_generichash_BYTES_MIN = _crypto_generichash_blake2b_BYTES_MIN;
  _crypto_generichash_BYTES_MAX = _crypto_generichash_blake2b_BYTES_MAX;
  _crypto_generichash_BYTES = _crypto_generichash_blake2b_BYTES;
  _crypto_generichash_KEYBYTES_MIN = _crypto_generichash_blake2b_KEYBYTES_MIN;
  _crypto_generichash_KEYBYTES_MAX = _crypto_generichash_blake2b_KEYBYTES_MAX;
  _crypto_generichash_KEYBYTES = _crypto_generichash_blake2b_KEYBYTES;
  _crypto_generichash_PRIMITIVE = 'blake2b';
  { HASH }
  _crypto_hash_PRIMITIVE = 'sha512';
  _crypto_hash_sha256_BYTES = 32;
  _crypto_hash_sha512_BYTES = 64;
  _crypto_hash_BYTES = _crypto_hash_sha512_BYTES;
  { KDF }
  _crypto_kdf_PRIMITIVE = 'blake2b';
  _crypto_kdf_blake2b_BYTES_MIN = 16;
  _crypto_kdf_blake2b_BYTES_MAX = 64;
  _crypto_kdf_blake2b_CONTEXTBYTES = 8;
  _crypto_kdf_blake2b_KEYBYTES = 32;
  _crypto_kdf_BYTES_MIN = _crypto_kdf_blake2b_BYTES_MIN;
  _crypto_kdf_BYTES_MAX = _crypto_kdf_blake2b_BYTES_MAX;
  _crypto_kdf_CONTEXTBYTES = _crypto_kdf_blake2b_CONTEXTBYTES;
  _crypto_kdf_KEYBYTES = _crypto_kdf_blake2b_KEYBYTES;
  _crypto_kdf_hkdf_sha256_KEYBYTES = _crypto_auth_hmacsha256_BYTES;
  _crypto_kdf_hkdf_sha256_BYTES_MIN = 0;
  _crypto_kdf_hkdf_sha256_BYTES_MAX = $ff * _crypto_auth_hmacsha256_BYTES;
  _crypto_kdf_hkdf_sha512_KEYBYTES = _crypto_auth_hmacsha512_BYTES;
  _crypto_kdf_hkdf_sha512_BYTES_MIN = 0;
  _crypto_kdf_hkdf_sha512_BYTES_MAX = $ff * _crypto_auth_hmacsha512_BYTES;
  { KX }
  _crypto_kx_PUBLICKEYBYTES = 32;
  _crypto_kx_SECRETKEYBYTES = 32;
  _crypto_kx_SEEDBYTES = 32;
  _crypto_kx_SESSIONKEYBYTES = 32;
  _crypto_kx_PRIMITIVE = 'x25519blake2b';
  { ONETIMEAUTH }
  _crypto_onetimeauth_PRIMITIVE = 'poly1305';
  _crypto_onetimeauth_poly1305_BYTES = 16;
  _crypto_onetimeauth_poly1305_KEYBYTES = 32;
  _crypto_onetimeauth_BYTES = _crypto_onetimeauth_poly1305_BYTES;
  _crypto_onetimeauth_KEYBYTES = _crypto_onetimeauth_poly1305_KEYBYTES;
  { PWHASH }
  _crypto_pwhash_argon2i_ALG_ARGON2I13 = 1;
  _crypto_pwhash_argon2i_BYTES_MIN = 16;
  _crypto_pwhash_argon2i_PASSWD_MIN = 0;
  _crypto_pwhash_argon2i_PASSWD_MAX = 4294967295;
  _crypto_pwhash_argon2i_SALTBYTES = 16;
  _crypto_pwhash_argon2i_STRBYTES = 128;
  _crypto_pwhash_argon2i_STRPREFIX = '$argon2i$';
  _crypto_pwhash_argon2i_OPSLIMIT_MIN = 3;
  _crypto_pwhash_argon2i_OPSLIMIT_MAX = 4294967295;
  _crypto_pwhash_argon2i_MEMLIMIT_MIN = 8192;
  _crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE = 4;
  _crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE = 33554432;
  _crypto_pwhash_argon2i_OPSLIMIT_MODERATE = 6;
  _crypto_pwhash_argon2i_MEMLIMIT_MODERATE = 134217728;
  _crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE = 8;
  _crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE = 536870912;
  _crypto_pwhash_argon2id_ALG_ARGON2ID13 = 2;
  _crypto_pwhash_argon2id_BYTES_MIN = 16;
  _crypto_pwhash_argon2id_BYTES_MAX = _sodium_size_max;
  _crypto_pwhash_argon2id_PASSWD_MIN = 0;
  _crypto_pwhash_argon2id_PASSWD_MAX = 4294967295;
  _crypto_pwhash_argon2id_SALTBYTES = 16;
  _crypto_pwhash_argon2id_STRBYTES = 128;
  _crypto_pwhash_argon2id_STRPREFIX = '$argon2id$';
  _crypto_pwhash_argon2id_OPSLIMIT_MIN = 1;
  _crypto_pwhash_argon2id_OPSLIMIT_MAX = 4294967295;
  _crypto_pwhash_argon2id_MEMLIMIT_MIN = 8192;
  _crypto_pwhash_argon2id_MEMLIMIT_MAX = _sodium_size_max;
  _crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE = 2;
  _crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE = 67108864;
  _crypto_pwhash_argon2id_OPSLIMIT_MODERATE = 3;
  _crypto_pwhash_argon2id_MEMLIMIT_MODERATE = 268435456;
  _crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE = 4;
  _crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE = 1073741824;
  _crypto_pwhash_scryptsalsa208sha256_BYTES_MIN = 16;
  _crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN = 0;
  _crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX = _sodium_size_max;
  _crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;
  _crypto_pwhash_scryptsalsa208sha256_STRBYTES = 102;
  _crypto_pwhash_scryptsalsa208sha256_STRPREFIX = '$7$';
  _crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN = 32768;
  _crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX = 4294967295;
  _crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN = 16777216;
  _crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = 524288;
  _crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = 16777216;
  _crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = 33554432;
  _crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = 1073741824;
  _crypto_pwhash_ALG_ARGON2I13 = _crypto_pwhash_argon2i_ALG_ARGON2I13;
  _crypto_pwhash_ALG_ARGON2ID13 = _crypto_pwhash_argon2id_ALG_ARGON2ID13;
  _crypto_pwhash_ALG_DEFAULT = _crypto_pwhash_ALG_ARGON2ID13;
  _crypto_pwhash_BYTES_MIN = _crypto_pwhash_argon2id_BYTES_MIN;
  _crypto_pwhash_BYTES_MAX = _crypto_pwhash_argon2id_BYTES_MAX;
  _crypto_pwhash_PASSWD_MIN = _crypto_pwhash_argon2id_PASSWD_MIN;
  _crypto_pwhash_PASSWD_MAX = _crypto_pwhash_argon2id_PASSWD_MAX;
  _crypto_pwhash_SALTBYTES = _crypto_pwhash_argon2id_SALTBYTES;
  _crypto_pwhash_STRBYTES = _crypto_pwhash_argon2id_STRBYTES;
  _crypto_pwhash_STRPREFIX = _crypto_pwhash_argon2id_STRPREFIX;
  _crypto_pwhash_OPSLIMIT_MIN = _crypto_pwhash_argon2id_OPSLIMIT_MIN;
  _crypto_pwhash_OPSLIMIT_MAX = _crypto_pwhash_argon2id_OPSLIMIT_MAX;
  _crypto_pwhash_MEMLIMIT_MIN = _crypto_pwhash_argon2id_MEMLIMIT_MIN;
  _crypto_pwhash_MEMLIMIT_MAX = _crypto_pwhash_argon2id_MEMLIMIT_MAX;
  _crypto_pwhash_OPSLIMIT_INTERACTIVE = _crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE;
  _crypto_pwhash_MEMLIMIT_INTERACTIVE = _crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE;
  _crypto_pwhash_OPSLIMIT_MODERATE = _crypto_pwhash_argon2id_OPSLIMIT_MODERATE;
  _crypto_pwhash_MEMLIMIT_MODERATE = _crypto_pwhash_argon2id_MEMLIMIT_MODERATE;
  _crypto_pwhash_OPSLIMIT_SENSITIVE = _crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE;
  _crypto_pwhash_MEMLIMIT_SENSITIVE = _crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE;
  _crypto_pwhash_PRIMITIVE = 'argon2id,argon2i';
  { RANDOMBYTES }
  _randombytes_SEEDBYTES = 32;
  _randombytes_BYTES_MAX = $ffffffff;
  { SCALARMULT }
  _crypto_scalarmult_PRIMITIVE = 'curve25519';
  _crypto_scalarmult_curve25519_BYTES = 32;
  _crypto_scalarmult_curve25519_SCALARBYTES = 32;
  _crypto_scalarmult_BYTES = _crypto_scalarmult_curve25519_BYTES;
  _crypto_scalarmult_SCALARBYTES = _crypto_scalarmult_curve25519_SCALARBYTES;
  _crypto_scalarmult_ed25519_BYTES = 32;
  _crypto_scalarmult_ed25519_SCALARBYTES = 32;
  _crypto_scalarmult_ristretto255_BYTES = 32;
  _crypto_scalarmult_ristretto255_SCALARBYTES = 32;
  { SECRETBOX }
  _crypto_secretbox_xchacha20poly1305_KEYBYTES = 32;
  _crypto_secretbox_xchacha20poly1305_NONCEBYTES = 24;
  _crypto_secretbox_xchacha20poly1305_MACBYTES = 16;
  _crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX = _crypto_stream_xchacha20_MESSAGEBYTES_MAX - _crypto_secretbox_xchacha20poly1305_MACBYTES;
  _crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
  _crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;
  _crypto_secretbox_xsalsa20poly1305_MACBYTES = 16;
  _crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16;
  _crypto_secretbox_KEYBYTES = _crypto_secretbox_xsalsa20poly1305_KEYBYTES;
  _crypto_secretbox_NONCEBYTES = _crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
  _crypto_secretbox_MACBYTES = _crypto_secretbox_xsalsa20poly1305_MACBYTES;
  _crypto_secretbox_PRIMITIVE = 'xsalsa20poly1305';
  _crypto_secretbox_MESSAGEBYTES_MAX = _crypto_stream_xsalsa20_MESSAGEBYTES_MAX - _crypto_secretbox_xsalsa20poly1305_MACBYTES;
  _crypto_secretbox_BOXZEROBYTES = _crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;
  { SECRETSTREAM }
  _crypto_secretstream_xchacha20poly1305_KEYBYTES = _crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  _crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = $00;
  _crypto_secretstream_xchacha20poly1305_TAG_PUSH = $01;
  _crypto_secretstream_xchacha20poly1305_TAG_REKEY = $02;
  _crypto_secretstream_xchacha20poly1305_TAG_FINAL = $03;
  _crypto_secretstream_xchacha20poly1305_ABYTES = 1 + _crypto_aead_xchacha20poly1305_ietf_ABYTES;
  _crypto_secretstream_xchacha20poly1305_HEADERBYTES = _crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  _crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX = 274877906816;
  { SHORTHASH }
  _crypto_shorthash_PRIMITIVE = 'siphash24';
  _crypto_shorthash_siphash24_BYTES = 8;
  _crypto_shorthash_siphash24_KEYBYTES = 16;
  _crypto_shorthash_BYTES = _crypto_shorthash_siphash24_BYTES;
  _crypto_shorthash_KEYBYTES = _crypto_shorthash_siphash24_KEYBYTES;
  _crypto_shorthash_siphashx24_BYTES = 16;
  _crypto_shorthash_siphashx24_KEYBYTES = 16;
  { SIGN }
  _crypto_sign_PRIMITIVE = 'ed25519';
  _crypto_sign_ed25519_BYTES = 64;
  _crypto_sign_ed25519_SEEDBYTES = 32;
  _crypto_sign_ed25519_PUBLICKEYBYTES = 32;
  _crypto_sign_ed25519_SECRETKEYBYTES = 64;
  _crypto_sign_ed25519_MESSAGEBYTES_MAX = _sodium_size_max - _crypto_sign_ed25519_BYTES;
  _crypto_sign_BYTES = _crypto_sign_ed25519_BYTES;
  _crypto_sign_SEEDBYTES = _crypto_sign_ed25519_SEEDBYTES;
  _crypto_sign_PUBLICKEYBYTES = _crypto_sign_ed25519_PUBLICKEYBYTES;
  _crypto_sign_SECRETKEYBYTES = _crypto_sign_ed25519_SECRETKEYBYTES;
  _crypto_sign_MESSAGEBYTES_MAX = _crypto_sign_ed25519_MESSAGEBYTES_MAX;
  { VERIFY }
  _crypto_verify_16_BYTES = 16;
  _crypto_verify_32_BYTES = 32;
  _crypto_verify_64_BYTES = 64;

type
  { HASH }
  crypto_hash_sha256_state = packed record
    state: array[0..7] of uint32;
    count: array[0..1] of uint32;
    buf: array[0..63] of byte;
  end;
  pcrypto_hash_sha256_state = ^crypto_hash_sha256_state;
  crypto_hash_sha512_state = packed record
    state: array[0..7] of uint64;
    count: array[0..1] of uint64;
    buf: array[0..127] of byte;
  end;
  pcrypto_hash_sha512_state = ^crypto_hash_sha512_state;

  { AUTH }
  crypto_auth_hmacsha256_state = packed record
    ictx: crypto_hash_sha256_state;
    octx: crypto_hash_sha256_state;
  end;
  pcrypto_auth_hmacsha256_state = ^crypto_auth_hmacsha256_state;
  crypto_auth_hmacsha512_state = packed record
    ictx: pcrypto_hash_sha512_state;
    octx: pcrypto_hash_sha512_state;
  end;
  pcrypto_auth_hmacsha512_state = ^crypto_auth_hmacsha512_state;
  crypto_auth_hmacsha512256_state = crypto_auth_hmacsha512_state;
  pcrypto_auth_hmacsha512256_state = ^crypto_auth_hmacsha512256_state;

  { GENERICHASH }
  crypto_generichash_blake2b_state = packed record
    h: array[0..7] of uint64;
    t: array[0..1] of uint64;
    f: array[0..1] of uint64;
    buf: array[0..255] of uint8;
    buflen: size_t;
    last_node: uint8;
    padding64: array[0..26] of byte;
  end;
  pcrypto_generichash_blake2b_state = ^crypto_generichash_blake2b_state;
  crypto_generichash_state = crypto_generichash_blake2b_state;
  pcrypto_generichash_state = ^crypto_generichash_state;

  { ONETIMEAUTH }
  crypto_onetimeauth_poly1305_state = packed record
    aligner: uint64;
    opaque: array[0..135] of byte;
  end;
  pcrypto_onetimeauth_poly1305_state = ^crypto_onetimeauth_poly1305_state;
  crypto_onetimeauth_state = crypto_onetimeauth_poly1305_state;
  pcrypto_onetimeauth_state = ^crypto_onetimeauth_state;

  { SIGN }
  crypto_sign_ed25519ph_state = packed record
    hs: crypto_hash_sha512_state;
  end;
  pcrypto_sign_ed25519ph_state = ^crypto_sign_ed25519ph_state;
  crypto_sign_state = crypto_sign_ed25519ph_state;
  pcrypto_sign_state = ^crypto_sign_state;

  { SECRETSTREAM }
  crypto_secretstream_xchacha20poly1305_state = packed record
    k: array[0..31] of uint32;
    nonce: array[0..11] of uint32;
    _pad: array[0..7] of byte;
  end;
  pcrypto_secretstream_xchacha20poly1305_state = ^crypto_secretstream_xchacha20poly1305_state;

  { AEAD }
  crypto_aead_aes256gcm_state = packed record
    opaque: array[0..511] of byte;
  end;
  pcrypto_aead_aes256gcm_state = ^crypto_aead_aes256gcm_state;

  { KDF }
  crypto_kdf_hkdf_sha256_state = packed record
    st: crypto_auth_hmacsha256_state;
  end;
  pcrypto_kdf_hkdf_sha256_state = ^crypto_kdf_hkdf_sha256_state;
  crypto_kdf_hkdf_sha512_state = packed record
    st: crypto_auth_hmacsha512_state;
  end;
  pcrypto_kdf_hkdf_sha512_state = ^crypto_kdf_hkdf_sha512_state;

  { RANDOMBYTES }
  randombytes_implementation = packed record
    implementation_name: pansichar;
    random: pointer;
    stir: pointer;
    uniform: pointer;
    buf: pointer;
    close: pointer;
  end;
  prandombytes_implementation = ^randombytes_implementation;

  { OTHER }
  psize_t = ^size_t;

{ AEAD }
// Number of bytes in a ChaCha20-Poly1305 key
function crypto_aead_chacha20poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the secret nonce for ChaCha20-Poly1305
function crypto_aead_chacha20poly1305_nsecbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the public nonce for ChaCha20-Poly1305
function crypto_aead_chacha20poly1305_npubbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Additional bytes added by the authentication tag
function crypto_aead_chacha20poly1305_abytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt and authenticate with ChaCha20-Poly1305
function crypto_aead_chacha20poly1305_encrypt(const c: pansichar; clen: puint64; const m: pansichar; mlen: uint64; const ad: pansichar; adlen: uint64; const nsec: pansichar; const npub: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify then decrypt with ChaCha20-Poly1305
function crypto_aead_chacha20poly1305_decrypt(const m: pansichar; mlen: puint64; const nsec: pansichar; const c: pansichar; clen: uint64; const ad: pansichar; adlen: uint64; const npub: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the IETF ChaCha20-Poly1305 public nonce
function crypto_aead_chacha20poly1305_ietf_npubbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt and authenticate using IETF ChaCha20-Poly1305
function crypto_aead_chacha20poly1305_ietf_encrypt(const c: pansichar; clen: puint64; const m: pansichar; mlen: uint64; const ad: pansichar; adlen: uint64; const nsec: pansichar; const npub: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify then decrypt using IETF ChaCha20-Poly1305
function crypto_aead_chacha20poly1305_ietf_decrypt(const m: pansichar; mlen: puint64; const nsec: pansichar; const c: pansichar; clen: uint64; const ad: pansichar; adlen: uint64; const npub: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for IETF ChaCha20-Poly1305
function crypto_aead_chacha20poly1305_ietf_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for ChaCha20-Poly1305
function crypto_aead_chacha20poly1305_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using xchacha20poly1305 ietf
function crypto_aead_xchacha20poly1305_ietf_encrypt(c: pbyte; clen: size_t; m: pbyte; mlen: size_t; ad: pbyte; adlen: size_t; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using xchacha20poly1305 ietf
function crypto_aead_xchacha20poly1305_ietf_decrypt(m: pbyte; mlen: size_t; nsec: pbyte; c: pbyte; clen: size_t; ad: pbyte; adlen: size_t; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a key for xchacha20poly1305 ietf
function crypto_aead_xchacha20poly1305_ietf_keygen(k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an XChaCha20-Poly1305 key
function crypto_aead_xchacha20poly1305_ietf_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the optional secret nonce
function crypto_aead_xchacha20poly1305_ietf_nsecbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the public nonce
function crypto_aead_xchacha20poly1305_ietf_npubbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Bytes added by the authentication tag
function crypto_aead_xchacha20poly1305_ietf_abytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for this construction
function crypto_aead_xchacha20poly1305_ietf_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using xchacha20poly1305 ietf detached
function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c: pbyte; mac: pbyte; maclen_p: puint64; m: pbyte; mlen: size_t; ad: pbyte; adlen: size_t; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using xchacha20poly1305 ietf detached
function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m: pbyte; nsec: pbyte; c: pbyte; clen: size_t; mac: pbyte; ad: pbyte; adlen: size_t; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns 1 if AES-256-GCM is available at runtime
function crypto_aead_aes256gcm_is_available: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the AES-256-GCM key
function crypto_aead_aes256gcm_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the optional secret nonce
function crypto_aead_aes256gcm_nsecbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the public nonce
function crypto_aead_aes256gcm_npubbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Bytes added by the authentication tag
function crypto_aead_aes256gcm_abytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for this construction
function crypto_aead_aes256gcm_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the internal state
function crypto_aead_aes256gcm_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using AES-256-GCM
function crypto_aead_aes256gcm_encrypt(c: pbyte; clen_p: puint64; m: pbyte; mlen: uint64; ad: pbyte; adlen: uint64; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using AES-256-GCM
function crypto_aead_aes256gcm_decrypt(m: pbyte; mlen_p: puint64; nsec: pbyte; c: pbyte; clen: uint64; ad: pbyte; adlen: uint64; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using AES-256-GCM detached
function crypto_aead_aes256gcm_encrypt_detached(c: pbyte; mac: pbyte; maclen_p: puint64; m: pbyte; mlen: uint64; ad: pbyte; adlen: uint64; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using AES-256-GCM detached
function crypto_aead_aes256gcm_decrypt_detached(m: pbyte; nsec: pbyte; c: pbyte; clen: uint64; mac: pbyte; ad: pbyte; adlen: uint64; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initializes a reusable state
function crypto_aead_aes256gcm_beforenm(ctx: pcrypto_aead_aes256gcm_state; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using AES-256-GCM with a precomputed state
function crypto_aead_aes256gcm_encrypt_afternm(c: pbyte; clen_p: puint64; m: pbyte; mlen: uint64; ad: pbyte; adlen: uint64; nsec: pbyte; npub: pbyte; ctx: pcrypto_aead_aes256gcm_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using AES-256-GCM with a precomputed state
function crypto_aead_aes256gcm_decrypt_afternm(m: pbyte; mlen_p: puint64; nsec: pbyte; c: pbyte; clen: uint64; ad: pbyte; adlen: uint64; npub: pbyte; ctx: pcrypto_aead_aes256gcm_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using AES-256-GCM detached with a precomputed state
function crypto_aead_aes256gcm_encrypt_detached_afternm(c: pbyte; mac: pbyte; maclen_p: puint64; m: pbyte; mlen: uint64; ad: pbyte; adlen: uint64; nsec: pbyte; npub: pbyte; ctx: pcrypto_aead_aes256gcm_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using AES-256-GCM detached with a precomputed state
function crypto_aead_aes256gcm_decrypt_detached_afternm(m: pbyte; nsec: pbyte; c: pbyte; clen: uint64; mac: pbyte; ad: pbyte; adlen: uint64; npub: pbyte; ctx: pcrypto_aead_aes256gcm_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random AES-256-GCM key
procedure crypto_aead_aes256gcm_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the AEGIS-128L key
function crypto_aead_aegis128l_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the optional secret nonce
function crypto_aead_aegis128l_nsecbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the public nonce
function crypto_aead_aegis128l_npubbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Bytes added by the authentication tag
function crypto_aead_aegis128l_abytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for this construction
function crypto_aead_aegis128l_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using AEGIS-128L
function crypto_aead_aegis128l_encrypt(c: pbyte; clen_p: puint64; m: pbyte; mlen: uint64; ad: pbyte; adlen: uint64; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using AEGIS-128L
function crypto_aead_aegis128l_decrypt(m: pbyte; mlen_p: puint64; nsec: pbyte; c: pbyte; clen: uint64; ad: pbyte; adlen: uint64; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using AEGIS-128L detached
function crypto_aead_aegis128l_encrypt_detached(c: pbyte; mac: pbyte; maclen_p: puint64; m: pbyte; mlen: uint64; ad: pbyte; adlen: uint64; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using AEGIS-128L detached
function crypto_aead_aegis128l_decrypt_detached(m: pbyte; nsec: pbyte; c: pbyte; clen: uint64; mac: pbyte; ad: pbyte; adlen: uint64; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random AEGIS-128L key
procedure crypto_aead_aegis128l_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the AEGIS-256 key
function crypto_aead_aegis256_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the optional secret nonce
function crypto_aead_aegis256_nsecbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the public nonce
function crypto_aead_aegis256_npubbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Bytes added by the authentication tag
function crypto_aead_aegis256_abytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for this construction
function crypto_aead_aegis256_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using AEGIS-256
function crypto_aead_aegis256_encrypt(c: pbyte; clen_p: puint64; m: pbyte; mlen: uint64; ad: pbyte; adlen: uint64; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using AEGIS-256
function crypto_aead_aegis256_decrypt(m: pbyte; mlen_p: puint64; nsec: pbyte; c: pbyte; clen: uint64; ad: pbyte; adlen: uint64; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts data using AEGIS-256 detached
function crypto_aead_aegis256_encrypt_detached(c: pbyte; mac: pbyte; maclen_p: puint64; m: pbyte; mlen: uint64; ad: pbyte; adlen: uint64; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts data using AEGIS-256 detached
function crypto_aead_aegis256_decrypt_detached(m: pbyte; nsec: pbyte; c: pbyte; clen: uint64; mac: pbyte; ad: pbyte; adlen: uint64; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random AEGIS-256 key
procedure crypto_aead_aegis256_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};

{ AUTH }
// Length of a crypto_auth authentication tag
function crypto_auth_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a crypto_auth key
function crypto_auth_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the crypto_auth primitive in use
function crypto_auth_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify a message authentication code
function crypto_auth_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an HMAC-SHA-256 authentication tag
function crypto_auth_hmacsha256_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the HMAC-SHA-256 key
function crypto_auth_hmacsha256_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute an HMAC-SHA-256 tag
function crypto_auth_hmacsha256(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify an HMAC-SHA-256 tag
function crypto_auth_hmacsha256_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HMAC-SHA-256 state structure
function crypto_auth_hmacsha256_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize an HMAC-SHA-256 state
function crypto_auth_hmacsha256_init(state: pcrypto_auth_hmacsha256_state; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update the HMAC-SHA-256 state with data
function crypto_auth_hmacsha256_update(state: pcrypto_auth_hmacsha256_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalize the HMAC-SHA-256 computation
function crypto_auth_hmacsha256_final(state: pcrypto_auth_hmacsha256_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an HMAC-SHA-512 authentication tag
function crypto_auth_hmacsha512_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the HMAC-SHA-512 key
function crypto_auth_hmacsha512_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute an HMAC-SHA-512 tag
function crypto_auth_hmacsha512(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify an HMAC-SHA-512 tag
function crypto_auth_hmacsha512_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HMAC-SHA-512 state structure
function crypto_auth_hmacsha512_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize an HMAC-SHA-512 state
function crypto_auth_hmacsha512_init(state: pcrypto_auth_hmacsha512_state; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update the HMAC-SHA-512 state with data
function crypto_auth_hmacsha512_update(state: pcrypto_auth_hmacsha512_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalize the HMAC-SHA-512 computation
function crypto_auth_hmacsha512_final(state: pcrypto_auth_hmacsha512_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an HMAC-SHA-512/256 authentication tag
function crypto_auth_hmacsha512256_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the HMAC-SHA-512/256 key
function crypto_auth_hmacsha512256_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute an HMAC-SHA-512/256 tag
function crypto_auth_hmacsha512256(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify an HMAC-SHA-512/256 tag
function crypto_auth_hmacsha512256_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HMAC-SHA-512/256 state structure
function crypto_auth_hmacsha512256_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize an HMAC-SHA-512/256 state
function crypto_auth_hmacsha512256_init(state: pcrypto_auth_hmacsha512256_state; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update the HMAC-SHA-512/256 state with data
function crypto_auth_hmacsha512256_update(state: pcrypto_auth_hmacsha512256_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalize the HMAC-SHA-512/256 computation
function crypto_auth_hmacsha512256_final(state: pcrypto_auth_hmacsha512256_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a key pair for crypto_auth
function crypto_auth_keypair(pk, sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ BOX }
// Number of bytes in a crypto_box seed
function crypto_box_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a crypto_box public key
function crypto_box_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a crypto_box secret key
function crypto_box_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a crypto_box nonce
function crypto_box_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a crypto_box authentication tag
function crypto_box_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_box_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a key pair from a seed
function crypto_box_seed_keypair(const pk: pansichar; const sk: pansichar; const seed: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random key pair
function crypto_box_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt and authenticate a message
function crypto_box_easy(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify and decrypt a message
function crypto_box_open_easy(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt with detached authentication
function crypto_box_detached(const c: pansichar; const mac: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify and decrypt a detached message
function crypto_box_open_detached(const m: pansichar; const c: pansichar; const mac: pansichar; clen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the precomputed shared key
function crypto_box_beforenmbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Precompute a shared key
function crypto_box_beforenm(const k: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt using a precomputed key
function crypto_box_easy_afternm(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt using a precomputed key
function crypto_box_open_easy_afternm(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt with a precomputed key and detached tag
function crypto_box_detached_afternm(const c: pansichar; const mac: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt with a precomputed key and detached tag
function crypto_box_open_detached_afternm(const m: pansichar; const c: pansichar; const mac: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Overhead added by crypto_box_seal
function crypto_box_sealbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt a message for a recipient
function crypto_box_seal(const c: pansichar; const m: pansichar; mlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt a sealed message
function crypto_box_seal_open(const m: pansichar; const c: pansichar; clen: uint64; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Leading zeros required for crypto_box
function crypto_box_zerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Leading zeros added to ciphertext
function crypto_box_boxzerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify and decrypt a message
function crypto_box_open(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt using a precomputed shared key
function crypto_box_afternm(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt using a precomputed shared key
function crypto_box_open_afternm(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of bytes in a curve25519xsalsa20poly1305 seed
function crypto_box_curve25519xsalsa20poly1305_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the curve25519xsalsa20poly1305 public key in bytes
function crypto_box_curve25519xsalsa20poly1305_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the curve25519xsalsa20poly1305 secret key in bytes
function crypto_box_curve25519xsalsa20poly1305_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the precomputed shared key in bytes
function crypto_box_curve25519xsalsa20poly1305_beforenmbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the curve25519xsalsa20poly1305 nonce in bytes
function crypto_box_curve25519xsalsa20poly1305_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of leading zero bytes required before the message
function crypto_box_curve25519xsalsa20poly1305_zerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of zero bytes required before the plaintext
function crypto_box_curve25519xsalsa20poly1305_boxzerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the authentication tag in bytes
function crypto_box_curve25519xsalsa20poly1305_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt using curve25519xsalsa20poly1305
function crypto_box_curve25519xsalsa20poly1305(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt using curve25519xsalsa20poly1305
function crypto_box_curve25519xsalsa20poly1305_open(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a curve25519xsalsa20poly1305 key pair from a seed
function crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk: pbyte; sk: pbyte; const seed: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random curve25519xsalsa20poly1305 key pair
function crypto_box_curve25519xsalsa20poly1305_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Precomputes a shared key for curve25519xsalsa20poly1305
function crypto_box_curve25519xsalsa20poly1305_beforenm(const k: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt using a precomputed key for curve25519xsalsa20poly1305
function crypto_box_curve25519xsalsa20poly1305_afternm(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt using a precomputed key for curve25519xsalsa20poly1305
function crypto_box_curve25519xsalsa20poly1305_open_afternm(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of bytes in a curve25519xchacha20poly1305 seed
function crypto_box_curve25519xchacha20poly1305_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the curve25519xchacha20poly1305 public key in bytes
function crypto_box_curve25519xchacha20poly1305_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the curve25519xchacha20poly1305 secret key in bytes
function crypto_box_curve25519xchacha20poly1305_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the precomputed shared key
function crypto_box_curve25519xchacha20poly1305_beforenmbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the curve25519xchacha20poly1305 nonce
function crypto_box_curve25519xchacha20poly1305_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the authentication tag in bytes
function crypto_box_curve25519xchacha20poly1305_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message size that can be encrypted
function crypto_box_curve25519xchacha20poly1305_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a key pair from a seed
function crypto_box_curve25519xchacha20poly1305_seed_keypair(pk: pbyte; sk: pbyte; const seed: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random curve25519xchacha20poly1305 key pair
function crypto_box_curve25519xchacha20poly1305_keypair(pk: pbyte; sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt and authenticate a message
function crypto_box_curve25519xchacha20poly1305_easy(c: pbyte; const m: pbyte; mlen: uint64; const n: pbyte; const pk: pbyte; const sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify and decrypt a message
function crypto_box_curve25519xchacha20poly1305_open_easy(m: pbyte; const c: pbyte; clen: uint64; const n: pbyte; const pk: pbyte; const sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt with detached authentication tag
function crypto_box_curve25519xchacha20poly1305_detached(c: pbyte; mac: pbyte; const m: pbyte; mlen: uint64; const n: pbyte; const pk: pbyte; const sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt a message with a detached tag
function crypto_box_curve25519xchacha20poly1305_open_detached(m: pbyte; const c: pbyte; const mac: pbyte; clen: uint64; const n: pbyte; const pk: pbyte; const sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Precompute a shared key
function crypto_box_curve25519xchacha20poly1305_beforenm(k: pbyte; const pk: pbyte; const sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt using a precomputed key
function crypto_box_curve25519xchacha20poly1305_easy_afternm(c: pbyte; const m: pbyte; mlen: uint64; const n: pbyte; const k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt using a precomputed key
function crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m: pbyte; const c: pbyte; clen: uint64; const n: pbyte; const k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt with a precomputed key and detached tag
function crypto_box_curve25519xchacha20poly1305_detached_afternm(c: pbyte; mac: pbyte; const m: pbyte; mlen: uint64; const n: pbyte; const k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt with a precomputed key and detached tag
function crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m: pbyte; const c: pbyte; const mac: pbyte; clen: uint64; const n: pbyte; const k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Overhead added by crypto_box_seal
function crypto_box_curve25519xchacha20poly1305_sealbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt a message for a recipient
function crypto_box_curve25519xchacha20poly1305_seal(c: pbyte; const m: pbyte; mlen: uint64; const pk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt a sealed message
function crypto_box_curve25519xchacha20poly1305_seal_open(m: pbyte; const c: pbyte; clen: uint64; const pk: pbyte; const sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ CORE }
// Size of the HSalsa20 output in bytes
function crypto_core_hsalsa20_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HSalsa20 input in bytes
function crypto_core_hsalsa20_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the hsalsa20 key
function crypto_core_hsalsa20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HSalsa20 constant in bytes
function crypto_core_hsalsa20_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Core HSalsa20 operation
function crypto_core_hsalsa20(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HChaCha20 output in bytes
function crypto_core_hchacha20_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HChaCha20 input in bytes
function crypto_core_hchacha20_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the HChaCha20 key
function crypto_core_hchacha20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HChaCha20 constant in bytes
function crypto_core_hchacha20_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Core HChaCha20 operation
function crypto_core_hchacha20(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa20 output in bytes
function crypto_core_salsa20_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa20 input in bytes
function crypto_core_salsa20_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the salsa20 key
function crypto_core_salsa20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa20 constant in bytes
function crypto_core_salsa20_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Core Salsa20 operation
function crypto_core_salsa20(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa2012 output in bytes
function crypto_core_salsa2012_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa2012 input in bytes
function crypto_core_salsa2012_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the salsa2012 key
function crypto_core_salsa2012_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa2012 constant in bytes
function crypto_core_salsa2012_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Core Salsa2012 operation
function crypto_core_salsa2012(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa208 output in bytes
function crypto_core_salsa208_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa208 input in bytes
function crypto_core_salsa208_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the salsa208 key
function crypto_core_salsa208_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the Salsa208 constant in bytes
function crypto_core_salsa208_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Core Salsa208 operation
function crypto_core_salsa208(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of an ed25519 point in bytes
function crypto_core_ed25519_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of a uniform ed25519 point representation
function crypto_core_ed25519_uniformbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ed25519 hash output
function crypto_core_ed25519_hashbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of an ed25519 scalar
function crypto_core_ed25519_scalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of an ed25519 non-reduced scalar
function crypto_core_ed25519_nonreducedscalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Validate that a point lies on the ed25519 curve
function crypto_core_ed25519_is_valid_point(const p: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Add two ed25519 points
function crypto_core_ed25519_add(r: pbyte; const p: pbyte; const q: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Subtract two ed25519 points
function crypto_core_ed25519_sub(r: pbyte; const p: pbyte; const q: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Map 32 uniform random bytes to a point
function crypto_core_ed25519_from_uniform(p: pbyte; const r: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Map 64 bytes of hash output to a point
function crypto_core_ed25519_from_hash(p: pbyte; const h: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random point on ed25519
procedure crypto_core_ed25519_random(p: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random ed25519 scalar
procedure crypto_core_ed25519_scalar_random(r: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute the multiplicative inverse of a scalar
function crypto_core_ed25519_scalar_invert(recip: pbyte; const s: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Negate a scalar modulo the group order
procedure crypto_core_ed25519_scalar_negate(neg: pbyte; const s: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute the complement of a scalar
procedure crypto_core_ed25519_scalar_complement(comp: pbyte; const s: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Add two scalars modulo the group order
procedure crypto_core_ed25519_scalar_add(z: pbyte; const x: pbyte; const y: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Subtract two scalars modulo the group order
procedure crypto_core_ed25519_scalar_sub(z: pbyte; const x: pbyte; const y: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Multiply two scalars modulo the group order
procedure crypto_core_ed25519_scalar_mul(z: pbyte; const x: pbyte; const y: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Reduce a 64-byte scalar modulo the group order
procedure crypto_core_ed25519_scalar_reduce(r: pbyte; const s: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of a ristretto255 point in bytes
function crypto_core_ristretto255_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ristretto255 hash output
function crypto_core_ristretto255_hashbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of a ristretto255 scalar
function crypto_core_ristretto255_scalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of a ristretto255 non-reduced scalar
function crypto_core_ristretto255_nonreducedscalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Validate that a point lies on the ristretto255 curve
function crypto_core_ristretto255_is_valid_point(const p: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Add two ristretto255 points
function crypto_core_ristretto255_add(r: pbyte; const p: pbyte; const q: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Subtract two ristretto255 points
function crypto_core_ristretto255_sub(r: pbyte; const p: pbyte; const q: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Map 64 bytes of hash output to a ristretto255 point
function crypto_core_ristretto255_from_hash(p: pbyte; const r: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random ristretto255 point
procedure crypto_core_ristretto255_random(p: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random ristretto255 scalar
procedure crypto_core_ristretto255_scalar_random(r: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute the multiplicative inverse of a ristretto255 scalar
function crypto_core_ristretto255_scalar_invert(recip: pbyte; const s: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Negate a ristretto255 scalar
procedure crypto_core_ristretto255_scalar_negate(neg: pbyte; const s: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute the complement of a ristretto255 scalar
procedure crypto_core_ristretto255_scalar_complement(comp: pbyte; const s: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Add two ristretto255 scalars
procedure crypto_core_ristretto255_scalar_add(z: pbyte; const x: pbyte; const y: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Subtract two ristretto255 scalars
procedure crypto_core_ristretto255_scalar_sub(z: pbyte; const x: pbyte; const y: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Multiply two ristretto255 scalars
procedure crypto_core_ristretto255_scalar_mul(z: pbyte; const x: pbyte; const y: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Reduce a 64-byte scalar modulo the ristretto255 group order
procedure crypto_core_ristretto255_scalar_reduce(r: pbyte; const s: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};

{ GENERICHASH }
// Minimum digest size in bytes
function crypto_generichash_bytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum digest size in bytes
function crypto_generichash_bytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Default digest size in bytes
function crypto_generichash_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum key size in bytes
function crypto_generichash_keybytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum key size in bytes
function crypto_generichash_keybytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the key in bytes
function crypto_generichash_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_generichash_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the state structure in bytes
function crypto_generichash_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize a crypto_generichash state
function crypto_generichash_init(state: pcrypto_generichash_state; const key: pansichar; const keylen: size_t; const outlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update the crypto_generichash state with data
function crypto_generichash_update(state: pcrypto_generichash_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalize the crypto_generichash state and produce the hash
function crypto_generichash_final(state: pcrypto_generichash_state; const outbuf: pansichar; const outlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum BLAKE2b digest size in bytes
function crypto_generichash_blake2b_bytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum BLAKE2b digest size in bytes
function crypto_generichash_blake2b_bytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Default BLAKE2b digest size in bytes
function crypto_generichash_blake2b_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum blake2b key size in bytes
function crypto_generichash_blake2b_keybytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum blake2b key size in bytes
function crypto_generichash_blake2b_keybytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the blake2b key
function crypto_generichash_blake2b_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the blake2b salt in bytes
function crypto_generichash_blake2b_saltbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the blake2b personal string in bytes
function crypto_generichash_blake2b_personalbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// blake2b hashing operation
function crypto_generichash_blake2b(const outbuf: pansichar; outlen: size_t; const inbuf: pansichar; inlen: uint64; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// blake2b hashing with custom salt and personal string
function crypto_generichash_blake2b_salt_personal(const outbuf: pansichar; outlen: size_t; const inbuf: pansichar; inlen: uint64; const key: pansichar; keylen: size_t; const salt: pansichar; const personal: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initializes blake2b state
function crypto_generichash_blake2b_init(state: pcrypto_generichash_blake2b_state; const key: pansichar; const keylen: size_t; const outlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initializes blake2b salt personal state
function crypto_generichash_blake2b_init_salt_personal(state: pcrypto_generichash_blake2b_state; const key: pansichar; const keylen: size_t; const outlen: size_t; const salt: pansichar; const personal: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Updates blake2b state
function crypto_generichash_blake2b_update(state: pcrypto_generichash_blake2b_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalizes blake2b state
function crypto_generichash_blake2b_final(state: pcrypto_generichash_blake2b_state; const outbuf: pansichar; const outlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ HASH }
// Digest size in bytes
function crypto_hash_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_hash_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the SHA-256 state in bytes
function crypto_hash_sha256_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// SHA-256 digest size in bytes
function crypto_hash_sha256_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute a SHA-256 hash
function crypto_hash_sha256(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initializes sha256 state
function crypto_hash_sha256_init(state: pcrypto_hash_sha256_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Updates sha256 state
function crypto_hash_sha256_update(state: pcrypto_hash_sha256_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalizes sha256 state
function crypto_hash_sha256_final(state: pcrypto_hash_sha256_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the SHA-512 state in bytes
function crypto_hash_sha512_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// SHA-512 digest size in bytes
function crypto_hash_sha512_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compute a SHA-512 hash
function crypto_hash_sha512(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initializes sha512 state
function crypto_hash_sha512_init(state: pcrypto_hash_sha512_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Updates sha512 state
function crypto_hash_sha512_update(state: pcrypto_hash_sha512_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalizes sha512 state
function crypto_hash_sha512_final(state: pcrypto_hash_sha512_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ KDF }
// Minimum derived key size in bytes
function crypto_kdf_bytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum derived key size in bytes
function crypto_kdf_bytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a crypto_kdf context string
function crypto_kdf_contextbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the key in bytes
function crypto_kdf_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_kdf_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Derive a subkey from a master key
function crypto_kdf_derive_from_key(subkey: pbyte; subkey_len: size_t; subkey_id: uint64; const ctx: pansichar; const key: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random master key
procedure crypto_kdf_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the HKDF-SHA-256 key
function crypto_kdf_hkdf_sha256_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum derived key size for HKDF-SHA-256
function crypto_kdf_hkdf_sha256_bytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum derived key size for HKDF-SHA-256
function crypto_kdf_hkdf_sha256_bytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Extract stage of HKDF-SHA-256
function crypto_kdf_hkdf_sha256_extract(prk: pbyte; const salt: pbyte; salt_len: size_t; const ikm: pbyte; ikm_len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random HKDF-SHA-256 key
procedure crypto_kdf_hkdf_sha256_keygen(prk: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Expand stage of HKDF-SHA-256
function crypto_kdf_hkdf_sha256_expand(out_: pbyte; out_len: size_t; const ctx: pansichar; ctx_len: size_t; const prk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HKDF-SHA-256 streaming state
function crypto_kdf_hkdf_sha256_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize HKDF-SHA-256 extract state
function crypto_kdf_hkdf_sha256_extract_init(state: pcrypto_kdf_hkdf_sha256_state; const salt: pbyte; salt_len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update HKDF-SHA-256 extract state
function crypto_kdf_hkdf_sha256_extract_update(state: pcrypto_kdf_hkdf_sha256_state; const ikm: pbyte; ikm_len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalize HKDF-SHA-256 extract stage
function crypto_kdf_hkdf_sha256_extract_final(state: pcrypto_kdf_hkdf_sha256_state; prk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the HKDF-SHA-512 key
function crypto_kdf_hkdf_sha512_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum derived key size for HKDF-SHA-512
function crypto_kdf_hkdf_sha512_bytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum derived key size for HKDF-SHA-512
function crypto_kdf_hkdf_sha512_bytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Extract stage of HKDF-SHA-512
function crypto_kdf_hkdf_sha512_extract(prk: pbyte; const salt: pbyte; salt_len: size_t; const ikm: pbyte; ikm_len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a random HKDF-SHA-512 key
procedure crypto_kdf_hkdf_sha512_keygen(prk: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Expand stage of HKDF-SHA-512
function crypto_kdf_hkdf_sha512_expand(out_: pbyte; out_len: size_t; const ctx: pansichar; ctx_len: size_t; const prk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the HKDF-SHA-512 streaming state
function crypto_kdf_hkdf_sha512_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize HKDF-SHA-512 extract state
function crypto_kdf_hkdf_sha512_extract_init(state: pcrypto_kdf_hkdf_sha512_state; const salt: pbyte; salt_len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update HKDF-SHA-512 extract state
function crypto_kdf_hkdf_sha512_extract_update(state: pcrypto_kdf_hkdf_sha512_state; const ikm: pbyte; ikm_len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalize HKDF-SHA-512 extract stage
function crypto_kdf_hkdf_sha512_extract_final(state: pcrypto_kdf_hkdf_sha512_state; prk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ KX }
// Size of the public key in bytes
function crypto_kx_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the secret key in bytes
function crypto_kx_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of seed bytes for key exchange
function crypto_kx_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of a session key in bytes
function crypto_kx_sessionkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_kx_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a key pair for seed
function crypto_kx_seed_keypair(pk: pbyte; sk: pbyte; const seed: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a key pair for
function crypto_kx_keypair(pk: pbyte; sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Derive client-side session keys
function crypto_kx_client_session_keys(rx: pbyte; tx: pbyte; const client_pk: pbyte; const client_sk: pbyte; const server_pk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Derive server-side session keys
function crypto_kx_server_session_keys(rx: pbyte; tx: pbyte; const server_pk: pbyte; const server_sk: pbyte; const client_pk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ ONETIMEAUTH }
// Size of the state structure in bytes
function crypto_onetimeauth_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Authenticator size in bytes
function crypto_onetimeauth_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the key in bytes
function crypto_onetimeauth_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_onetimeauth_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify a one-time authentication tag
function crypto_onetimeauth_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize a crypto_onetimeauth state
function crypto_onetimeauth_init(state: pcrypto_onetimeauth_state; const key: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update the crypto_onetimeauth state with data
function crypto_onetimeauth_update(state: pcrypto_onetimeauth_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalize the crypto_onetimeauth state and produce the tag
function crypto_onetimeauth_final(state: pcrypto_onetimeauth_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Poly1305 authenticator size in bytes
function crypto_onetimeauth_poly1305_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the poly1305 key
function crypto_onetimeauth_poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Computes a Poly1305 authenticator
function crypto_onetimeauth_poly1305(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify a Poly1305 authenticator
function crypto_onetimeauth_poly1305_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initializes poly1305 state
function crypto_onetimeauth_poly1305_init(state: pcrypto_onetimeauth_poly1305_state; const key: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Updates poly1305 state
function crypto_onetimeauth_poly1305_update(state: pcrypto_onetimeauth_poly1305_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalizes poly1305 state
function crypto_onetimeauth_poly1305_final(state: pcrypto_onetimeauth_poly1305_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ PWHASH }
// Size of the scryptsalsa208sha256 salt in bytes
function crypto_pwhash_scryptsalsa208sha256_saltbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the scryptsalsa208sha256 encoded string
function crypto_pwhash_scryptsalsa208sha256_strbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Prefix used for scryptsalsa208sha256 hashes
function crypto_pwhash_scryptsalsa208sha256_strprefix: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Interactive opslimit for scryptsalsa208sha256
function crypto_pwhash_scryptsalsa208sha256_opslimit_interactive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Interactive memory limit for scryptsalsa208sha256
function crypto_pwhash_scryptsalsa208sha256_memlimit_interactive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Sensitive opslimit for scryptsalsa208sha256
function crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Sensitive memory limit for scryptsalsa208sha256
function crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Derives a key using scryptsalsa208sha256
function crypto_pwhash_scryptsalsa208sha256(const outbuf: pansichar; outlen: uint64; const passwd: pansichar; passwdlen: uint64; const salt: pansichar; opslimit: uint64; memlimit: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Derives a key using scryptsalsa208sha256
function crypto_pwhash_scryptsalsa208sha256_str(outbuf: pansichar; const passwd: pansichar; passwdlen: uint64; opslimit: uint64; memlimit: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify a scryptsalsa208sha256 hash string
function crypto_pwhash_scryptsalsa208sha256_str_verify(const str: pansichar; const passwd: pansichar; passwdlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Low-level key derivation using scryptsalsa208sha256
function crypto_pwhash_scryptsalsa208sha256_ll(const passwd: puint8; passwdlen: size_t; const salt: puint8; saltlen: size_t; n: uint64; r: uint32; p: uint32; buf: puint8; buflen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Identifier for the Argon2i algorithm
function crypto_pwhash_alg_argon2i13: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Identifier for the Argon2id algorithm
function crypto_pwhash_alg_argon2id13: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Identifier of the default algorithm
function crypto_pwhash_alg_default: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum output length for crypto_pwhash
function crypto_pwhash_bytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum output length for crypto_pwhash
function crypto_pwhash_bytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum password length
function crypto_pwhash_passwd_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum password length
function crypto_pwhash_passwd_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the password hashing salt
function crypto_pwhash_saltbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the encoded hash string
function crypto_pwhash_strbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Prefix for encoded password hashes
function crypto_pwhash_strprefix: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum operations limit
function crypto_pwhash_opslimit_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum operations limit
function crypto_pwhash_opslimit_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Minimum memory limit
function crypto_pwhash_memlimit_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum memory limit
function crypto_pwhash_memlimit_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Operations limit for interactive use
function crypto_pwhash_opslimit_interactive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Memory limit for interactive use
function crypto_pwhash_memlimit_interactive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Operations limit for moderate use
function crypto_pwhash_opslimit_moderate: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Memory limit for moderate use
function crypto_pwhash_memlimit_moderate: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Operations limit for sensitive data
function crypto_pwhash_opslimit_sensitive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Memory limit for sensitive data
function crypto_pwhash_memlimit_sensitive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Derives a key from a password using the given parameters
function crypto_pwhash(out_: pbyte; outlen: uint64; const passwd: pansichar; passwdlen: uint64; const salt: pbyte; opslimit: uint64; memlimit: size_t; alg: integer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Hashes a password and stores the result as an encoded string
function crypto_pwhash_str(out_: pansichar; const passwd: pansichar; passwdlen: uint64; opslimit: uint64; memlimit: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Hash a password using the specified algorithm
function crypto_pwhash_str_alg(out_: pansichar; const passwd: pansichar; passwdlen: uint64; opslimit: uint64; memlimit: size_t; alg: integer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify an encoded password hash
function crypto_pwhash_str_verify(const str: pansichar; const passwd: pansichar; passwdlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks if a stored hash needs to be recalculated with stronger parameters
function crypto_pwhash_str_needs_rehash(const str: pansichar; opslimit: uint64; memlimit: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_pwhash_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ RANDOMBYTES }
// Fills a buffer with random bytes
procedure randombytes_buf(const buf: pointer; const size: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Fills a buffer with deterministic random bytes
procedure randombytes_buf_deterministic(const buf: pointer; const size: size_t; const seed: pansichar) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the seed for deterministic random bytes
function randombytes_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns a random 32-bit value
function randombytes_random: uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns a uniform random number below the bound
function randombytes_uniform(const upper_bound: uint32): uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
// Reseeds the random number generator
procedure randombytes_stir; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Closes the random number generator
function randombytes_close: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns the implementation name
function randombytes_implementation_name: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Set a custom randombytes implementation
function randombytes_set_implementation(impl: prandombytes_implementation): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns the implementation name
function randombytes_salsa20_implementation_name: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns a random 32-bit value
function randombytes_salsa20_random: uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns a random 32-bit value
procedure randombytes_salsa20_random_stir; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns a random 32-bit value
function randombytes_salsa20_random_uniform(const upper_bound: uint32): uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns a random 32-bit value
procedure randombytes_salsa20_random_buf(const buf: pointer; const size: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Closes the random number generator
function randombytes_salsa20_random_close: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns the implementation name
function randombytes_sysrandom_implementation_name: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Return a 32-bit random value using the system RNG
function randombytes_sysrandom: uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
// Reseeds the random number generator
procedure randombytes_sysrandom_stir; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns a uniform random number below the bound
function randombytes_sysrandom_uniform(const upper_bound: uint32): uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
// Fills a buffer with random bytes
procedure randombytes_sysrandom_buf(const buf: pointer; const size: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Closes the random number generator
function randombytes_sysrandom_close: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ SCALARMULT }
// Group element size in bytes
function crypto_scalarmult_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the scalar used in scalar multiplication
function crypto_scalarmult_scalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_scalarmult_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Multiplies the base point by a scalar
function crypto_scalarmult_base(const q: pansichar; const n: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Curve25519 group element size in bytes
function crypto_scalarmult_curve25519_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the curve25519 scalar in bytes
function crypto_scalarmult_curve25519_scalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Performs scalar multiplication on curve25519
function crypto_scalarmult_curve25519(const q: pansichar; const n: pansichar; const p: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Multiplies the curve25519 base point
function crypto_scalarmult_curve25519_base(const q: pansichar; const n: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ed25519 group element
function crypto_scalarmult_ed25519_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ed25519 scalar
function crypto_scalarmult_ed25519_scalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Perform scalar multiplication on ed25519
function crypto_scalarmult_ed25519(q: pbyte; const n: pbyte; const p: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Scalar multiplication without clamping the scalar
function crypto_scalarmult_ed25519_noclamp(q: pbyte; const n: pbyte; const p: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Multiply the base point by a scalar
function crypto_scalarmult_ed25519_base(q: pbyte; const n: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Multiply the base point by a scalar without clamping
function crypto_scalarmult_ed25519_base_noclamp(q: pbyte; const n: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ristretto255 group element
function crypto_scalarmult_ristretto255_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ristretto255 scalar
function crypto_scalarmult_ristretto255_scalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Perform scalar multiplication on ristretto255
function crypto_scalarmult_ristretto255(q: pbyte; const n: pbyte; const p: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Multiply the ristretto255 base point
function crypto_scalarmult_ristretto255_base(q: pbyte; const n: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ SECRETBOX }
// Size of the key in bytes
function crypto_secretbox_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the crypto_secretbox nonce in bytes
function crypto_secretbox_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the crypto_secretbox MAC in bytes
function crypto_secretbox_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_secretbox_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts and authenticates a message
function crypto_secretbox_easy(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts and authenticates a message
function crypto_secretbox_open_easy(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts a message and outputs a separate MAC
function crypto_secretbox_detached(const c: pansichar; const mac: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypts a message using a separate MAC
function crypto_secretbox_open_detached(const m: pansichar; const c: pansichar; const mac: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of leading zero bytes required before the message
function crypto_secretbox_zerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of zero bytes required before the ciphertext
function crypto_secretbox_boxzerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verifies and decrypts a message encrypted with crypto_secretbox
function crypto_secretbox_open(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the xsalsa20poly1305 key
function crypto_secretbox_xsalsa20poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the XSalsa20-Poly1305 nonce in bytes
function crypto_secretbox_xsalsa20poly1305_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of leading zero bytes required before the message
function crypto_secretbox_xsalsa20poly1305_zerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of zero bytes required before the ciphertext
function crypto_secretbox_xsalsa20poly1305_boxzerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the XSalsa20-Poly1305 MAC in bytes
function crypto_secretbox_xsalsa20poly1305_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts and authenticates a message using XSalsa20-Poly1305
function crypto_secretbox_xsalsa20poly1305(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts and authenticates a message using XSalsa20-Poly1305
function crypto_secretbox_xsalsa20poly1305_open(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the xchacha20poly1305 key
function crypto_secretbox_xchacha20poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an XChaCha20-Poly1305 nonce
function crypto_secretbox_xchacha20poly1305_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the XChaCha20-Poly1305 MAC
function crypto_secretbox_xchacha20poly1305_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for XChaCha20-Poly1305
function crypto_secretbox_xchacha20poly1305_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt and authenticate a message
function crypto_secretbox_xchacha20poly1305_easy(c: pbyte; m: pbyte; mlen: size_t; n: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt and verify a message
function crypto_secretbox_xchacha20poly1305_open_easy(m: pbyte; c: pbyte; clen: size_t; n: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt a message and store the MAC separately
function crypto_secretbox_xchacha20poly1305_detached(c: pbyte; mac: pbyte; m: pbyte; mlen: size_t; n: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt a message using a detached MAC
function crypto_secretbox_xchacha20poly1305_open_detached(m: pbyte; c: pbyte; mac: pbyte; clen: size_t; n: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ SECRETSTREAM }
// Bytes added by an xchacha20poly1305 authentication tag
function crypto_secretstream_xchacha20poly1305_abytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an xchacha20poly1305 header
function crypto_secretstream_xchacha20poly1305_headerbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the xchacha20poly1305 key
function crypto_secretstream_xchacha20poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum chunk size for secret streams
function crypto_secretstream_xchacha20poly1305_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Tag value for a regular message
function crypto_secretstream_xchacha20poly1305_tag_message: byte cdecl; external {$ifndef STATICLINK}lib{$endif};
// Tag value to request pushing a message
function crypto_secretstream_xchacha20poly1305_tag_push: byte cdecl; external {$ifndef STATICLINK}lib{$endif};
// Tag value to rotate the stream key
function crypto_secretstream_xchacha20poly1305_tag_rekey: byte cdecl; external {$ifndef STATICLINK}lib{$endif};
// Tag value marking the final chunk
function crypto_secretstream_xchacha20poly1305_tag_final: byte cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the secret stream state structure
function crypto_secretstream_xchacha20poly1305_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a key for xchacha20poly1305
procedure crypto_secretstream_xchacha20poly1305_keygen(const k: pansichar) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initializes xchacha20poly1305 push state
function crypto_secretstream_xchacha20poly1305_init_push(state: pcrypto_secretstream_xchacha20poly1305_state; header: pansichar; k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt a chunk for a secret stream
function crypto_secretstream_xchacha20poly1305_push(state: pcrypto_secretstream_xchacha20poly1305_state; c: pansichar; clen_p: puint64; const m: pansichar; mlen: uint64; const ad: pansichar; adlen: uint64; tag: byte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initializes xchacha20poly1305 pull state
function crypto_secretstream_xchacha20poly1305_init_pull(state: pcrypto_secretstream_xchacha20poly1305_state; header: pansichar; k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Decrypt a chunk from a secret stream
function crypto_secretstream_xchacha20poly1305_pull(state: pcrypto_secretstream_xchacha20poly1305_state; m: pansichar; mlen_p: puint64; tag_p: pansichar; const c: pansichar; clen: uint64; const ad: pansichar; adlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Rotate the key of an existing secret stream
procedure crypto_secretstream_xchacha20poly1305_rekey(state: pcrypto_secretstream_xchacha20poly1305_state) cdecl; external {$ifndef STATICLINK}lib{$endif};

{ SHORTHASH }
// Hash output size in bytes
function crypto_shorthash_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the key in bytes
function crypto_shorthash_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_shorthash_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// SipHash-2-4 output size in bytes
function crypto_shorthash_siphash24_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the siphash24 key
function crypto_shorthash_siphash24_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Computes a SipHash-2-4 message authenticator
function crypto_shorthash_siphash24(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Finalize a crypto_shorthash state
function crypto_shorthash_final(out_: pbyte; sh: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// SipHash-x-2-4 output size in bytes
function crypto_shorthash_siphashx24_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the siphashx24 key
function crypto_shorthash_siphashx24_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Computes a SipHash-x-2-4 message authenticator
function crypto_shorthash_siphashx24(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ SIGN }
// Maximum signature size in bytes
function crypto_sign_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of bytes in a signing seed
function crypto_sign_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the signing public key in bytes
function crypto_sign_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the signing secret key in bytes
function crypto_sign_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_sign_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a signing key pair from a seed
function crypto_sign_seed_keypair(const pk: pansichar; const sk: pansichar; const seed: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a new signing key pair
function crypto_sign_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verifies a signed message and retrieves its contents
function crypto_sign_open(const m: pansichar; mlen_p: puint64; const sm: pansichar; smlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Sign a message and return a detached signature
function crypto_sign_detached(const sig: pansichar; siglen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify a detached signature
function crypto_sign_verify_detached(const sig: pansichar; const m: pansichar; mlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the incremental signing state structure
function crypto_sign_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize an incremental signing state
function crypto_sign_init(state: pcrypto_sign_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update the signing state with more data
function crypto_sign_update(state: pcrypto_sign_state; const m: pansichar; mlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Produce a signature using the accumulated state
function crypto_sign_final_create(state: pcrypto_sign_state; sig: pansichar; siglen_p: puint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify a signature using the accumulated state
function crypto_sign_final_verify(state: pcrypto_sign_state; const sig: pansichar; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Ed25519 signature size in bytes
function crypto_sign_ed25519_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Number of ed25519 seed bytes
function crypto_sign_ed25519_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ed25519 public key in bytes
function crypto_sign_ed25519_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ed25519 secret key in bytes
function crypto_sign_ed25519_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Creates an ed25519 signature
function crypto_sign_ed25519(const sm: pansichar; smlen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Creates an ed25519 signature
function crypto_sign_ed25519_open(const m: pansichar; mlen_p: puint64; const sm: pansichar; smlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Creates a detached ed25519 signature
function crypto_sign_ed25519_detached(const sig: pansichar; siglen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verifies a signature for ed25519 detached
function crypto_sign_ed25519_verify_detached(const sig: pansichar; const m: pansichar; mlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a key pair for ed25519
function crypto_sign_ed25519_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a key pair for ed25519 seed
function crypto_sign_ed25519_seed_keypair(const pk: pansichar; const sk: pansichar; const seed: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Converts an ed25519 public key to a curve25519 key
function crypto_sign_ed25519_pk_to_curve25519(const curve25519_pk: pansichar; const ed25519_pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Converts an ed25519 secret key to a curve25519 key
function crypto_sign_ed25519_sk_to_curve25519(const curve25519_sk: pansichar; const ed25519_sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Extracts the seed from an ed25519 secret key
function crypto_sign_ed25519_sk_to_seed(const seed: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Derives the public key from an ed25519 secret key
function crypto_sign_ed25519_sk_to_pk(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Size of the ed25519ph state structure
function crypto_sign_ed25519ph_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize an ed25519ph signing state
function crypto_sign_ed25519ph_init(state: pcrypto_sign_ed25519ph_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Update the ed25519ph state with data
function crypto_sign_ed25519ph_update(state: pcrypto_sign_ed25519ph_state; const m: pansichar; mlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Create a detached signature using ed25519ph
function crypto_sign_ed25519ph_final_create(state: pcrypto_sign_ed25519ph_state; sig: pansichar; siglen_p: puint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify a detached ed25519ph signature
function crypto_sign_ed25519ph_final_verify(state: pcrypto_sign_ed25519ph_state; const sig: pansichar; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Edwards25519-SHA512batch signature size in bytes
function crypto_sign_edwards25519sha512batch_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the edwards25519sha512batch public key
function crypto_sign_edwards25519sha512batch_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the edwards25519sha512batch secret key
function crypto_sign_edwards25519sha512batch_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Sign a message using edwards25519sha512batch
function crypto_sign_edwards25519sha512batch(const sm: pansichar; smlen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Verify an edwards25519sha512batch signature
function crypto_sign_edwards25519sha512batch_open(const m: pansichar; mlen_p: puint64; const sm: pansichar; smlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a key pair for edwards25519sha512batch
function crypto_sign_edwards25519sha512batch_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ STREAM }
// Size of the key in bytes
function crypto_stream_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the crypto_secretbox nonce in bytes
function crypto_stream_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Name of the primitive in use
function crypto_stream_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with a pseudorandom stream
function crypto_stream_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the chacha20 key
function crypto_stream_chacha20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a ChaCha20 nonce
function crypto_stream_chacha20_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate a ChaCha20 keystream
function crypto_stream_chacha20(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with a ChaCha20 stream
function crypto_stream_chacha20_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with a ChaCha20 stream starting at a given block
function crypto_stream_chacha20_xor_ic(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; ic: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for ChaCha20
function crypto_stream_chacha20_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random key for ChaCha20
procedure crypto_stream_chacha20_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an IETF ChaCha20 nonce
function crypto_stream_chacha20_ietf_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate an IETF ChaCha20 keystream
function crypto_stream_chacha20_ietf(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR using the IETF ChaCha20 variant
function crypto_stream_chacha20_ietf_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR using the IETF ChaCha20 variant starting at a block counter
function crypto_stream_chacha20_ietf_xor_ic(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; ic: uint32; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an IETF ChaCha20 key
function crypto_stream_chacha20_ietf_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for IETF ChaCha20
function crypto_stream_chacha20_ietf_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random key for IETF ChaCha20
procedure crypto_stream_chacha20_ietf_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the salsa20 key
function crypto_stream_salsa20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a Salsa20 nonce
function crypto_stream_salsa20_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Core Salsa20 operation
function crypto_stream_salsa20(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with a Salsa20 stream
function crypto_stream_salsa20_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with a Salsa20 stream starting at a given block
function crypto_stream_salsa20_xor_ic(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; ic: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for Salsa20
function crypto_stream_salsa20_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random key for Salsa20
procedure crypto_stream_salsa20_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the salsa2012 key
function crypto_stream_salsa2012_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a Salsa2012 nonce
function crypto_stream_salsa2012_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Core Salsa2012 operation
function crypto_stream_salsa2012(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with a Salsa2012 stream
function crypto_stream_salsa2012_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for Salsa2012
function crypto_stream_salsa2012_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random key for Salsa2012
procedure crypto_stream_salsa2012_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the salsa208 key
function crypto_stream_salsa208_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of a Salsa208 nonce
function crypto_stream_salsa208_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for Salsa208
function crypto_stream_salsa208_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Core Salsa208 operation
function crypto_stream_salsa208(c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with a Salsa208 stream
function crypto_stream_salsa208_xor(c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random key for Salsa208
procedure crypto_stream_salsa208_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the xsalsa20 key
function crypto_stream_xsalsa20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an XSalsa20 nonce
function crypto_stream_xsalsa20_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate an XSalsa20 keystream
function crypto_stream_xsalsa20(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with an XSalsa20 stream
function crypto_stream_xsalsa20_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR using the XSalsa20 stream starting at a given block
function crypto_stream_xsalsa20_xor_ic(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; ic: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for XSalsa20
function crypto_stream_xsalsa20_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a random key for XSalsa20
procedure crypto_stream_xsalsa20_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of the xchacha20 key
function crypto_stream_xchacha20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Length of an XChaCha20 nonce
function crypto_stream_xchacha20_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Maximum message length for XChaCha20
function crypto_stream_xchacha20_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generate an XChaCha20 keystream
function crypto_stream_xchacha20(c: pbyte; clen: size_t; n: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR a message with an XChaCha20 stream
function crypto_stream_xchacha20_xor(c: pbyte; m: pbyte; mlen: size_t; n: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// XOR with an XChaCha20 stream starting at a block counter
function crypto_stream_xchacha20_xor_ic(c: pbyte; m: pbyte; mlen: size_t; n: pbyte; ic: uint64; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a key for xchacha20
procedure crypto_stream_xchacha20_keygen(k: pbyte) cdecl; external {$ifndef STATICLINK}lib{$endif};

{ VERIFY }
// Constant-time comparison length for 16-byte values
function crypto_verify_16_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compare two 16-byte sequences in constant time
function crypto_verify_16(const x: pansichar; const y: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Constant-time comparison length for 32-byte values
function crypto_verify_32_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compare two 32-byte sequences in constant time
function crypto_verify_32(const x: pansichar; const y: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Constant-time comparison length for 64-byte values
function crypto_verify_64_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compare two 64-byte sequences in constant time
function crypto_verify_64(const x: pansichar; const y: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ SODIUM }
// Checks at runtime for neon support
function sodium_runtime_has_neon: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for sse2 support
function sodium_runtime_has_sse2: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for sse3 support
function sodium_runtime_has_sse3: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Securely wipe memory
procedure sodium_memzero(const pnt: pointer; const len: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compare two buffers in constant time
function sodium_memcmp(const b1_: pansichar; const b2_: pansichar; len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Convert binary data to a hexadecimal string
function sodium_bin2hex(const hex: pansichar; const hex_maxlen: size_t; const bin: pansichar; const bin_len: size_t): pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Parse a hexadecimal string into binary data
function sodium_hex2bin(const bin: pansichar; const bin_maxlen: size_t; const hex: pansichar; const hex_len: size_t; const ignore: pansichar; bin_len: psize_t; const hex_end: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Convert binary data to Base64
function sodium_bin2base64(const b64: pansichar; const b64_maxlen: size_t; const bin: pansichar; const bin_len: size_t; const variant: integer): pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Parse a Base64 string into binary data
function sodium_base642bin(const bin: pansichar; const bin_maxlen: size_t; const b64: pansichar; const b64_len: size_t; const ignore: pansichar; bin_len: psize_t; const b64_end: pansichar; const variant: integer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Calculate the required length for a Base64 string
function sodium_base64_encoded_len(bin_len: size_t; variant: integer): size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Locks memory to prevent swapping
function sodium_mlock(const addr: pointer; const len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Unlocks previously locked memory
function sodium_munlock(const addr: pointer; const len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Allocates guarded memory
function sodium_malloc(const size: size_t): pointer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Allocates guarded memory for an array
function sodium_allocarray(count: size_t; size: size_t): pointer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Marks memory as inaccessible
function sodium_mprotect_noaccess(ptr: pointer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Marks memory as read-only
function sodium_mprotect_readonly(ptr: pointer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Marks memory as read-write
function sodium_mprotect_readwrite(ptr: pointer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Pads data to a multiple of blocksize
function sodium_pad(padded_buflen_p: psize_t; const buf: pansichar; const unpadded_buflen: size_t; const blocksize: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Removes padding from data
function sodium_unpad(unpadded_buflen_p: psize_t; const buf: pansichar; const padded_buflen: size_t; const blocksize: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns the library version string
function sodium_version_string: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns the major library version
function sodium_library_version_major: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns the minor library version
function sodium_library_version_minor: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize the sodium library
function sodium_init: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Frees memory allocated by sodium_malloc
procedure sodium_free(ptr: pointer) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Compares two buffers in constant time
function sodium_compare(const b1: pansichar; const b2: pansichar; const len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Increments a big-endian number
procedure sodium_increment(const bin: pansichar; const bin_len: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Returns 1 if the buffer is all zeros, 0 otherwise
function sodium_is_zero(const n: pansichar; nlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Adds two large numbers (little-endian)
procedure sodium_add(const a: pansichar; const b: pansichar; const len: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Subtracts two large numbers (little-endian)
procedure sodium_sub(const a: pansichar; const b: pansichar; const len: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Wipes stack memory
procedure sodium_stackzero(const len: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for ssse3 support
function sodium_runtime_has_ssse3: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for sse41 support
function sodium_runtime_has_sse41: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for avx support
function sodium_runtime_has_avx: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for avx2 support
function sodium_runtime_has_avx2: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for avx512 support
function sodium_runtime_has_avx512: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for pclmul support
function sodium_runtime_has_pclmul: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for aesni support
function sodium_runtime_has_aesni: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for the ARM crypto extensions
function sodium_runtime_has_armcrypto: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Checks at runtime for the RDRAND instruction
function sodium_runtime_has_rdrand: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Install a custom misuse handler
function sodium_set_misuse_handler(handler: pointer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Trigger the installed misuse handler
procedure sodium_misuse; cdecl; external {$ifndef STATICLINK}lib{$endif};

{ OTHER }
// Compute a message authentication code
function crypto_auth(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypt and authenticate a message
function crypto_box(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Computes a generic hash for a message using an optional key
function crypto_generichash(const outbuf: pansichar; outlen: size_t; const inbuf: pansichar; inlen: uint64; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Computes a cryptographic hash of the input message
function crypto_hash(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Computes a one-time authentication tag for a message
function crypto_onetimeauth(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Performs scalar multiplication of an elliptic curve point
function crypto_scalarmult(const q: pansichar; const n: pansichar; const p: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Encrypts and authenticates a message using XSalsa20-Poly1305
function crypto_secretbox(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Produces a fixed-size hash suitable for hash tables
function crypto_shorthash(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Signs a message using the secret key
function crypto_sign(const sm: pansichar; smlen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Generates a pseudorandom byte stream
function crypto_stream(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
// Fills a buffer with cryptographically secure random bytes
procedure randombytes(const buf: pansichar; const buf_len: uint64) cdecl; external {$ifndef STATICLINK}lib{$endif};
// Initialize the guarded memory allocator
function _sodium_alloc_init: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

implementation

end.
