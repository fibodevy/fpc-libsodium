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

type
  psize_t = ^size_t;

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

  crypto_onetimeauth_poly1305_state = packed record
    aligner: uint64;
    opaque: array[0..135] of byte;
  end;
  pcrypto_onetimeauth_poly1305_state = ^crypto_onetimeauth_poly1305_state;

  crypto_onetimeauth_state = crypto_onetimeauth_poly1305_state;
  pcrypto_onetimeauth_state = ^crypto_onetimeauth_state;

type
  crypto_secretstream_xchacha20poly1305_state = packed record
    k: array[0..31] of uint32;
    nonce: array[0..11] of uint32;
    _pad: array[0..7] of byte;
  end;

  randombytes_implementation = packed record
    implementation_name: pansichar;
    random: pointer;
    stir: pointer;
    uniform: pointer;
    buf: pointer;
    close: pointer;
  end;
  prandombytes_implementation = ^randombytes_implementation;

function crypto_aead_chacha20poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_chacha20poly1305_nsecbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_chacha20poly1305_npubbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_chacha20poly1305_abytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_chacha20poly1305_encrypt(const c: pansichar; clen: puint64; const m: pansichar; mlen: uint64; const ad: pansichar; adlen: uint64; const nsec: pansichar; const npub: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_chacha20poly1305_decrypt(const m: pansichar; mlen: puint64; const nsec: pansichar; const c: pansichar; clen: uint64; const ad: pansichar; adlen: uint64; const npub: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_chacha20poly1305_ietf_npubbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_chacha20poly1305_ietf_encrypt(const c: pansichar; clen: puint64; const m: pansichar; mlen: uint64; const ad: pansichar; adlen: uint64; const nsec: pansichar; const npub: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_chacha20poly1305_ietf_decrypt(const m: pansichar; mlen: puint64; const nsec: pansichar; const c: pansichar; clen: uint64; const ad: pansichar; adlen: uint64; const npub: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha256_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha256_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha256(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha256_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha256_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha256_init(state: pcrypto_auth_hmacsha256_state; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha256_update(state: pcrypto_auth_hmacsha256_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha256_final(state: pcrypto_auth_hmacsha256_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512_init(state: pcrypto_auth_hmacsha512_state; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512_update(state: pcrypto_auth_hmacsha512_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512_final(state: pcrypto_auth_hmacsha512_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512256_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512256_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512256(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512256_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512256_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512256_init(state: pcrypto_auth_hmacsha512256_state; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512256_update(state: pcrypto_auth_hmacsha512256_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_hmacsha512256_final(state: pcrypto_auth_hmacsha512256_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_seed_keypair(const pk: pansichar; const sk: pansichar; const seed: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_easy(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_open_easy(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_detached(const c: pansichar; const mac: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_open_detached(const m: pansichar; const c: pansichar; const mac: pansichar; clen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_beforenmbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_beforenm(const k: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_easy_afternm(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_open_easy_afternm(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_detached_afternm(const c: pansichar; const mac: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_open_detached_afternm(const m: pansichar; const c: pansichar; const mac: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_sealbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_seal(const c: pansichar; const m: pansichar; mlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_seal_open(const m: pansichar; const c: pansichar; clen: uint64; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_zerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_boxzerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_open(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_afternm(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_open_afternm(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_beforenmbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_zerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_boxzerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_open(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk: pbyte; sk: pbyte; const seed: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_beforenm(const k: pansichar; const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_afternm(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_box_curve25519xsalsa20poly1305_open_afternm(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_hsalsa20_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_hsalsa20_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_hsalsa20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_hsalsa20_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_hsalsa20(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa20_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa20_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa20_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa20(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa2012_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa2012_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa2012_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa2012_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa2012(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa208_outputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa208_inputbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa208_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa208_constbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_core_salsa208(const outbuf: pansichar; const inbuf: pansichar; const k: pansichar; const c: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_bytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_bytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_keybytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_keybytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash(const outbuf: pansichar; outlen: size_t; const inbuf: pansichar; inlen: uint64; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_init(state: pcrypto_generichash_state; const key: pansichar; const keylen: size_t; const outlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_update(state: pcrypto_generichash_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_final(state: pcrypto_generichash_state; const outbuf: pansichar; const outlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_bytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_bytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_keybytes_min: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_keybytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_saltbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_personalbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b(const outbuf: pansichar; outlen: size_t; const inbuf: pansichar; inlen: uint64; const key: pansichar; keylen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_salt_personal(const outbuf: pansichar; outlen: size_t; const inbuf: pansichar; inlen: uint64; const key: pansichar; keylen: size_t; const salt: pansichar; const personal: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_init(state: pcrypto_generichash_blake2b_state; const key: pansichar; const keylen: size_t; const outlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_init_salt_personal(state: pcrypto_generichash_blake2b_state; const key: pansichar; const keylen: size_t; const outlen: size_t; const salt: pansichar; const personal: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_update(state: pcrypto_generichash_blake2b_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_generichash_blake2b_final(state: pcrypto_generichash_blake2b_state; const outbuf: pansichar; const outlen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha256_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha256_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha256(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha256_init(state: pcrypto_hash_sha256_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha256_update(state: pcrypto_hash_sha256_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha256_final(state: pcrypto_hash_sha256_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha512_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha512_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha512(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha512_init(state: pcrypto_hash_sha512_state): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha512_update(state: pcrypto_hash_sha512_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_hash_sha512_final(state: pcrypto_hash_sha512_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_init(state: pcrypto_onetimeauth_state; const key: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_update(state: pcrypto_onetimeauth_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_final(state: pcrypto_onetimeauth_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_poly1305_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_poly1305(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_poly1305_verify(const h: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_poly1305_init(state: pcrypto_onetimeauth_poly1305_state; const key: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_poly1305_update(state: pcrypto_onetimeauth_poly1305_state; const inbuf: pansichar; inlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_onetimeauth_poly1305_final(state: pcrypto_onetimeauth_poly1305_state; const outbuf: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_saltbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_strbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_strprefix: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_opslimit_interactive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_memlimit_interactive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256(const outbuf: pansichar; outlen: uint64; const passwd: pansichar; passwdlen: uint64; const salt: pansichar; opslimit: uint64; memlimit: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_str(outbuf: pansichar; const passwd: pansichar; passwdlen: uint64; opslimit: uint64; memlimit: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_str_verify(const str: pansichar; const passwd: pansichar; passwdlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_pwhash_scryptsalsa208sha256_ll(const passwd: puint8; passwdlen: size_t; const salt: puint8; saltlen: size_t; n: uint64; r: uint32; p: uint32; buf: puint8; buflen: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult_scalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult_base(const q: pansichar; const n: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult(const q: pansichar; const n: pansichar; const p: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult_curve25519_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult_curve25519_scalarbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult_curve25519(const q: pansichar; const n: pansichar; const p: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_scalarmult_curve25519_base(const q: pansichar; const n: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_easy(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_open_easy(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_detached(const c: pansichar; const mac: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_open_detached(const m: pansichar; const c: pansichar; const mac: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_zerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_boxzerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_open(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_xsalsa20poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_xsalsa20poly1305_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_xsalsa20poly1305_zerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_xsalsa20poly1305_boxzerobytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_xsalsa20poly1305_macbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_xsalsa20poly1305(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretbox_xsalsa20poly1305_open(const m: pansichar; const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_shorthash_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_shorthash_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_shorthash_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_shorthash(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_shorthash_siphash24_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_shorthash_siphash24_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_shorthash_siphash24(const outbuf: pansichar; const inbuf: pansichar; inlen: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_seed_keypair(const pk: pansichar; const sk: pansichar; const seed: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign(const sm: pansichar; smlen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_open(const m: pansichar; mlen_p: puint64; const sm: pansichar; smlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_detached(const sig: pansichar; siglen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_verify_detached(const sig: pansichar; const m: pansichar; mlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_seedbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519(const sm: pansichar; smlen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_open(const m: pansichar; mlen_p: puint64; const sm: pansichar; smlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_detached(const sig: pansichar; siglen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_verify_detached(const sig: pansichar; const m: pansichar; mlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_seed_keypair(const pk: pansichar; const sk: pansichar; const seed: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_pk_to_curve25519(const curve25519_pk: pansichar; const ed25519_pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_sk_to_curve25519(const curve25519_sk: pansichar; const ed25519_sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_sk_to_seed(const seed: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_ed25519_sk_to_pk(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_edwards25519sha512batch_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_edwards25519sha512batch_publickeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_edwards25519sha512batch_secretkeybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_edwards25519sha512batch(const sm: pansichar; smlen_p: puint64; const m: pansichar; mlen: uint64; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_edwards25519sha512batch_open(const m: pansichar; mlen_p: puint64; const sm: pansichar; smlen: uint64; const pk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_sign_edwards25519sha512batch_keypair(const pk: pansichar; const sk: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_primitive: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_abytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_headerbytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_messagebytes_max: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_tag_message: byte cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_tag_push: byte cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_tag_rekey: byte cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_tag_final: byte cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_statebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure crypto_secretstream_xchacha20poly1305_keygen(const k: pansichar) cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_init_push(state: ppointer; header: pansichar; k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_push(state: ppointer; c: pansichar; clen_p: uint64; const m: pansichar; mlen: uint64; const ad: pansichar; adlen: uint64; tag: byte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_init_pull(state: ppointer; header: pansichar; k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_secretstream_xchacha20poly1305_pull(state: ppointer; m: pansichar; mlen_p: uint64; tag_p: pansichar; const c: pansichar; clen: uint64; const ad: pansichar; adlen: uint64): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure crypto_secretstream_xchacha20poly1305_rekey(state: ppansichar) cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20_xor_ic(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; ic: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20_ietf_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20_ietf(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20_ietf_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_chacha20_ietf_xor_ic(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; ic: uint32; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa20_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa20(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa20_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa20_xor_ic(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; ic: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa2012_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa2012_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa2012(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_salsa2012_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_xsalsa20_keybytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_xsalsa20_noncebytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_xsalsa20(const c: pansichar; clen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_xsalsa20_xor(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_stream_xsalsa20_xor_ic(const c: pansichar; const m: pansichar; mlen: uint64; const n: pansichar; ic: uint64; const k: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_verify_16_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_verify_16(const x: pansichar; const y: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_verify_32_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_verify_32(const x: pansichar; const y: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_verify_64_bytes: size_t; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_verify_64(const x: pansichar; const y: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure randombytes_buf(const buf: pointer; const size: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure randombytes_buf_deterministic(const buf: pointer; const size: size_t; const seed: pansichar) cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_random: uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_uniform(const upper_bound: uint32): uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure randombytes_stir; cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_close: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_implementation_name: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_set_implementation(impl: prandombytes_implementation): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure randombytes(const buf: pansichar; const buf_len: uint64) cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_salsa20_implementation_name: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_salsa20_random: uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure randombytes_salsa20_random_stir; cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_salsa20_random_uniform(const upper_bound: uint32): uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure randombytes_salsa20_random_buf(const buf: pointer; const size: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_salsa20_random_close: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_sysrandom_implementation_name: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_sysrandom: uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure randombytes_sysrandom_stir; cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_sysrandom_uniform(const upper_bound: uint32): uint32 cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure randombytes_sysrandom_buf(const buf: pointer; const size: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
function randombytes_sysrandom_close: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_neon: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_sse2: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_sse3: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure sodium_memzero(const pnt: pointer; const len: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_memcmp(const b1_: pansichar; const b2_: pansichar; len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_bin2hex(const hex: pansichar; const hex_maxlen: size_t; const bin: pansichar; const bin_len: size_t): pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_hex2bin(const bin: pansichar; const bin_maxlen: size_t; const hex: pansichar; const hex_len: size_t; const ignore: pansichar; bin_len: psize_t; const hex_end: pansichar): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_bin2base64(const b64: pansichar; const b64_maxlen: size_t; const bin: pansichar; const bin_len: size_t; const variant: integer): pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_base642bin(const bin: pansichar; const bin_maxlen: size_t; const b64: pansichar; const b64_len: size_t; const ignore: pansichar; bin_len: psize_t; const b64_end: pansichar; const variant: integer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_mlock(const addr: pointer; const len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_munlock(const addr: pointer; const len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_malloc(const size: size_t): pointer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_allocarray(count: size_t; size: size_t): pointer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_mprotect_noaccess(ptr: pointer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_mprotect_readonly(ptr: pointer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_mprotect_readwrite(ptr: pointer): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_pad(padded_buflen_p: psize_t; const buf: pansichar; const unpadded_buflen: size_t; const blocksize: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_unpad(unpadded_buflen_p: psize_t; const buf: pansichar; const padded_buflen: size_t; const blocksize: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function _sodium_alloc_init: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_version_string: pansichar; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_library_version_major: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_library_version_minor: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_init: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure sodium_free(ptr: pointer) cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_compare(const b1: pansichar; const b2: pansichar; const len: size_t): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
procedure sodium_increment(const bin: pansichar; const bin_len: size_t) cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_ssse3: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_sse41: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_avx: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_avx2: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_avx512: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_pclmul: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function sodium_runtime_has_aesni: integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_auth_keypair(pk, sk: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_shorthash_final(out_: pbyte; sh: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_xchacha20poly1305_ietf_encrypt(c: pbyte; clen: size_t; m: pbyte; mlen: size_t; ad: pbyte; adlen: size_t; nsec: pbyte; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_xchacha20poly1305_ietf_decrypt(m: pbyte; mlen: size_t; nsec: pbyte; c: pbyte; clen: size_t; ad: pbyte; adlen: size_t; npub: pbyte; k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};
function crypto_aead_xchacha20poly1305_ietf_keygen(k: pbyte): integer; cdecl; external {$ifndef STATICLINK}lib{$endif};

implementation

end.
