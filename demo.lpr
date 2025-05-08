program demo;

uses Windows, libsodium;

function tohex(p: pointer; len: dword): string;
const
  hexchar = '0123456789abcdef';
var
  i: integer;
begin
  setlength(result, len*2);
  for i := 0 to len-1 do begin
    result[1+i*2+0] := hexchar[1+pbyte(p+i)^ shr 4];
    result[1+i*2+1] := hexchar[1+pbyte(p+i)^ and $f];
  end;
end;

procedure test_sign_verify;
var
  pubkey, privkey, message, signature: string;
begin
  if sodium_init = -1 then exit;
  // key pair
  setlength(pubkey, crypto_sign_publickeybytes);
  setlength(privkey, crypto_sign_publickeybytes);
  crypto_sign_keypair(@pubkey[1], @privkey[1]);
  writeln('pubkey    = ', tohex(@pubkey[1], length(pubkey)));
  writeln('privkey   = ', tohex(@privkey[1], length(privkey)));
  // msg
  message := 'hello libsodium';
  // sign
  setlength(signature, crypto_sign_bytes);
  writeln('sign      = ', crypto_sign_detached(@signature[1], nil, @message[1], length(message), @privkey[1]));
  writeln('signature = ', tohex(@signature[1], length(signature)));
  // verify
  writeln('verify    = ', crypto_sign_verify_detached(@signature[1], @message[1], length(message), @pubkey[1]));
end;

procedure test_sha512;
var
  state: crypto_hash_sha512_state;
  message, hash: string;
begin
  message := 'hello';
  crypto_hash_sha512_init(@state);
  crypto_hash_sha512_update(@state, @message[1], length(message));
  setlength(hash, crypto_auth_hmacsha512_bytes);
  crypto_hash_sha512_final(@state, @hash[1]);
  writeln('sha512 of "', message, '" = ', tohex(@hash[1], length(hash)));
end;

procedure main;
begin
  writeln('sodium init = ', sodium_init);
  writeln('sodium version = ', sodium_version_string);
  writeln;

  test_sign_verify;
  writeln;

  test_sha512;
  writeln;

  readln;
end;

begin
  main;
end.

