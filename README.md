# fpc-libsodium

Pascal bindings for the [libsodium](https://doc.libsodium.org/) cryptographic library, tailored for FreePascal.

## What’s Included

- **Dynamic Libraries (v1.0.20)**  
  - `libsodium.dll` (32-bit)  
  - `libsodium64.dll` (64-bit)  
  Precompiled from official [libsodium releases](https://download.libsodium.org/libsodium/releases/).

- **Static Libraries (v1.0.20)**  
  - Found in `static/win32` and `static/win64`  
  - Built from source using provided scripts in the `static` directory

## How to Use

1. Add `libsodium.pas` to your project.
2. Define `STATICLINK` to compile without DLL dependencies (statically linked).
3. Check `demo.lpr` for a basic usage example.

## License

This binding (`libsodium.pas`) is released under the MIT license.
