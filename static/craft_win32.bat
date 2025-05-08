@echo off

rem doesnt work for win32
rem demo.lpr(69,1) Error: Undefined symbol: __head_win32_libsodium_a (first seen in libsodium.a(dwhjcs00618.o))

copy ..\libsodium.dll .\libsodium.dll
pexports libsodium.dll > libsodium.def
dlltool -d libsodium.def -l win32\libsodium.a
del libsodium.def
del libsodium.dll
