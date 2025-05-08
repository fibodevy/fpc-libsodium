@echo off
copy ..\libsodium64.dll .\libsodium.dll
pexports libsodium.dll > libsodium.def
sed -i '1s/.*/LIBRARY libsodium64/' libsodium.def
dlltool64 -d libsodium.def -l win64\libsodium.a
del libsodium.def
del libsodium.dll
