@echo off

set iter=10000
set salt=BE32971343FC9A48A02A885F194B09A1
set pwd=B194BAC80A08F53B
set pri=1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269

goto :unwrap


echo kek:
stack exec -- bee2-exe pbkdf2 %iter% %salt% %pwd% --out-hex
echo.
echo epri:
stack exec -- bee2-exe pbkdf2 %iter% %salt% %pwd% --out-bin | stack exec -- bee2-exe kwp %pri% --in-bin --out-hex


stack exec -- bee2-exe pbkdf2 %iter% %salt% %pwd% --of-bin kek.bin
stack exec -- bee2-exe pkcs8-pri %pri% --of-bin pri.pkcs8
stack exec -- bee2-exe kwp --if-bin kek.bin --if-bin pri.pkcs8 --of-bin epri.pkcs8.bin
stack exec -- bee2-exe pkcs8-encpri %iter% %salt% %pwd% %pri% --of-bin encpri.pkcs8

:unwrap
stack exec -- bee2-exe d-pkcs8-encpri %pwd% --if-bin encpri.pkcs8 --out-hex
rem stack exec -- bee2-exe d-pkcs8-encwrap --if-bin encpri.pkcs8 --of-bin pri.salt.bin --of-bin pri.ekey.bin

