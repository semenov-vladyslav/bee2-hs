@echo off

set x=stack exec -- bee2-exe

md zed 2>NUL
copy privkey_z.der zed\
copy privkey_z_10000.der zed\

pushd zed
REM fails
%x% d-pkcs8-encpri zed --if-bin privkey_z.der --of-bin z.pri
%x% d-pkcs8-encpri zed --if-bin privkey_z_10000.der --of-bin z_10000.pri

REM decode iter & salt & epri
%x% d-pkcs8-encwrap --if-bin privkey_z.der --of-bin z.salt --of-bin z.epri
%x% d-pkcs8-encwrap --if-bin privkey_z_10000.der --of-bin z_10000.salt --of-bin z_10000.epri

REM mk kek
%x% pbkdf2 2048 --if-bin z.salt zed --of-bin z.kek
%x% pbkdf2 10000 --if-bin z_10000.salt zed --of-bin z_10000.kek

REM try unwrap
%x% uwp --if-bin z.kek --if-bin z.epri --of-bin z.pri
%x% uwp --if-bin z_10000.kek --if-bin z_10000.epri --of-bin z_10000.pri

popd
