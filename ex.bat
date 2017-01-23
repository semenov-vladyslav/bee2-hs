@echo off

set x=stack exec -- bee2-exe

md ex 2>NUL
pushd ex
@echo on
%x% io 42313934424143383041303846353342 --of-bin stdpwd
%x% io BE32971343FC9A48A02A885F194B09A1 --of-bin stdsalt
%x% pbkdf2 10000 --if-bin stdsalt B194BAC80A08F53B --of-bin stdkek
%x% io 1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269 --of-bin stdpri
%x% kwp --if-bin stdkek --if-bin stdpri --of-bin stdepri
%x% uwp --if-bin stdkek --if-bin stdepri --of-bin stddepri
%x% pkcs8-encpri 10000 --if-bin stdsalt B194BAC80A08F53B --if-bin stdpri --of-bin pkcs8epri
%x% d-pkcs8-encpri B194BAC80A08F53B --if-bin pkcs8epri --of-bin pkcs8depri
@echo off
popd
