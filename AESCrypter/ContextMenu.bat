copy "%~dp0AESCrypter.exe" "C:\Program Files\AESCrypter.exe"
attrib +h "C:\Program Files\AESCrypter.exe"
echo Windows Registry Editor Version 5.00 >> "Register.reg"
echo.  >> "Register.reg"
echo [HKEY_CLASSES_ROOT\*\Shell] >> "Register.reg"
echo.  >> "Register.reg"
echo [HKEY_CLASSES_ROOT\*\Shell\AESCrypter] >> "Register.reg"
echo @="AESCrypter" >> "Register.reg"
echo.  >> "Register.reg"
echo [HKEY_CLASSES_ROOT\*\Shell\AESCrypter] >> "Register.reg"
echo "Icon"="C:\\Program Files\\AESCrypter.exe" >> "Register.reg"
echo.  >> "Register.reg"
echo [HKEY_CLASSES_ROOT\*\Shell\AESCrypter\command] >> "Register.reg"
echo @="C:\\Program Files\\AESCrypter.exe %%1" >> "Register.reg"
start Register.reg
pause
del Register.reg