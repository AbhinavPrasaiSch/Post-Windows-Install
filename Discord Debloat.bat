@echo off
TITLE Discord Debloat by Reknotic

:start
echo Discord Debloat by Reknotic
echo.

echo Closing discord.exe!
TASKKILL /T /F /IM  discord.exe
CLS

echo Discord Debloat by Reknotic
echo.
echo 1 - Debloat Discord
echo.
echo 2 - Exit
echo.

set choice=
set /p choice=Type the Number to Execute = 
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Debloat
if '%choice%'=='2' goto Exit

echo "%choice%" is not valid, try again

echo.

goto start

:Debloat
echo Debloating Discord!

cd %HOMEPATH%\AppData\Local\Discord\app-1.0.9003\modules\
Rmdir /S /Q "discord_cloudsync-1"
Rmdir /S /Q "discord_dispatch-1"
Rmdir /S /Q "discord_erlpack-1"
Rmdir /S /Q "discord_game_utils-1"
Rmdir /S /Q "discord_krisp-1"
Rmdir /S /Q "discord_overlay2-1"
Rmdir /S /Q "discord_rpc-1"
Rmdir /S /Q "discord_spellcheck-2"

CLS
echo Completed Successfully!
echo.
echo After running this batch file, you can create a Discord shortcut from
echo.
echo %HOMEPATH%\appdata\Local\discord\app-0.0.(your version) if you want!

echo.
Pause

:Exit
exit
