set LIGHTHOUSE_LOGGING=1
REM - Close any running instances of Binja
call close_BINJA.bat

REM - Purge old lighthouse log files
del /F /Q "C:\Users\user\AppData\Roaming\Binary Ninja\lighthouse_logs\*"

REM - Delete the old plugin bits
del /F /Q "C:\Users\user\AppData\Roaming\Binary Ninja\plugins\*lighthouse_plugin.py"
rmdir     "C:\Users\user\AppData\Roaming\Binary Ninja\plugins\lighthouse" /s /q

REM - Copy over the new plugin bits
xcopy /s/y "..\plugin\*" "C:\Users\user\AppData\Roaming\Binary Ninja\plugins\"
del /F /Q "C:\Users\user\AppData\Roaming\Binary Ninja\plugins\.#lighthouse_plugin.py"

REM - Launch a new Binja session
start "" "C:\tools\disassemblers\BinaryNinja_Personal\binaryninja.exe" "..\..\testcase\boombox.bndb"

