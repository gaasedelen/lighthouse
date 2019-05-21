set LIGHTHOUSE_LOGGING=1
REM - Close any running instances of IDA
call close_IDA.bat

REM - Purge old lighthouse log files
del /F /Q "C:\Users\user\AppData\Roaming\Hex-Rays\IDA Pro\lighthouse_logs\*"

REM - Delete the old plugin bits
del /F /Q "C:\Users\user\AppData\Roaming\Hex-Rays\IDA Pro\plugins\*lighthouse_plugin.py"
rmdir     "C:\Users\user\AppData\Roaming\Hex-Rays\IDA Pro\plugins\lighthouse" /s /q

REM - Copy over the new plugin bits
xcopy /s/y "..\plugin\*" "C:\Users\user\AppData\Roaming\Hex-Rays\IDA Pro\plugins\"
del /F /Q "C:\Users\user\AppData\Roaming\Hex-Rays\IDA Pro\plugins\.#lighthouse_plugin.py"

REM - Relaunch two IDA sessions
start "" "C:\tools\disassemblers\IDA 6.95\idaq64.exe" "..\..\testcase\boombox95.i64"

