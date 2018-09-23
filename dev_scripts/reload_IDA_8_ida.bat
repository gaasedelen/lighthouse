set LIGHTHOUSE_LOGGING=1
REM - Close any running instances of IDA
call close_IDA.bat

REM - Purge old lighthouse log files
del /F /Q "C:\Users\user\AppData\Roaming\Hex-Rays\IDA Pro\lighthouse_logs\*"

REM - Delete the old plugin bits
del /F /Q "C:\tools\disassemblers\IDA 6.8\plugins\*lighthouse_plugin.py"
rmdir     "C:\tools\disassemblers\IDA 6.8\plugins\lighthouse" /s /q

REM - Copy over the new plugin bits
xcopy /s/y "..\plugin\*" "C:\tools\disassemblers\IDA 6.8\plugins\"
del /F /Q "C:\tools\disassemblers\IDA 6.8\plugins\.#lighthouse_plugin.py"

REM - Relaunch two IDA sessions
start "" "C:\tools\disassemblers\IDA 6.8\idaq.exe" "..\..\testcase\idaq.idb"

