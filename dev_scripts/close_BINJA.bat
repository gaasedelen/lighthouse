REM - Clean up an existing or past 'test session' 
taskkill /F /IM "binaryninja.exe"
timeout 1
REM del "..\..\testcase\*.id0" 
REM del "..\..\testcase\*.id1" 
REM del "..\..\testcase\*.id2" 
REM del "..\..\testcase\*.nam" 
REM del "..\..\testcase\*.til"
REM del "..\..\testcase\*.$$$"