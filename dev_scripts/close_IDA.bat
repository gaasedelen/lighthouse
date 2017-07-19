REM - Clean up an existing or past 'test session' 
taskkill /F /IM "ida.exe"
taskkill /F /IM "ida64.exe"
taskkill /F /IM "idaq.exe"
taskkill /F /IM "idaq64.exe"
timeout 1
del "..\..\testcase\*.id0" 
del "..\..\testcase\*.id1" 
del "..\..\testcase\*.id2" 
del "..\..\testcase\*.nam" 
del "..\..\testcase\*.til"
del "..\..\testcase\*.$$$"