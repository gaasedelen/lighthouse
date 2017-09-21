@echo off
cls

cl ^
    /c ^
    /I%PIN_ROOT%\source\include\pin ^
    /I%PIN_ROOT%\source\include\pin\gen ^
    /I%PIN_ROOT%\source\tools\InstLib   ^
    /I"%PIN_ROOT%\extras\xed-intel64\include\xed" ^
    /I%PIN_ROOT%\extras\components\include ^
    /I%PIN_ROOT%\extras\stlport\include ^
    /I%PIN_ROOT%\extras ^
    /I%PIN_ROOT%\extras\libstdc++\include ^
    /I%PIN_ROOT%\extras\crt\include ^
    /I%PIN_ROOT%\extras\crt ^
    /I"%PIN_ROOT%\extras\crt\include\arch-x86_64" ^
    /I%PIN_ROOT%\extras\crt\include\kernel\uapi ^
    /I"%PIN_ROOT%\extras\crt\include\kernel\uapi\asm-x86" ^
    /nologo /W3 /WX- /O2 ^
    /D TARGET_IA32E /D HOST_IA32E /D TARGET_WINDOWS /D WIN32 /D __PIN__=1 /D PIN_CRT=1 /D __LP64__ ^
    /Gm- /MT /GS- /Gy /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline /GR- /Gd /TP /wd4530 /GR- /GS- /EHs- /EHa- /FP:strict /Oi- ^
    /FIinclude/msvc_compat.h CodeCoverage.cpp ImageManager.cpp ImageManager.h TraceFile.h

link ^
    /ERRORREPORT:QUEUE ^
    /OUT:CodeCoverage64.dll ^
    /INCREMENTAL:NO ^
    /NOLOGO ^
    /LIBPATH:%PIN_ROOT%\intel64\lib ^
    /LIBPATH:"%PIN_ROOT%\intel64\lib-ext" ^
    /LIBPATH:"%PIN_ROOT%\extras\xed-intel64\lib" ^
    /LIBPATH:%PIN_ROOT%\intel64\runtime\pincrt pin.lib xed.lib pinvm.lib kernel32.lib "stlport-static.lib" "m-static.lib" "c-static.lib" "os-apis.lib" "ntdll-64.lib" crtbeginS.obj ^
    /NODEFAULTLIB ^
    /MANIFEST:NO ^
    /OPT:NOREF ^
    /TLBID:1 ^
    /ENTRY:"Ptrace_DllMainCRTStartup" ^
    /BASE:"0xC5000000" ^
    /DYNAMICBASE ^
    /NXCOMPAT ^
    /IMPLIB:CodeCoverage.lib ^
    /MACHINE:X64 ^
    /SAFESEH:NO ^
    /export:main ^
    /ignore:4049 ^
    /ignore:4210 ^
    /ignore:4217 ^
    /DLL CodeCoverage.obj ImageManager.obj

del *.obj *.pdb *.exp *.lib