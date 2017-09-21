@echo off
cls

cl ^
    /c /EHa- /EHs- /GR- /GS- /Gd /Gm- /Gy /MT /O2 /Oi- /Oy- /TP /W3 /WX- /Zc:forScope /Zc:inline /Zc:wchar_t /fp:precise /nologo /wd4316  ^
    /DTARGET_IA32 /DHOST_IA32 /DTARGET_WINDOWS /DBIGARRAY_MULTIPLIER=1 /DWIN32 /D__PIN__=1 /DPIN_CRT=1 /D__i386__ ^
    /I"%PIN_ROOT%\extras\xed-ia32\include\xed" ^
    /I%PIN_ROOT%\source\include\pin ^
    /I%PIN_ROOT%\source\include\pin\gen ^
    /I%PIN_ROOT%\source\tools\InstLib   ^
    /I"%PIN_ROOT%\extras\xed-ia32\include" ^
    /I%PIN_ROOT%\extras\components\include ^
    /I%PIN_ROOT%\extras\stlport\include ^
    /I%PIN_ROOT%\extras ^
    /I%PIN_ROOT%\extras\libstdc++\include ^
    /I%PIN_ROOT%\extras\crt\include ^
    /I%PIN_ROOT%\extras\crt ^
    /I"%PIN_ROOT%\extras\crt\include\arch-x86" ^
    /I%PIN_ROOT%\extras\crt\include\kernel\uapi ^
    /I"%PIN_ROOT%\extras\crt\include\kernel\uapi\asm-x86" ^
    /FIinclude/msvc_compat.h CodeCoverage.cpp ImageManager.cpp ImageManager.h TraceFile.h

link ^
    /ERRORREPORT:QUEUE ^
    /OUT:CodeCoverage.dll ^
    /INCREMENTAL:NO ^
    /NOLOGO ^
    /LIBPATH:%PIN_ROOT%\ia32\lib ^
    /LIBPATH:"%PIN_ROOT%\ia32\lib-ext" ^
    /LIBPATH:"%PIN_ROOT%\extras\xed-ia32\lib" ^
    /LIBPATH:%PIN_ROOT%\ia32\runtime\pincrt pin.lib xed.lib pinvm.lib kernel32.lib "stlport-static.lib" "m-static.lib" "c-static.lib" "os-apis.lib" "ntdll-32.lib" crtbeginS.obj ^
    /NODEFAULTLIB ^
    /MANIFEST:NO ^
    /OPT:NOREF ^
    /TLBID:1 ^
    /ENTRY:"Ptrace_DllMainCRTStartup@12" ^
    /BASE:"0x55000000" ^
    /DYNAMICBASE ^
    /NXCOMPAT ^
    /IMPLIB:CodeCoverage.lib ^
    /MACHINE:X86 ^
    /SAFESEH:NO ^
    /export:main ^
    /ignore:4049 ^
    /ignore:4210 ^
    /ignore:4217 ^
    /DLL CodeCoverage.obj ImageManager.obj

del *.obj *.pdb *.exp *.lib
