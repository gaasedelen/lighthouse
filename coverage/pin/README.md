# About

`CodeCoverage` pintool that creates a log file with information regarding the instructions executed
by a process. The tool works on Windows, Linux and OS X.

This tool aims to facilitate locating interesting parts of a program without incurring in too much
instrumentation overhead. For this reason the pintool can be instructed to only instrument those
modules inside a white-list.

## Usage example

Here we run the pintool from the command line and we specify that only the `test`
image should be instrumented. This improves performance and reduce the amount of information collected.
You can specify as many white-listed images as you want by adding several `-w` arguments to the pintool.
If no `-w` arguments are supplied, this means the tool will trace all loaded images.

```
$ pin -t obj-intel64/CodeCoverage.dylib -w test -- ./test
CodeCoverage tool by Agustin Gianni (agustingianni@gmail.com)
White-listing image: test
Logging code coverage information to: trace.log
Loaded image: 0x000000010a1df000:0x000000010a1dffff -> test
Loaded image: 0x00007fff65a5c000:0x00007fff65acffff -> dyld
Loaded image: 0x00007fff94b07000:0x00007fff94b5afff -> libc++.1.dylib
Loaded image: 0x00007fff942fa000:0x00007fff942fbfff -> libSystem.B.dylib
Loaded image: 0x00007fff8bf30000:0x00007fff8bf59fff -> libc++abi.dylib
Loaded image: 0x00007fff875ac000:0x00007fff875b0fff -> libcache.dylib

$ ll trace.log
-rw-------  1 anon  staff   3.1K Apr 28 01:01 trace.log

If you want to instrument all the loaded modules you can leave out the "-w" parameter and it will
trace all the basic blocks. Beware that the resulting log file will be several orders of magnitude
bigger.

$ pin -t obj-intel64/CodeCoverage.dylib -- ./test
CodeCoverage tool by Agustin Gianni (agustingianni@gmail.com)
White-listed images not specified, instrumenting every module by default.
Logging code coverage information to: trace.log
Loaded image: 0x0000000101bf1000:0x0000000101bf1fff -> test
Loaded image: 0x00007fff6d167000:0x00007fff6d1dafff -> dyld
Loaded image: 0x00007fff94b07000:0x00007fff94b5afff -> libc++.1.dylib
Loaded image: 0x00007fff942fa000:0x00007fff942fbfff -> libSystem.B.dylib
Loaded image: 0x00007fff8bf30000:0x00007fff8bf59fff -> libc++abi.dylib
Loaded image: 0x00007fff875ac000:0x00007fff875b0fff -> libcache.dylib

$ ll trace.log
-rw-------  1 anon  staff   113K Apr 28 00:57 trace.log
```

As it can be appreciated in the log file, we have both information about the trace hits and information about the
loaded images (in the example some entries were removed for clarity). This is because when importing the
information into IDA Pro we need to accommodate the addresses to the base address in the IDB. Due to ASLR
the addresses won't match.

## Compilation

In order to compile this pintool, you need to download pin from https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool and place it in a cozy place. Once you've done that, make sure to export an environment variable named `PIN_ROOT` and make it point to your pin installation dir. Also make sure the you add `$PIN_ROOT` to your `PATH` environment variable.

```
$ export PIN_ROOT=/Users/anon/pin  # Location where you unpacked pintool
$ export PATH=$PATH:$PIN_ROOT
$ make

mkdir -p obj-intel64
/Applications/Xcode.app/Contents/Developer/usr/bin/make objects
make[1]: Nothing to be done for `objects'.
/Applications/Xcode.app/Contents/Developer/usr/bin/make libs
make[1]: Nothing to be done for `libs'.
/Applications/Xcode.app/Contents/Developer/usr/bin/make dlls
make[1]: Nothing to be done for `dlls'.
/Applications/Xcode.app/Contents/Developer/usr/bin/make apps
make[1]: Nothing to be done for `apps'.
/Applications/Xcode.app/Contents/Developer/usr/bin/make tools

c++ -DBIGARRAY_MULTIPLIER=1 -Wall -Werror -Wno-unknown-pragmas -D__PIN__=1 -DPIN_CRT=1 -fno-stack-protector -fno-exceptions -funwind-tables -fno-rtti -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_MAC -D__DARWIN_ONLY_UNIX_CONFORMANCE=1 -D__DARWIN_UNIX03=0   -I/Users/anon/pin/source/include/pin -I/Users/anon/pin/source/include/pin/gen -isystem /Users/anon/pin/extras/stlport/include -isystem /Users/anon/pin/extras/libstdc++/include -isystem /Users/anon/pin/extras/crt/include -isystem /Users/anon/pin/extras/crt/include/arch-x86_64 -isystem /Users/anon/pin/extras/crt/include/kernel/uapi -isystem /Users/anon/pin/extras/crt/include/kernel/uapi/asm-x86 -I/Users/anon/pin/extras/components/include -I/Users/anon/pin/extras/xed-intel64/include/xed -I/Users/anon/pin/source/tools/InstLib -O3 -fomit-frame-pointer -fno-strict-aliasing  -std=c++11 -Wno-format  -c -o obj-intel64/CodeCoverage.o CodeCoverage.cpp

c++ -DBIGARRAY_MULTIPLIER=1 -Wall -Werror -Wno-unknown-pragmas -D__PIN__=1 -DPIN_CRT=1 -fno-stack-protector -fno-exceptions -funwind-tables -fno-rtti -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_MAC -D__DARWIN_ONLY_UNIX_CONFORMANCE=1 -D__DARWIN_UNIX03=0   -I/Users/anon/pin/source/include/pin -I/Users/anon/pin/source/include/pin/gen -isystem /Users/anon/pin/extras/stlport/include -isystem /Users/anon/pin/extras/libstdc++/include -isystem /Users/anon/pin/extras/crt/include -isystem /Users/anon/pin/extras/crt/include/arch-x86_64 -isystem /Users/anon/pin/extras/crt/include/kernel/uapi -isystem /Users/anon/pin/extras/crt/include/kernel/uapi/asm-x86 -I/Users/anon/pin/extras/components/include -I/Users/anon/pin/extras/xed-intel64/include/xed -I/Users/anon/pin/source/tools/InstLib -O3 -fomit-frame-pointer -fno-strict-aliasing  -std=c++11 -Wno-format  -c -o obj-intel64/ImageManager.o ImageManager.cpp

c++ -shared /Users/anon/pin/intel64/runtime/pincrt/crtbeginS.o -w -Wl,-exported_symbols_list,/Users/anon/pin/source/include/pin/pintool.exp     -o obj-intel64/CodeCoverage.dylib obj-intel64/CodeCoverage.o obj-intel64/ImageManager.o  -L/Users/anon/pin/intel64/runtime/pincrt -L/Users/anon/pin/intel64/lib -L/Users/anon/pin/intel64/lib-ext -L/Users/anon/pin/extras/xed-intel64/lib -lpin -lxed -lpin3dwarf -nostdlib -lstlport-dynamic -lm-dynamic -lc-dynamic -lunwind-dynamic
```

The resulting binaries will be placed inside a directory whose name depends on the arch/platform/build type.

- Linux and OSX

	- obj-intel32/CodeCoverage.[so|dylib]
	- obj-intel64/CodeCoverage.[so|dylib]

- Windows

	- Debug/CodeCoverage.dll
	- Release/CodeCoverage.dll
	- x64/Debug/CodeCoverage.dll
	- x64/Release/CodeCoverage.dll

## Trace file format
The format of the trace file emulates that of `drcov` tool from `dynamorio`. More information can be found in
http://dynamorio.org/docs/page_drcov.html

## Authors

* Agustin Gianni ([@agustingianni](https://twitter.com/agustingianni))
