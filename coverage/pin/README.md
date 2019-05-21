# CodeCoverage Pintool

The `CodeCoverage` pintool runs ontop of the [Intel Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) DBI framework and collects code coverage data in a log format compatible with [Lighthouse](https://github.com/gaasedelen/lighthouse). The log produced by this pintool emulates that of [drcov](http://dynamorio.org/docs/page_drcov.html) as shipped with [DynamoRIO](http://www.dynamorio.org). 

This pintool is labeled only as a prototype.

# Compilation

To compile the pintool, you first will need to [download](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads) and extract Pin.

Follow the build instructions below for your respective platform.

## Building for MacOS or Linux

On MacOS or Liunux, one can compile the pintool using the following commands.

```
# Location of this repo / pintool source
cd ~/lighthouse/coverage/pin

# Location where you extracted Pin
export PIN_ROOT=~/pin
export PATH=$PATH:$PIN_ROOT
make
make TARGET=ia32
```

The resulting binaries will be placed inside a directory whose name depends on the arch/platform/build type.

* obj-intel32/CodeCoverage.[so|dylib]
* obj-intel64/CodeCoverage.[so|dylib]

## Building for Windows

To compile the Windows pintool, you must have at least Visual Studio 2015 installed.

Launch a command prompt and build the pintool with the following commands.

### 32bit Pintool

```
"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86

REM Location of this repo / pintool source
cd C:\Users\user\lighthouse\coverage\pin

REM Location where you extracted Pin
set PIN_ROOT=C:\pin
set PATH=%PATH%;%PIN_ROOT%
build-x86.bat
```

### 64bit Pintool

```
"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86_amd64

REM Location of this repo / pintool source
cd C:\Users\user\lighthouse\coverage\pin

REM Location where you extracted Pin
set PIN_ROOT=C:\pin
set PATH=%PATH%;%PIN_ROOT%
build-x64.bat
```

The resulting binaries will be labaled based on their architecture (eg, 64 is the 64bit pintool).

* CodeCoverage.dll
* CodeCoverage64.dll

Compiling a pintool on Windows can be more arduous. Because of this, we have provided compiled binaries for Windows on the [releases](https://github.com/gaasedelen/lighthouse/releases) page. Please be sure to use the pintool that matches your version of Pin.

# Usage

Once compiled, usage of the pintool is straightforward. Simply provide the compiled `CodeCoverage` pintool to `pin` via the `-t` argument. The resulting code coverage data will be written to the file `trace.log` at the end of execution.

Here is an example of us instrumenting a 64bit binary called `test` with our `CodeCoverage` pintool.

```
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

## Module Whitelisting

Using the `-w` command line flag, the pintool can be instructed to instrument only the modules you specify.

Here we run the pintool from the command line and specify that only the `test` image should be instrumented. This improves performance and drastically reduces the amount of data collected by ignoring the execution of shared libraries such as `libc`.

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
```

You can specify as many white-listed images as you want by adding several `-w` arguments to the pintool.

If no `-w` arguments are supplied, the pintool will trace all loaded images.

# Authors

* Agustin Gianni ([@agustingianni](https://twitter.com/agustingianni))
