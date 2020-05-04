# Collecting Coverage

Before using Lighthouse, one will need to collect code coverage data for their target binary / application.

The examples below demonstrate how one can use [DynamoRIO](http://www.dynamorio.org), [Intel Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) or [Frida](https://www.frida.re) to collect Lighthouse compatible coverage against a target. The `.log` files produced by these instrumentation tools can be loaded directly into Lighthouse.

## DynamoRIO

Code coverage data can be collected via DynamoRIO's [drcov](http://dynamorio.org/docs/page_drcov.html) code coverage module. 

Example usage:

```
..\DynamoRIO-Windows-7.0.0-RC1\bin64\drrun.exe -t drcov -- boombox.exe
```

## Intel Pin

Using a [custom pintool](pin) contributed by [Agustin Gianni](https://twitter.com/agustingianni), the Intel Pin DBI can also be used to collect coverage data.

Example usage:

```
pin.exe -t CodeCoverage64.dll -- boombox.exe
```

For convenience, binaries for the Windows pintool can be found on the [releases](https://github.com/gaasedelen/lighthouse/releases) page. macOS and Linux users need to compile the pintool themselves following the [instructions](pin#compilation) included with the pintool for their respective platforms.

## Frida (Experimental)

Lighthouse offers limited support for Frida based code coverage via a custom [instrumentation script](frida) contributed by [yrp](https://twitter.com/yrp604).

Example usage:

```
sudo python frida-drcov.py bb-bench
```

# Other Coverage Formats

Lighthouse is flexible as to what kind of coverage or 'trace' file formats it can load. Below is an outline of these human-readable text formats that are arguably the easiest to output from a custom tracer. 

## Module + Offset (modoff)

A 'Module+Offset' coverage file / trace is a highly recommended coverage format due to its simplicity and readability:

```
boombox+3a06
boombox+3a09
boombox+3a0f
boombox+3a15
...
```

Each line of the trace represents an executed instruction or basic block in the instrumented program. The line *must* name an executed module eg `boombox.exe` and a relative offset to the executed address from the imagebase. 

It is okay for hits from other modules (say, `kernel32.dll`) to exist in the trace. Lighthouse will not load coverage for them.

## Address Trace (Instruction, or Basic Block)

Perhaps the most primitive coverage format, Lighthouse can also consume an 'absolute address' style trace:

```
0x14000419c
0x1400041a0
0x1400045dc
0x1400045e1
0x1400045e2
...
```

Note that these address traces can be either instruction addresses, or basic block addresses -- it does not matter. The main caveat is that addresses in the trace *must* match the address space within the disassembler database. 

If an address cannot be mapped into a function in the disassembler database, Lighthouse will simply discard it.

## Custom Trace Formats

If you are adamant to use a completely custom coverage format, you can try to subclass Lighthouse's `CoverageFile` parser interface. Once complete, simply drop your parser into the `parsers` folder.

