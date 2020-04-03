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

Using a [custom pintool](coverage/pin) contributed by [Agustin Gianni](https://twitter.com/agustingianni), the Intel Pin DBI can also be used to collect coverage data.

Example usage:

```
pin.exe -t CodeCoverage64.dll -- boombox.exe
```

For convenience, binaries for the Windows pintool can be found on the [releases](https://github.com/gaasedelen/lighthouse/releases) page. macOS and Linux users need to compile the pintool themselves following the [instructions](coverage/pin#compilation) included with the pintool for their respective platforms.

## Frida (Experimental)

Lighthouse offers limited support for Frida based code coverage via a custom [instrumentation script](coverage/frida) contributed by [yrp](https://twitter.com/yrp604). 

Example usage:

```
sudo python frida-drcov.py bb-bench
```

