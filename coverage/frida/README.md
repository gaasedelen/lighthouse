# frida-drcov.py

A quick and dirty frida-based bb-tracer

If your target is complex, you'll likely want to use a better, dedicated
tracing engine like drcov or pin. This tracer has some significant
shortcomings, which are exagerated on larger or more complex binaries:
* It drops coverage, especially near `exit()`
* It cannot easily detect new threads being created, thus cannot instrument
them
* Self modifying code will confuse it, though to be fair I'm not sure how
drcov, pin, or otheres deal with self modifying code either

These shortcomines are probably 10% frida's fault and 90% the author's. Despite
these flaws however, it is hard to beat the ease of use frida provides.

## Install

`$ pip install frida`

## Usage
`$ ./frida-drcov <process name | pid>`

You can whitelist specific modules inside your target. Say you have binary
`foo` which imports `libbiz`, `libbaz`, and `libbar`. You only want to trace
`libbiz` and `libbaz`:

`$ ./frida-drcov -w libbiz -w libbaz foo`

By default, it will create and write to `frida-drcov.log` in the current
working directory. You can change this with `-o`:

`$ ./frida-drcov -o more-coverage.log foo`
