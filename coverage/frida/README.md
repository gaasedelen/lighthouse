# frida-drcov.py

A quick and dirty frida-based bb-tracer, with an emphasis on ease of use.

If your target is complex, you'll likely want to use a better, dedicated
tracing engine like drcov or a pin based tracer. This tracer has some
significant shortcomings, which are exagerated on larger or more complex
binaries:
* It is roughly two orders of magnitude slower than native execution
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

`$ ./frida-drcov.py <process name | pid>`

You can whitelist specific modules inside your target. Say you have binary
`foo` which imports `libbiz`, `libbaz`, and `libbar`. You only want to trace
`libbiz` and `libbaz`:

`$ ./frida-drcov.py -w libbiz -w libbaz foo`

By default, this script will trace all modules. This script will create and
write to  `frida-drcov.log` in the current working directory. You can change
this with `-o`:

`$ ./frida-drcov.py -o more-coverage.log foo`

For slightly more advanced usage, on multi-threaded applications, tracing all
threads can impose significant overhead, especially if you only care about
particular threads. For these cases you can filter based on thread id. Say you
have another tool which identifies interesting threads 543 and 678 inside your
target.

`$ ./frida-drcov.py -t 543 -t 678 foo`

Will only trace those threads. By default, all threads are traced.

## Example

```
$ sudo ./frida-drcov.py bb-bench
[+] Got module info
Starting to stalk threads...
Stalking thread 775
Done stalking threads.
[*] Now collecting info, control-D to terminate....
[*] Detatching, this might take a second... # ^d
[+] Detatched. Got 320 basic blocks.
[*] Formatting coverage and saving...
[!] Done
$ ls -lh frida-cov.log # this is the file you will load into lighthouse
-rw-r--r--  1 root  staff   7.2K 21 Oct 11:58 frida-cov.log
```
