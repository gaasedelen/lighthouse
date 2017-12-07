# frida-drcov.py

In this folder you will find the code coverage collection script `frida-drcov.py` that run ontop of the [Frida](https://www.frida.re/) DBI toolkit. This script will produce code coverage (using Frida) in a log format compatible with [Lighthouse](https://github.com/gaasedelen/lighthouse).

Frida is best supported on mobile platforms such as iOS or Android, claiming some support for Windows, MacOS, Linux, and QNX. Practically speaking, `frida-drcov.py` should only be used for collecting coverage data on mobile applications.

This script is labeled only as a prototype.

## Install

To use `frida-drcov.py`, you must have [Frida](https://www.frida.re/) installed. This can be done via python's `pip`:

```
sudo pip install frida
```

## Usage

Once frida is installed, the `frida-drcov.py` script in this repo can be used to collect coverage against a running process as demonstrated below. By default, the code coverage data will be written to the file `frida-drcov.log` at the end of execution.

```
python frida-drcov.py <process name | pid>
```

Here is an example of us instrumenting the running process `bb-bench`.

```
$ sudo python frida-drcov.py bb-bench
[+] Got module info
Starting to stalk threads...
Stalking thread 775
Done stalking threads.
[*] Now collecting info, control-D to terminate....
[*] Detaching, this might take a second... # ^d
[+] Detached. Got 320 basic blocks.
[*] Formatting coverage and saving...
[!] Done
$ ls -lh frida-cov.log # this is the file you will load into lighthouse
-rw-r--r--  1 root  staff   7.2K 21 Oct 11:58 frida-cov.log
```

Using the `-o` flag, one can specify a custom name/location for the coverage log file:

```
python frida-drcov.py -o more-coverage.log foo
```

## Module Whitelisting

One can whitelist specific modules inside the target process. Say you have binary `foo` which imports the libraries `libfoo`, `libbar`, and `libbaz`. Using the `-w` flag (whitelist) on the command line, we can explicitly target modules of interest:

```
$ python frida-drcov.py -w libfoo -w libbaz foo
```

This will reduce the amount of information collected and improve performance. If no `-w` arguments are supplied, `frida-drcov.py` will trace all loaded images.

## Thread Targeting

On multi-threaded applications, tracing all threads can impose significant overhead. For these cases you can filter coverage collection based on thread id if you only care about specific threads.

In the following example, we target thread id `543`, and `678` running in the process named `foo`.

```
python frida-drcov.py -t 543 -t 678 foo
```

Without the `-t` flag, all threads that exist in the process at the time of attach will be traced.

# Authors

* yrp ([@yrp604](https://twitter.com/yrp604))
