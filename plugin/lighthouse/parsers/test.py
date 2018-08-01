from drcov import *

x = DrcovData(r"C:\Users\user\Desktop\jsc-debug-asan\drcov.jsc.99926.0000.proc.log")
blocks = x.filter_by_module("libJavaScriptCore.so")
print blocks
