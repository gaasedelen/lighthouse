import os
import binaryninja

target = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "testcase",
    "boombox.exe"
))

print "Opening '%s' headlessly..." % target
x = binaryninja.BinaryViewType["PE"].open(target)
x.update_analysis_and_wait()
print "DONE!"
