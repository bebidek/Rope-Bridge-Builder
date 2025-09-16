#!/usr/bin/env python3
import sys, subprocess, resource, os.path
os.chdir(os.path.dirname(os.path.realpath(__file__)))

old_or_new = sys.argv[1]
assert old_or_new in ["old", "new"]

result = subprocess.run([f"./{old_or_new}_dummy", "1000000"], stdout=subprocess.DEVNULL)
assert result.returncode == 0
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
print(usage.ru_utime + usage.ru_stime)
