#!/usr/bin/env python3
import subprocess, sys, sys, resource, os, os.path, shutil
os.chdir(os.path.dirname(os.path.realpath(__file__)))
TEMPDIR = '/dev/shm'

old_or_new=sys.argv[1]
assert old_or_new in ["old", "new"]
custom_env = os.environ

#if old_or_new == "new":
#    custom_env["GLIBC_TUNABLES"] = "glibc.cpu.hwcaps=Prefer_ERMS"

os.symlink(f'{old_or_new}_busybox', 'busybox')
try:
    result = subprocess.run(['./busybox', 'tar', 'xf', '../../linux-6.10.tar', '-C', f'{TEMPDIR}'], env=custom_env)
    assert result.returncode == 0
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    print(usage.ru_utime + usage.ru_stime)
except:
    print(f"Process terminated abnormally", file=sys.stderr)
finally:
    # shutil.rmtree(f"{TEMPDIR}/linux-6.10", ignore_errors=True)
    os.unlink('busybox')
