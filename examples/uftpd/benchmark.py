#!/usr/bin/env python3
import multiprocessing.connection
import subprocess, sys, multiprocessing, signal, resource, random, os, os.path, time, tftpy
os.chdir(os.path.dirname(os.path.realpath(__file__)))

NUMBER_OF_REQUESTS = 4096
FILE_SIZE = 30000
SAMPLE_FILES_DIR = '/dev/shm'
TFTP_PORT = 40128

old_or_new=sys.argv[1]
assert old_or_new in ["old", "new"]
custom_env = os.environ
# if old_or_new == "new":
#    custom_env["GLIBC_TUNABLES"] = "glibc.cpu.hwcaps=Prefer_ERMS"


# generate random sample file
with open(f'{SAMPLE_FILES_DIR}/the_file', 'wb') as f:
    f.write(random.randbytes(FILE_SIZE))


# start UFTPD server
def subprocess_func(pipe: multiprocessing.connection.Connection):
    try: 
        server = None
        server = subprocess.Popen([f'./{old_or_new}_uftpd', '-n', SAMPLE_FILES_DIR, '-l', 'none', '-o', f'tftp={TFTP_PORT}'], preexec_fn=os.setpgrp, env=custom_env)

        time.sleep(0.5)
        pipe.send(server.pid) # signal server ready to start
        assert server.wait() == 0

        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        pipe.send(float(usage.ru_stime + usage.ru_utime))
    except:
        print("Killing server abnormally", file=sys.stderr)
        pipe.close()
        if server is not None:
            os.killpg(server.pid, signal.SIGKILL)
            server.kill()
        sys.exit(1)

pipe_parent, pipe_child = multiprocessing.Pipe()
server_process = multiprocessing.Process(target=subprocess_func, args=(pipe_child,))
server_process.start()


try:
    server_pid = pipe_parent.recv()

    # run TFTP client multiple times
    client = tftpy.TftpClient("127.0.0.1", port=TFTP_PORT)
    for _ in range(NUMBER_OF_REQUESTS):
        # result = subprocess.run(['curl', '-s', '-o', f'{SAMPLE_FILES_DIR}/recv_file', f'tftp://127.0.0.1:{TFTP_PORT}/the_file'], timeout=1)
        # assert result.returncode == 0
        client.download('the_file', f'{SAMPLE_FILES_DIR}/recv_file')

    # get the time and kill the server
    os.killpg(server_pid, signal.SIGINT)
    result_time = pipe_parent.recv()
    server_process.join()
    print(result_time)
except:
    print("Killing main process abnormally", file=sys.stderr)
    os.killpg(server_pid, signal.SIGKILL)
    sys.exit(1)
