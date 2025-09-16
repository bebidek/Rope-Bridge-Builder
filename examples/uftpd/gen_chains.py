#!/usr/bin/env python3
import multiprocessing.connection
import subprocess, sys, multiprocessing, signal, random, os, os.path, time, tftpy
os.chdir(os.path.dirname(os.path.realpath(__file__)))

NUMBER_OF_REQUESTS = 100
FILE_SIZE = 10000
SAMPLE_FILES_DIR = '/dev/shm'
TFTP_PORT = 40128


# generate random sample file
with open(f'{SAMPLE_FILES_DIR}/the_file', 'wb') as f:
    f.write(random.randbytes(FILE_SIZE))


# start UFTPD server
def subprocess_func(pipe: multiprocessing.connection.Connection):
    try: 
        server = None
        server = subprocess.Popen([
            '../../valgrind/output/bin/valgrind',
            '--tool=syscall_tracker',
            '--pos-file=nodes.txt',
            '--out-file=chains.txt',
            '--seg-len=1024',
            './new_uftpd_raw', '-n', SAMPLE_FILES_DIR, '-l', 'none', '-o', f'tftp={TFTP_PORT}'
            ], preexec_fn=os.setpgrp)

        time.sleep(0.2)
        pipe.send(server.pid) # signal server ready to start
        assert server.wait() == 0

    except:
        print("Killing server process abnormally", file=sys.stderr)
        pipe.close()
        if server is not None:
            os.killpg(server.pid, signal.SIGKILL)
            os.remove("chains.txt")
        sys.exit(1)

pipe_parent, pipe_child = multiprocessing.Pipe()
server_process = multiprocessing.Process(target=subprocess_func, args=(pipe_child,))
server_process.start()


try:
    server_pid = pipe_parent.recv()

    # run TFTP client multiple times
    client = tftpy.TftpClient("127.0.0.1", port=TFTP_PORT)
    for _ in range(NUMBER_OF_REQUESTS):
        print("Running...", file=sys.stderr)
        # result = subprocess.run(['curl', '-s', '-o', f'{SAMPLE_FILES_DIR}/recv_file', f'tftp://127.0.0.1:{TFTP_PORT}/the_file'], timeout=1)
        # assert result.returncode == 0
        client.download('the_file', f'{SAMPLE_FILES_DIR}/recv_file')

    # kill the server
    os.killpg(server_pid, signal.SIGINT)
    server_process.join()

except:
    print("Killing main process abnormally", file=sys.stderr)
    os.killpg(server_pid, signal.SIGKILL)
    sys.exit(1)
