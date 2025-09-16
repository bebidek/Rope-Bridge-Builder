#!/usr/bin/env python3
import subprocess, sys, statistics, csv
from pathlib import Path

WARMUP = 2

test_object = sys.argv[1]
iterations = int(sys.argv[2])
csv_output_path = sys.argv[3] if len(sys.argv)>=4 else None

scripts_path = Path(__file__).resolve().parent
example_path = scripts_path.parent / "examples" / test_object


# load blob to kernel
result = subprocess.run([scripts_path / "loader.py", example_path / f"new_{test_object}"])
assert result.returncode == 0


# run benchmark for old and new versions alternately
old_times, new_times = [], []
for i in range(iterations + WARMUP):
    for old_or_new, times_array in zip(["old", "new"], [old_times, new_times]):
        if i < WARMUP:
            print(f"Warmup iteration #{i}:{old_or_new}... ", end='', file=sys.stderr)
        else:
            print(f"Iteration #{i-WARMUP}:{old_or_new}...  ", end='', file=sys.stderr)
        sys.stderr.flush()
        result = subprocess.run([example_path / "benchmark.py", old_or_new], stdout=subprocess.PIPE)
        assert result.returncode == 0
        time = float(result.stdout)
        if i >= WARMUP:
            times_array.append(time)
        print(f"{time:.2f}", file=sys.stderr)


# summarize the reults
old_avg, old_std = statistics.mean(old_times), statistics.stdev(old_times) if len(old_times)>1 else 0
new_avg, new_std = statistics.mean(new_times), statistics.stdev(new_times) if len(new_times)>1 else 0
print(f"Mean old time = {old_avg:.2f} (std = {old_std:.2f})", file=sys.stderr)
print(f"Mean new time = {new_avg:.2f} (std = {new_std:.2f})", file=sys.stderr)
print(f"Estimated performance gain = {(1 - (new_avg / old_avg)) * 100:.2f} %", file=sys.stderr)


# output CSV
if csv_output_path is not None:
    with open(csv_output_path, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(old_times)
        csv_writer.writerow(new_times)
