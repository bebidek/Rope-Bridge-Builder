#!/usr/bin/env python3
import matplotlib.pyplot as plt
import csv, sys, statistics
plt.xkcd()

csv_path = sys.argv[1]
x_range = (float(sys.argv[2]), float(sys.argv[3])) if len(sys.argv)>=4 else None

with open(csv_path, 'r') as csv_file:
    reader = csv.reader(csv_file)
    avgs = []
    for row, description in zip(reader, ["Stare", "Nowe"]):
        times = [float(x) for x in row]
        avgs.append(statistics.mean(times))
        print(f"{description}: avg = {statistics.mean(times):.2f},  stdev = {statistics.stdev(times):.2f}")
        plt.hist(times, alpha=0.6, edgecolor='black', label=description)
    print(f"Estimated speedup = {(1-avgs[1]/avgs[0])*100:.1f}%")
    plt.xlabel("czas [s]")
    if x_range is not None:
        plt.xlim(x_range)
    plt.title(csv_path)
    plt.legend()
    plt.show()