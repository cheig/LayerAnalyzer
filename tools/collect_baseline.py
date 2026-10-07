#!/usr/bin/env python3
"""Collect a LayerAnalyzer behavior/performance baseline from a device.

This script only gathers evidence; the operator drives the app UI. Run the
scenario you want to measure, then call this script to snapshot logcat
timing/cancel lines and pull the exportPerfResults debug output.

Usage:
  python tools/collect_baseline.py --label phase1_split --out-dir baselines
  python tools/collect_baseline.py --label phase1_split --out-dir baselines \
      --pull /data/data/com.layeranalyzer.android/files/perf_export
"""

import argparse
import datetime
import os
import subprocess
import sys

LOGTAG_ARGS = ["-s", "LayAnalyzer-JNI:V", "AndroidRuntime:E"]


def adb(*args):
    cmd = ["adb"] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"adb {' '.join(args)} failed: {result.stderr.strip()}",
              file=sys.stderr)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True,
                        help="short label, e.g. phase0_baseline or phase4_fastpath")
    parser.add_argument("--out-dir", default="baselines")
    parser.add_argument("--pull", metavar="DEVICE_DIR",
                        help="pull a directory written by exportPerfResults")
    parser.add_argument("--heap", action="store_true",
                        help="capture one 'dumpsys meminfo' native heap snapshot")
    args = parser.parse_args()

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(args.out_dir, f"{args.label}-{stamp}")
    os.makedirs(run_dir, exist_ok=True)

    logcat = adb("logcat", "-d", *LOGTAG_ARGS)
    with open(os.path.join(run_dir, "logcat.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(logcat)
    perf_lines = [ln for ln in logcat.splitlines()
                  if "[PERF-scan]" in ln or "[PERF-export]" in ln]
    with open(os.path.join(run_dir, "perf_scan.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(perf_lines) + "\n")
    print(f"logcat.txt / perf_scan.txt ({len(perf_lines)} PERF lines) -> {run_dir}")

    if args.heap:
        pkg = adb("shell", "pm", "list", "packages").strip().splitlines()
        pkg = [p.split(":")[1] for p in pkg if "layanalyzer" in p]
        if pkg:
            meminfo = adb("shell", "dumpsys", "meminfo", pkg[0])
            with open(os.path.join(run_dir, "meminfo.txt"), "w",
                      encoding="utf-8", newline="\n") as f:
                f.write(meminfo)
            print(f"meminfo.txt -> {run_dir}")

    if args.pull:
        target = os.path.join(run_dir, "perf_export")
        result = subprocess.run(["adb", "pull", args.pull, target],
                                capture_output=True, text=True)
        if result.returncode == 0:
            print(f"perf export -> {target}")
        else:
            print(f"pull failed: {result.stderr.strip()}", file=sys.stderr)

    # Rotate logcat so the next run only sees its own lines.
    adb("logcat", "-c")
    print("logcat cleared for the next run.")


if __name__ == "__main__":
    main()
