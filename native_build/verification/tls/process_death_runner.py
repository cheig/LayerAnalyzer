"""TLS-403 host-driven termination with a live VPN and plaintext analysis lease.

Install the TLS ON / probe OFF debug and test APKs first. Uses only the explicitly
selected USB test device and the debug package verified in APK output metadata.
The HTTP fixture must already be running at --host (failure_device_fixture.py).
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid

from failure_matrix_runner import ROOT, debug_application_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--mode", choices=("force-stop", "crash"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    run_id = "death-" + uuid.uuid4().hex
    package = debug_application_id(ROOT / "app/build/outputs/apk/debug/output-metadata.json")
    adb = [args.adb, "-s", args.serial]
    external = f"/sdcard/Android/data/{package}/files/tls-403/{run_id}"

    def command(*parts, timeout=15):
        return subprocess.run(adb + list(parts), capture_output=True, text=True, timeout=timeout, check=True).stdout

    def instrument(method):
        return adb + ["shell", "am", "instrument", "-w", "-r", "-e", "class",
                      "com.example.layanalyzer.TlsDeviceRecoveryTest#" + method,
                      "-e", "hostGateway", args.host, "-e", "failureRunId", run_id,
                      package + ".test/androidx.test.runner.AndroidJUnitRunner"]

    def read_record(name):
        raw = command("exec-out", "cat", external + "/" + name + ".json")
        return json.loads(raw)

    process = None
    result = {"runId": run_id, "mode": args.mode, "package": package, "gatePassed": False}
    try:
        with (output / "arm.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen(instrument("armProcessDeath"), stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 55
            while True:
                try:
                    armed = read_record("armed")
                    break
                except (subprocess.SubprocessError, ValueError):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("Arming did not produce fresh live VPN/lease evidence")
                    time.sleep(0.25)
            result["armed"] = armed
            links = command("shell", "ip", "link", "show")
            if "tun0" not in links:
                raise RuntimeError("No live VPN at process termination")
            started = time.monotonic()
            if args.mode == "crash":
                command("shell", "am", "crash", package)
            else:
                command("shell", "am", "force-stop", package)
            while "tun0" in command("shell", "ip", "link", "show"):
                if time.monotonic() - started > 10:
                    raise RuntimeError("VPN route remained after process death")
                time.sleep(0.05)
            result["routeReleaseMillis"] = round((time.monotonic() - started) * 1000)
            process.wait(timeout=15)
            # Terminating instrumentation is expected here, never a passing test.
            result["armProcessExitCode"] = process.returncode
        command("shell", "am", "start", "-n", package + "/com.example.layanalyzer.MainActivity")
        # Let normal Application initialization perform orphan recovery before
        # launching the verification instrumentation in its new process.
        time.sleep(3)
        verified = subprocess.run(instrument("verifyProcessDeath"), capture_output=True, text=True, timeout=90)
        (output / "verify.log").write_text(verified.stdout + verified.stderr, encoding="utf-8")
        if verified.returncode != 0 or "OK (1 test)" not in verified.stdout or "FAILURES!!!" in verified.stdout:
            raise RuntimeError("Restart verification failed; see verify.log")
        result["restart"] = read_record("restart")
        if result["restart"]["previousPid"] != armed["pid"] or result["restart"]["pid"] == armed["pid"]:
            raise RuntimeError("Verification did not match the terminated process")
        result["gatePassed"] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            command("shell", "am", "force-stop", package)
            process.wait(timeout=15)
        (output / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "gatePassed": result["gatePassed"]}))
    return 0 if result["gatePassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
