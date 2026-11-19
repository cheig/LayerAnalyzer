#!/usr/bin/env python3
"""Check the NIO-only Gradle launch boundary and finite capacity validation gate."""
import argparse
import os
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[3]
REMOVED_MODE = "layanalyzerSocksMode has been removed"
HIGH_CAPACITY = "Non-default SOCKS tiers require layanalyzerSocksCapacityValidation=true"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO / "build/nio-602-configuration")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    wrapper = REPO / ("gradlew.bat" if os.name == "nt" else "gradlew")
    # Run configuration only: none of these cases builds native code or needs a device.
    cases = [
        ("default", [], None),
        ("expanded-default-explicit", ["-PlayanalyzerSocksTcp=1024", "-PlayanalyzerSocksUdp=256",
                                       "-PlayanalyzerSocksAuth=128"], None),
        ("legacy-tier-explicit", ["-PlayanalyzerSocksTcp=64", "-PlayanalyzerSocksUdp=64",
                                  "-PlayanalyzerSocksAuth=64"], None),
        ("retired-blocking", ["-PlayanalyzerSocksMode=BLOCKING"], REMOVED_MODE),
        ("retired-nio-selector", ["-PlayanalyzerSocksMode=NIO"], REMOVED_MODE),
        ("retired-empty-selector", ["-PlayanalyzerSocksMode="], REMOVED_MODE),
        ("high-tcp-needs-validation", ["-PlayanalyzerSocksTcp=128"], HIGH_CAPACITY),
        ("high-udp-needs-validation", ["-PlayanalyzerSocksUdp=128"], HIGH_CAPACITY),
        ("mixed-auth-needs-validation", ["-PlayanalyzerSocksAuth=64"], HIGH_CAPACITY),
        ("finite-validation", ["-PlayanalyzerSocksTcp=1024", "-PlayanalyzerSocksUdp=256",
                               "-PlayanalyzerSocksAuth=128",
                               "-PlayanalyzerSocksCapacityValidation=true"], None),
        ("invalid-tcp", ["-PlayanalyzerSocksTcp=65", "-PlayanalyzerSocksCapacityValidation=true"],
         "Failed requirement"),
        ("invalid-udp", ["-PlayanalyzerSocksUdp=512", "-PlayanalyzerSocksCapacityValidation=true"],
         "Failed requirement"),
        ("invalid-auth", ["-PlayanalyzerSocksAuth=129", "-PlayanalyzerSocksCapacityValidation=true"],
         "Failed requirement"),
        ("validation-cannot-restore-blocking", ["-PlayanalyzerSocksMode=BLOCKING",
                                               "-PlayanalyzerSocksCapacityValidation=true"], REMOVED_MODE),
    ]
    failures = []
    for name, properties, expected_error in cases:
        result = subprocess.run([str(wrapper), ":app:help", "--console=plain",
                                 "-PlayanalyzerEnableTls=false", "-PlayanalyzerTlsProbe=false",
                                 *properties], cwd=REPO, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                timeout=180)
        (args.output / f"{name}.log").write_text(result.stdout, encoding="utf-8")
        passed = (result.returncode == 0 if expected_error is None else
                  result.returncode != 0 and expected_error in result.stdout)
        print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)
        if not passed:
            failures.append(name)
    if failures:
        raise SystemExit(f"Configuration checks failed: {', '.join(failures)}; see {args.output}")
    print(f"All {len(cases)} NIO configuration checks passed; logs: {args.output}")


if __name__ == "__main__":
    main()
