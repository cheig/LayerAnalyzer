#!/usr/bin/env python3
"""Required tests must actually run: failures, errors, skips and empty reports fail CI."""
import argparse
import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


def junit(directory):
    paths = sorted(Path(directory).rglob("TEST-*.xml"))
    tests = 0
    if not paths:
        raise ValueError("No required JUnit XML reports")
    for path in paths:
        root = ET.parse(path).getroot()
        suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
        if not suites:
            raise ValueError("No JUnit test suites: " + str(path))
        for suite in suites:
            count = int(suite.attrib.get("tests", 0))
            tests += count
            if count != len(list(suite.iter('testcase'))):
                raise ValueError('JUnit testcase count differs from declared tests: ' + str(path))
            if count == 0 or any(int(suite.attrib.get(k, 0)) for k in ("failures", "errors", "skipped", "disabled")):
                raise ValueError("Required JUnit suite empty/failed/errored/skipped: " + str(path))
            if any(next(suite.iter(tag), None) is not None for tag in ("skipped", "failure", "error")):
                raise ValueError("Required JUnit testcase failed/errored/skipped: " + str(path))
    return tests


def go_report(path):
    events = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    tests = 0
    packages = set()
    completed = set()
    no_test_output = set()
    for event in events:
        action = event.get("Action")
        if action == 'output' and '[no test files]' in event.get('Output', ''):
            no_test_output.add(event.get('Package'))
        if action == 'skip' and not event.get('Test') and event.get('Package') == 'com.layeranalyzer/tlsbridge/cmd/androidbridge' and event['Package'] in no_test_output:
            # This C ABI entry package has no Go tests. It is compiled by go test
            # and audited in both APK jobs; NOT a skipped required testcase.
            completed.add(event['Package'])
            continue
        if action in ("fail", "skip"):
            raise ValueError("Required Go test failed/skipped: " + str(event))
        if action == "start":
            packages.add(event["Package"])
        if action == "pass":
            if event.get("Test"):
                tests += 1
            else:
                completed.add(event["Package"])
    if not tests or not packages or packages != completed:
        raise ValueError("Missing/incomplete/empty required Go report")
    return tests


def required_unittest(directory, pattern="test_*.py", report=None):
    # Add only this suite's directory; tools and TLS verifier suites run separately.
    suite = unittest.defaultTestLoader.discover(str(directory), pattern=pattern)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({
            "tests": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "expectedFailures": len(result.expectedFailures),
            "unexpectedSuccesses": len(result.unexpectedSuccesses),
            "status": "PASS" if (result.wasSuccessful() and not result.skipped
                                  and not result.expectedFailures and result.testsRun) else "FAIL",
        }, indent=2) + "\n", encoding="utf-8")
    if not result.wasSuccessful() or result.skipped or result.expectedFailures or not result.testsRun:
        raise ValueError("Required Python suite failed/errored/skipped/expected-failure/empty")
    return result.testsRun


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("kind", choices=("unittest", "junit", "go"))
    p.add_argument("path", type=Path)
    p.add_argument("--report", type=Path, help="Write unittest counts, including failed runs")
    args = p.parse_args()
    if args.report and args.kind != "unittest":
        p.error("--report is currently supported only for unittest")
    count = (required_unittest(args.path, report=args.report) if args.kind == "unittest"
             else {"junit": junit, "go": go_report}[args.kind](args.path))
    print(f"PASS {args.kind}: {count} required tests, no failures/errors/skips")


if __name__ == "__main__":
    main()
