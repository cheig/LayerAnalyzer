#!/usr/bin/env python3
"""TLS-007: audit actual bundled Wireshark exports, without claiming device execution."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REQUIRED = {
    "prefs_find_module", "prefs_find_preference", "prefs_pref_to_str", "prefs_set_pref", "prefs_apply",
    "get_follow_by_name", "get_follow_tap_string", "get_follow_tap_handler", "follow_reset_stream",
    "follow_info_free", "register_tap_listener", "remove_tap_listener", "get_data_source_name",
    "get_data_source_tvb", "tvb_captured_length", "tvb_memcpy", "find_dissector_table", "find_dissector",
    "dissector_get_uint_handle", "dissector_is_uint_changed", "dissector_change_uint", "dissector_reset_uint",
    "epan_new", "epan_free", "epan_dissect_run", "epan_dissect_run_with_taps",
}


def audit(libraries: Path, readelf: Path) -> dict:
    result = {"schemaVersion": 1, "deviceTestsExecuted": 0, "libraries": {}}
    for abi in ("arm64-v8a", "x86_64"):
        library = libraries / abi / "libwireshark.so"
        symbols = subprocess.run([str(readelf), "--dyn-syms", "--wide", str(library)],
                                 check=True, capture_output=True, text=True).stdout
        exports = {parts[7] for line in symbols.splitlines()
                   if len(parts := line.split()) >= 8 and parts[3:6] == ["FUNC", "GLOBAL", "DEFAULT"]
                   and parts[6] != "UND"}
        missing = REQUIRED - exports
        if missing:
            raise ValueError(f"{abi}: missing required exports: {sorted(missing)}")
        result["libraries"][abi] = {
            "sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            "requiredExports": sorted(REQUIRED),
            "privateTapQueueExports": sorted(exports & {"tap_queue_init", "tap_push_tapped_queue"}),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libraries", type=Path, default=Path("app/src/main/cpp/libs"))
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.libraries, args.readelf)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
