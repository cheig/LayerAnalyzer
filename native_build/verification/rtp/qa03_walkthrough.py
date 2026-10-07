#!/usr/bin/env python3
"""RTP4-QA-03 device walkthrough driver.

Drives the LayerAnalyzer UI over adb so the per-codec walkthrough
(playback / export / external open) is repeatable and its taps are
recorded rather than ad hoc.  Nothing here changes application source; it
only sends input events and reads the accessibility tree back.

The UI tree is read with `uiautomator dump` + `adb exec-out cat`, which
keeps the UTF-8 Chinese labels intact (uiautomator writes the dump in the
device's locale encoding, so it must be pulled byte-exact).

Requires: adb on PATH, a device with the debug build installed.

Examples
--------
    python qa03_walkthrough.py open --fixture sip_rtp_g729.pcap
    python qa03_walkthrough.py tap-desc "RTP 流"
    python qa03_walkthrough.py tap-text 播放
    python qa03_walkthrough.py shot --name player_g729_playing_light.png
    python qa03_walkthrough.py ls
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

APP_ID = "com.layeranalyzer.android"
ACTIVITY = "com.example.layanalyzer.MainActivity"
DEVICE_DIR = "/sdcard/Android/data/%s/files/rtp-qa" % APP_ID
DUMP_PATH = "/sdcard/qa03-ui.xml"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SHOT_DIR = os.path.join(REPO_ROOT, "build", "verification", "rtp", "screenshots")
FIXTURE_DIR = os.path.join(REPO_ROOT, "app", "src", "androidTest", "assets", "rtp")

SERIAL = os.environ.get("QA03_SERIAL")


def adb(*args, binary=False, check=True, timeout=30):
    cmd = ["adb"] + (["-s", SERIAL] if SERIAL else []) + list(args)
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        # `uiautomator dump` occasionally hangs on MIUI; make it recoverable.
        subprocess.run(["adb", "-s", SERIAL, "shell", "pkill", "-f", "uiautomator"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        raise
    if check and res.returncode != 0:
        sys.stderr.write(res.stdout.decode("utf-8", "replace") + "\n")
        raise SystemExit("adb %s failed" % (" ".join(args),))
    return res.stdout if binary else res.stdout.decode("utf-8", "replace")


def shell(cmd, **kw):
    return adb("shell", cmd, **kw)


def tap(x, y):
    shell("input tap %d %d" % (int(x), int(y)))


def tap_node(node):
    x1, y1, x2, y2 = node["bounds"]
    tap((x1 + x2) / 2, (y1 + y2) / 2)


def parse_bounds(value):
    inner = value.strip("[]")
    left, right = inner.split("][")
    x1, y1 = (int(v) for v in left.split(","))
    x2, y2 = (int(v) for v in right.split(","))
    return x1, y1, x2, y2


def tree():
    """Return the current accessibility tree as a list of node dicts."""
    raw = b""
    for attempt in range(4):
        try:
            # MIUI's uiautomator prints a stack trace and exits non-zero while still
            # writing a valid dump, so the exit code is not a failure signal here.
            adb("shell", "uiautomator dump %s" % DUMP_PATH, check=False, timeout=25)
            raw = adb("exec-out", "cat", DUMP_PATH, binary=True, timeout=25)
        except subprocess.TimeoutExpired:
            time.sleep(1.5)
            continue
        if raw.lstrip().startswith(b"<?xml"):
            break
        time.sleep(1.5)
    if not raw.lstrip().startswith(b"<?xml"):
        raise SystemExit("uiautomator dump did not produce a tree")
    root = ET.fromstring(raw.decode("utf-8"))
    nodes = []
    for n in root.iter("node"):
        nodes.append(
            {
                "text": n.get("text") or "",
                "desc": n.get("content-desc") or "",
                "cls": n.get("class") or "",
                "clickable": n.get("clickable") == "true",
                "bounds": parse_bounds(n.get("bounds")),
            }
        )
    return nodes


def find(nodes, text=None, desc=None):
    found = []
    for n in nodes:
        if text is not None and n["text"] != text:
            continue
        if desc is not None and n["desc"] != desc:
            continue
        found.append(n)
    return found


def require(nodes, text=None, desc=None):
    found = find(nodes, text=text, desc=desc)
    if not found:
        raise SystemExit("no node with %s" % (("text=%r" % text) if text else ("desc=%r" % desc),))
    return found[0]


def require_nth(nodes, index, text=None, desc=None):
    """Like [require] but for lists with one entry per row (stream action buttons)."""
    found = find(nodes, text=text, desc=desc)
    if len(found) <= index:
        raise SystemExit("only %d node(s) with %s, wanted #%d"
                         % (len(found), (("text=%r" % text) if text else ("desc=%r" % desc)), index))
    return found[index]


def wait_for(text=None, desc=None, timeout=25.0, interval=1.0):
    deadline = time.time() + timeout
    last = []
    while time.time() < deadline:
        last = tree()
        if find(last, text=text, desc=desc):
            return last
        time.sleep(interval)
    raise SystemExit(
        "timed out waiting for %s (visible: %s)"
        % ((("text=%r" % text) if text else ("desc=%r" % desc)), [n["text"] for n in last if n["text"]][:12])
    )


def shot(name, subdir=None):
    out_dir = SHOT_DIR if subdir is None else os.path.join(SHOT_DIR, subdir)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "wb") as fh:
        fh.write(adb("exec-out", "screencap", "-p", binary=True))
    print("shot %s" % (path,))
    return path


def cmd_open(args):
    local = os.path.join(FIXTURE_DIR, args.fixture)
    if not os.path.exists(local):
        raise SystemExit("fixture not found: %s" % (local,))
    shell("mkdir -p %s" % DEVICE_DIR)
    adb("push", local, DEVICE_DIR + "/")
    remote = "%s/%s" % (DEVICE_DIR, args.fixture)
    shell("am force-stop %s" % APP_ID)
    shell(
        'am start -a android.intent.action.VIEW -d "file://%s" -t application/octet-stream -n %s/%s'
        % (remote, APP_ID, ACTIVITY)
    )
    if args.settle > 0:
        time.sleep(args.settle)


def cmd_tap_text(args):
    tap_node(require(tree(), text=args.value))
    time.sleep(args.settle)


def cmd_tap_desc(args):
    tap_node(require(tree(), desc=args.value))
    time.sleep(args.settle)


def cmd_tap_xy(args):
    tap(args.x, args.y)
    time.sleep(args.settle)


def cmd_shot(args):
    shot(args.name)


def cmd_ls(args):
    for n in tree():
        if n["text"] or n["desc"]:
            print("%-28s %-16s %s %r %r" % (n["cls"], n["bounds"], "C" if n["clickable"] else "-", n["text"], n["desc"]))


def exported_files():
    out = adb("shell", "ls -l /sdcard/Download/")
    rows = {}
    for line in out.splitlines():
        # `ls -l` gives mode links owner group size date time name; the name may
        # contain spaces (SAF writes `... (1).wav`), so split only the first 7 fields.
        parts = line.split(None, 7)
        if len(parts) == 8 and parts[7].startswith("rtp_"):
            rows[parts[7]] = int(parts[4])
    return rows


def tap_retry(tap_fn, timeout=20.0, interval=1.5, **want):
    """Tap, then wait for a node to appear; retry the tap until it does."""
    deadline = time.time() + timeout
    while True:
        tap_fn()
        end = min(deadline, time.time() + 8.0)
        while time.time() < end:
            nodes = tree()
            if find(nodes, **want):
                return nodes
            time.sleep(interval)
        if time.time() >= deadline:
            raise SystemExit("gave up waiting for %s" % (want,))


def cmd_pass(args):
    """One codec's walkthrough: playback, export formats, external open."""
    before = exported_files()

    args.settle = args.open_settle
    cmd_open(args)
    time.sleep(0)
    tap_retry(lambda: tap_node(require(tree(), desc="更多文件操作")), text="RTP 流")
    tap_node(require(tree(), text="RTP 流"))
    time.sleep(5.0)
    shot("rtp_streams_%s_light.png" % args.codec)

    # playback
    tap_node(require_nth(tree(), args.stream_index, desc="流操作"))
    time.sleep(2.0)
    tap_node(require(tree(), text="播放"))
    time.sleep(args.play_settle)
    shot("player_%s_playing_light.png" % args.codec)
    time.sleep(8.0)

    if args.formats:
        tap_node(require(tree(), desc="返回"))
        time.sleep(3.0)
        tap_node(require_nth(tree(), args.stream_index, desc="流操作"))
        time.sleep(2.0)
        tap_node(require(tree(), text="导出格式…"))
        time.sleep(2.5)
        shot("export_formats_%s_light.png" % args.codec)

        for index, label in enumerate(args.formats):
            if index > 0:
                tap_node(require_nth(tree(), args.stream_index, desc="流操作"))
                time.sleep(2.0)
                tap_node(require(tree(), text="导出格式…"))
                time.sleep(2.5)
            tap_node(require(tree(), text=label))
            time.sleep(6.0)
            tap_node(require(tree(), text="保存"))
            time.sleep(7.0)

        after = exported_files()
        for name, size in sorted(after.items()):
            if name not in before:
                print("EXPORTED %s %d" % (name, size))

    if args.external:
        tap_node(require_nth(tree(), args.stream_index, desc="流操作"))
        time.sleep(2.0)
        tap_node(require(tree(), text="播放"))
        time.sleep(8.0)
        tap_node(require(tree(), desc="使用外部播放器打开"))
        time.sleep(6.0)
        shot("external_open_%s_chooser_light.png" % args.codec)
        for n in tree():
            if n["text"]:
                print("CHOOSER %r" % (n["text"],))


def cmd_key(args):
    shell("input keyevent %s" % args.code)
    time.sleep(args.settle)


def main():
    global SERIAL
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--serial", default=SERIAL)
    sub = p.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("open", help="push a fixture and open it through ACTION_VIEW")
    o.add_argument("--fixture", required=True)
    o.add_argument("--settle", type=float, default=18.0)
    o.set_defaults(func=cmd_open)

    t = sub.add_parser("tap-text", help="tap the node whose text matches exactly")
    t.add_argument("value")
    t.add_argument("--settle", type=float, default=2.0)
    t.set_defaults(func=cmd_tap_text)

    d = sub.add_parser("tap-desc", help="tap the node whose content-desc matches exactly")
    d.add_argument("value")
    d.add_argument("--settle", type=float, default=2.0)
    d.set_defaults(func=cmd_tap_desc)

    x = sub.add_parser("tap-xy", help="tap raw display coordinates")
    x.add_argument("x", type=int)
    x.add_argument("y", type=int)
    x.add_argument("--settle", type=float, default=2.0)
    x.set_defaults(func=cmd_tap_xy)

    s = sub.add_parser("shot", help="capture a screenshot into the evidence directory")
    s.add_argument("--name", required=True)
    s.set_defaults(func=cmd_shot)

    k = sub.add_parser("key", help="send a keyevent")
    k.add_argument("code")
    k.add_argument("--settle", type=float, default=2.0)
    k.set_defaults(func=cmd_key)

    ps = sub.add_parser("pass", help="full per-codec walkthrough: playback, export, external open")
    ps.add_argument("--fixture", required=True)
    ps.add_argument("--codec", required=True)
    ps.add_argument("--formats", default="", help="comma separated export-format labels to exercise")
    ps.add_argument("--open-settle", type=float, default=18.0)
    ps.add_argument("--play-settle", type=float, default=2.2)
    ps.add_argument("--external", action="store_true")
    ps.add_argument("--stream-index", type=int, default=0, help="which stream row's action button to use (0-based)")
    ps.set_defaults(func=cmd_pass, settle=0.0)

    l = sub.add_parser("ls", help="print the current tree")
    l.set_defaults(func=cmd_ls)

    args = p.parse_args()
    SERIAL = args.serial
    if getattr(args, "formats", None):
        args.formats = [f for f in args.formats.split(",") if f]
    args.func(args)


if __name__ == "__main__":
    main()
