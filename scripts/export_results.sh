#!/usr/bin/env bash
# export_results.sh —— G4 对拍结果导出（T0 交付物 d）
#
# 对同一抓包触发 App 内的 [PERF-export] 通道（仅 Debug 构建），把过滤/搜索/
# 统计/Expert/Follow Stream/HTTP 对象/可见帧 pcap 结果落盘，供改动前后 diff。
#
# 用法:
#   scripts/export_results.sh <轮次标签> <pcap路径> [帧数提示]
#   例:
#     scripts/export_results.sh baseline jank50k.pcap          # 第一次（改动前）
#     scripts/export_results.sh after    jank50k.pcap          # 第二次（改动后）
#     diff -r perf_results/baseline/jank50k perf_results/after/jank50k   # 对拍
#
# 流程:
#   1. adb push pcap 到 /data/local/tmp/
#   2. run-as 拷入 files/captures/ 并覆写 shared_prefs/active_session.xml
#   3. am start 带 --es perf_export <标签>，App 自动恢复会话并导出
#   4. 等待 logcat 出现 [PERF-export] DONE，再 run-as pull 结果回本机
#
# Windows Git Bash 注意: 脚本已内置 MSYS_NO_PATHCONV，避免 adb 参数被路径转换。
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

PKG="com.layeranalyzer.android"
TAG_NAME="${1:-}"
PCAP="${2:-}"
if [ -z "$TAG_NAME" ] || [ -z "$PCAP" ]; then
  echo "用法: scripts/export_results.sh <轮次标签> <pcap路径>" >&2
  exit 2
fi
if [ ! -f "$PCAP" ]; then
  echo "pcap 不存在: $PCAP" >&2
  exit 2
fi

BASE="$(basename "$PCAP")"
STEM="${BASE%.*}"
SIZE="$(stat -c%s "$PCAP" 2>/dev/null || stat -f%z "$PCAP")"
DEVICE_TMP="/data/local/tmp/$BASE"
DEVICE_CAPTURE="files/captures/$BASE"
OUT_LOCAL="perf_results/$TAG_NAME/$STEM"

echo "== export_results: tag=$TAG_NAME pcap=$PCAP ($SIZE bytes) =="

# 1) 推到设备临时目录
adb push "$PCAP" "$DEVICE_TMP" >/dev/null

# 2) 拷入应用私有目录并预制 active_session，让 App 启动时恢复该会话
run-as "$PKG" sh -c "mkdir -p files/captures && cp '$DEVICE_TMP' '$DEVICE_CAPTURE'"
# 写 active_session.xml（注意 XML 转义：路径里一般无特殊字符，直接写入）。
# 用 base64 传输避免 shell 引号/转义在 Windows Git Bash 下出问题。
DEVICE_PATH="/data/data/$PKG/$DEVICE_CAPTURE"
PREFS_B64="$(printf '%s' "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name=\"path\">$DEVICE_PATH</string>
    <string name=\"displayName\">$BASE</string>
    <long name=\"sizeBytes\" value=\"$SIZE\" />
</map>" | base64 -w0)"
run-as "$PKG" sh -c "mkdir -p shared_prefs && echo '$PREFS_B64' | base64 -d > shared_prefs/active_session.xml"

# 3) 冷启动 App 并触发导出
adb shell am force-stop "$PKG"
adb logcat -c
adb shell am start -n "$PKG/.MainActivity" --es perf_export "$TAG_NAME/$STEM" >/dev/null

# 4) 等待 [PERF-export] DONE / FAILED（最多 10 分钟）
# 说明：DONE/FAILED 由 MainActivity 打在 logcat 的 LayAnalyzer tag 上。
echo "-- 等待导出完成（logcat 过滤 [PERF-export]）..."
DEADLINE=$(( $(date +%s) + 600 ))
STATUS=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  LINE="$(adb logcat -d -s LayAnalyzer 2>/dev/null | grep 'PERF-export' | tail -n1 || true)"
  case "$LINE" in
    *" DONE"*) STATUS="done"; break ;;
    *FAILED*)  STATUS="failed"; break ;;
  esac
  sleep 3
done

if [ "$STATUS" != "done" ]; then
  echo "导出未完成（状态: ${STATUS:-超时}）。最后日志:" >&2
  adb logcat -d -s LayAnalyzer 2>/dev/null | grep 'PERF' | tail -n10 >&2 || true
  exit 1
fi
echo "-- 导出完成，拉取结果..."

# 5) 拉回结果（run-as 读的目录在应用私有区，adb pull 无法直取；
#    先通过 run-as 打包到 /data/local/tmp（shell 可读），再 adb pull）
rm -rf "$OUT_LOCAL"
mkdir -p "$OUT_LOCAL"
DEVICE_EXPORT_DIR="files/perf_export/$TAG_NAME/$STEM"
TAR_NAME="perf_export_$STEM.tar"
adb shell rm -f "/data/local/tmp/$TAR_NAME"
run-as "$PKG" sh -c "cd '$DEVICE_EXPORT_DIR' && tar -cf '/data/local/tmp/$TAR_NAME' ."
adb shell chmod 644 "/data/local/tmp/$TAR_NAME"
adb pull "/data/local/tmp/$TAR_NAME" "$OUT_LOCAL/$TAR_NAME" >/dev/null
tar -xf "$OUT_LOCAL/$TAR_NAME" -C "$OUT_LOCAL"
rm -f "$OUT_LOCAL/$TAR_NAME"
adb shell rm -f "/data/local/tmp/$TAR_NAME"

echo "== 完成: $OUT_LOCAL =="
ls -la "$OUT_LOCAL"
echo
echo "对拍: diff -r perf_results/baseline/$STEM perf_results/after/$STEM"
