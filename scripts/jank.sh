#!/usr/bin/env bash
# jank.sh —— 滑动流畅度基线测量（T0 交付物 b）
#
# 对已打开目标抓包的 App 做 12 次上滑 + 12 次下滑，然后解析 gfxinfo 输出
# Janky% / 50th / 90th / 95th / 99th / Slow UI thread。
#
# 用法:
#   scripts/jank.sh [包名]          # 默认 com.layeranalyzer.android
#   scripts/jank.sh com.layeranalyzer.android 1080 2400   # 显式给屏幕分辨率
#
# 前置条件:
#   - App 已在前台并打开目标抓包（PacketListScreen 可见）。
#   - 为排除 JIT 解释执行干扰，先做一次大规模滑动预热（--warmup-only 可单独跑预热）。
#
# Windows Git Bash 注意: 脚本已内置 MSYS_NO_PATHCONV，避免 adb 参数被路径转换。
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

PKG="${1:-com.layeranalyzer.android}"
W="${2:-}"
H="${3:-}"
WARMUP_ONLY=0
if [ "${1:-}" = "--warmup-only" ]; then
  WARMUP_ONLY=1
  PKG="${2:-com.layeranalyzer.android}"
fi

if [ -z "$W" ] || [ -z "$H" ]; then
  SIZE_LINE="$(adb shell wm size | tr -d '\r' | tail -n1)"
  # 形如 "Physical size: 1080x2400"
  RES="$(echo "$SIZE_LINE" | grep -oE '[0-9]+x[0-9]+' | tail -n1)"
  W="${RES%x*}"
  H="${RES#*x}"
fi
if [ -z "$W" ] || [ -z "$H" ]; then
  echo "无法获取屏幕分辨率，请显式传入: scripts/jank.sh <pkg> <宽> <高>" >&2
  exit 1
fi

X=$(( W / 2 ))
Y_LOW=$(( H * 79 / 100 ))   # 靠近底部
Y_HIGH=$(( H * 29 / 100 ))  # 靠近顶部

swipe_series() {
  local from_y="$1" to_y="$2" count="$3"
  local i
  for i in $(seq 1 "$count"); do
    adb shell input swipe "$X" "$from_y" "$X" "$to_y" 120 >/dev/null
    sleep 0.35
  done
}

echo "== jank.sh: pkg=$PKG 屏幕 ${W}x${H} 滑动坐标 x=$X y=[$Y_LOW <-> $Y_HIGH] =="

# JIT 预热：先大幅来回滚动两轮（不计入统计）
echo "-- 预热（2×8 次滑动）..."
swipe_series "$Y_LOW" "$Y_HIGH" 8
swipe_series "$Y_HIGH" "$Y_LOW" 8

if [ "$WARMUP_ONLY" = "1" ]; then
  echo "预热完成。"
  exit 0
fi

adb shell dumpsys gfxinfo "$PKG" reset >/dev/null
adb logcat -c 2>/dev/null || true

echo "-- 正式测量（12 上滑 + 12 下滑）..."
swipe_series "$Y_LOW" "$Y_HIGH" 12
swipe_series "$Y_HIGH" "$Y_LOW" 12

GFX="$(adb shell dumpsys gfxinfo "$PKG")"

# 提取关键指标。gfxinfo 输出格式（Android 11+）示例：
#   Janky frames: 123 (12.34%)
#   50th percentile: 8ms
#   90th percentile: 16ms
#   95th percentile: 24ms
#   99th percentile: 48ms
#   Number Slow UI thread: 12
extract() { echo "$GFX" | grep -E "$1" | tail -n1 | sed 's/^[[:space:]]*//'; }

echo
echo "== gfxinfo 关键指标 =="
echo "$(extract 'Janky frames:')"
echo "$(extract '50th percentile:')"
echo "$(extract '90th percentile:')"
echo "$(extract '95th percentile:')"
echo "$(extract '99th percentile:')"
echo "$(extract 'Number Slow UI thread:')"
echo "$(extract 'Number Slow draw:')"
echo
echo "完整输出已省略；如需原始数据请手动执行: adb shell dumpsys gfxinfo $PKG"
