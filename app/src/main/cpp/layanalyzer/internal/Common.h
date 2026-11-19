// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Common include context shared by every LayerAnalyzer native module.
//
// This header defines inline functions (dump_json / dump_json_pretty), so it
// needs a guard: several translation units (EngineLifecycle.cpp,
// PacketListJni.cpp, ...) reach it twice through EngineState.h plus their own
// direct include, and a second definition inside one translation unit is a
// hard error even for inline functions.
#pragma once

// Each module translation unit includes this header instead of repeating the
// Wireshark/GLib/JNI include block that used to open native-lib.cpp.  The
// include order matches the former single-translation-unit build so the
// module split itself stays behaviour-neutral.  Cross-module declarations
// live in the per-module headers (EngineRuntime.h, SessionRegistry.h,
// CaptureSession.h, FieldReader.h, SummaryProjector.h, ...).
#include <android/log.h>
#include <glib.h>
#include <jni.h>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <limits>
#include <list>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <tuple>
#include <thread>
#include <unordered_map>
#include <vector>

using json = nlohmann::json;

/**
 * Serializes a result envelope for the JNI boundary.
 *
 * Packet payloads, HTTP header values and reassembled stream text are arbitrary
 * bytes: a GBK/Shift-JIS body or a binary field is not valid UTF-8, and
 * nlohmann's dump() throws type_error.316 for it. Inside a JNI function that
 * exception has no Kotlin frame to unwind into, so the process aborts
 * (SIGABRT / "terminating due to uncaught exception"). Replacing an undecodable
 * byte with U+FFFD keeps the rest of the envelope, which is always the better
 * trade than losing the capture session the user is looking at.
 *
 * Use this for every string returned to Kotlin; plain dump() is only safe for
 * envelopes built exclusively from numbers and fixed ASCII labels.
 */
inline std::string dump_json(const json& value) {
  return value.dump(-1, ' ', false, json::error_handler_t::replace);
}

/**
 * Two-space indented variant of dump_json, for exported report files.
 *
 * The file exports (expert.json, statistics.json, http_objects.json) carry the
 * same arbitrary header/protocol text as the JNI envelopes, but they are
 * written from inside a JNI entry point with no enclosing try/catch, so one
 * undecodable byte would abort the process instead of failing the export.
 * Keeps dump(2) formatting so the on-disk shape is unchanged.
 */
inline std::string dump_json_pretty(const json& value) {
  return value.dump(2, ' ', false, json::error_handler_t::replace);
}

// Wireshark headers
#include <ares.h>
#include <epan/addr_resolv.h>
#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/dfilter/dfilter.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/export_object.h>
#include <epan/ftypes/ftypes.h>
#include <epan/guid-utils.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <epan/tvbuff.h>
#include <epan/wmem_scopes.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/wmem/wmem.h>
#include <wsutil/wslog.h>
#include "layanalyzer/projection/ByteFormatter.h"
#include "layanalyzer/export/PcapWriter.h"

using layanalyzer::projection::bytes_to_ascii;
using layanalyzer::projection::bytes_to_hex;
using layanalyzer::projection::bytes_to_utf8_text;
using layanalyzer::exporter::link_type_for_encapsulation;
using layanalyzer::exporter::write_le16;
using layanalyzer::exporter::write_le32;

#define TAG "LayAnalyzer-JNI"
#define LOGI(...) __android_log_print(4, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(5, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(6, TAG, __VA_ARGS__)

// [PERF-scan] 观测性打点（T0 基线任务，不改功能行为）。
// 由 CMake 仅在 Debug 构建定义 LA_PERF_SCAN=1；Release 下宏为空、
// 计时代码整体被编译期消除。
// 打点格式统一为 "[PERF-scan] <op> key=value ..."，便于 grep 一键清理。
#ifdef LA_PERF_SCAN
#define PERF_SCAN_START() \
  auto __perf_t0 = std::chrono::steady_clock::now()
#define PERF_SCAN_LOG(...)                                                   \
  do {                                                                       \
    const long long __perf_ms =                                              \
        std::chrono::duration_cast<std::chrono::milliseconds>(               \
            std::chrono::steady_clock::now() - __perf_t0)                    \
            .count();                                                        \
    LOGI("[PERF-scan] " __VA_ARGS__);                                        \
  } while (0)
#else
#define PERF_SCAN_START()
#define PERF_SCAN_LOG(...) \
  do {                     \
  } while (0)
#endif
