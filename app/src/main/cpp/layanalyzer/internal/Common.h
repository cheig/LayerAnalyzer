// Common include context shared by every LayerAnalyzer native module.
//
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
