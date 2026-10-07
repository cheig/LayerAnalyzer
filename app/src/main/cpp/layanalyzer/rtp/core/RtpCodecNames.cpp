// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// RTP 编码名规范化（RTP1-NAT-06）—— 见 RtpCodecNames.h 顶部说明。
//
// 表内容逐字照抄 model/RtpCodecCatalog.kt。
// 规范 ID 的大小写是规范的一部分（例如 g711U / g722 / L16），别名匹配
// 一律大小写不敏感。

#include "layanalyzer/rtp/core/RtpCodecNames.h"

#include <cstring>

namespace layanalyzer::rtp {

namespace {

// ---------------------------------------------------------------------------
// §4.3 的规范 ID 表：规范 ID / 别名 / 默认时钟 / kind。
// 静态 PT 一列不影响 canonical_codec（静态名字由 rtp_static_pt_codec_name 提供），
// 此处仅作留档：g711U=0、g711A=8、g722=9、L16=10(双声道)/11(单声道)、
// g729=18、CN=13/19。
// ---------------------------------------------------------------------------
struct CodecEntry {
  const char *id;
  const char *const *aliases;
  size_t alias_count;
  int default_clock_rate;
  bool is_audio;
  bool is_video;
  bool is_event;
};

const char *const kAliasesG711U[] = {"g711U", "PCMU"};
const char *const kAliasesG711A[] = {"g711A", "PCMA"};
const char *const kAliasesG722[] = {"g722", "G722"};
const char *const kAliasesL16[] = {"L16", "16-bit audio, monaural",
                                   "16-bit audio, stereo"};
const char *const kAliasesG729[] = {"g729", "G729", "G729A", "G729B"};
const char *const kAliasesG726_16[] = {"G726-16"};
const char *const kAliasesG726_24[] = {"G726-24"};
const char *const kAliasesG726_32[] = {"G726-32"};
const char *const kAliasesG726_40[] = {"G726-40"};
const char *const kAliasesAAL2G726_16[] = {"AAL2-G726-16"};
const char *const kAliasesAAL2G726_24[] = {"AAL2-G726-24"};
const char *const kAliasesAAL2G726_32[] = {"AAL2-G726-32"};
const char *const kAliasesAAL2G726_40[] = {"AAL2-G726-40"};
const char *const kAliasesAMR[] = {"AMR"};
const char *const kAliasesAMRWB[] = {"AMR-WB"};
const char *const kAliasesOpus[] = {"opus"};
const char *const kAliasesILBC[] = {"iLBC"};
const char *const kAliasesTelephoneEvent[] = {"telephone-event"};
const char *const kAliasesCN[] = {"CN", "CN(old)"};
const char *const kAliasesH264[] = {"H264"};
const char *const kAliasesH265[] = {"H265", "HEVC"};
const char *const kAliasesPS[] = {"PS", "MP2P"};

const CodecEntry kCodecTable[] = {
    {"g711U", kAliasesG711U, 2, 8000, true, false, false},
    {"g711A", kAliasesG711A, 2, 8000, true, false, false},
    {"g722", kAliasesG722, 2, 8000, true, false, false},
    {"L16", kAliasesL16, 3, 44100, true, false, false},
    {"g729", kAliasesG729, 4, 8000, true, false, false},
    {"G726-16", kAliasesG726_16, 1, 8000, true, false, false},
    {"G726-24", kAliasesG726_24, 1, 8000, true, false, false},
    {"G726-32", kAliasesG726_32, 1, 8000, true, false, false},
    {"G726-40", kAliasesG726_40, 1, 8000, true, false, false},
    {"AAL2-G726-16", kAliasesAAL2G726_16, 1, 8000, true, false, false},
    {"AAL2-G726-24", kAliasesAAL2G726_24, 1, 8000, true, false, false},
    {"AAL2-G726-32", kAliasesAAL2G726_32, 1, 8000, true, false, false},
    {"AAL2-G726-40", kAliasesAAL2G726_40, 1, 8000, true, false, false},
    {"AMR", kAliasesAMR, 1, 8000, true, false, false},
    {"AMR-WB", kAliasesAMRWB, 1, 16000, true, false, false},
    {"opus", kAliasesOpus, 1, 48000, true, false, false},
    {"iLBC", kAliasesILBC, 1, 8000, true, false, false},
    {"telephone-event", kAliasesTelephoneEvent, 1, 8000, false, false, true},
    {"CN", kAliasesCN, 2, 8000, false, false, true},
    {"H264", kAliasesH264, 1, 90000, false, true, false},
    {"H265", kAliasesH265, 2, 90000, false, true, false},
    {"PS", kAliasesPS, 2, 90000, false, true, false},
};

bool is_ascii_space(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
         c == '\v';
}

std::string trim_copy(const std::string &text) {
  size_t begin = 0;
  size_t end = text.size();
  while (begin < end && is_ascii_space(text[begin])) {
    ++begin;
  }
  while (end > begin && is_ascii_space(text[end - 1])) {
    --end;
  }
  return text.substr(begin, end - begin);
}

// 只折叠 ASCII 大小写的相等比较（长度必须一致）。
bool ascii_iequals(const std::string &value, const char *other) {
  if (value.size() != std::strlen(other)) {
    return false;
  }
  for (size_t i = 0; i < value.size(); ++i) {
    unsigned char a = static_cast<unsigned char>(value[i]);
    unsigned char b = static_cast<unsigned char>(other[i]);
    if (a >= 'A' && a <= 'Z') {
      a = static_cast<unsigned char>(a - 'A' + 'a');
    }
    if (b >= 'A' && b <= 'Z') {
      b = static_cast<unsigned char>(b - 'A' + 'a');
    }
    if (a != b) {
      return false;
    }
  }
  return true;
}

// 已去掉首尾空白后的名字是否命中表；命中返回表项，否则 nullptr。
const CodecEntry *find_entry(const std::string &trimmed) {
  if (trimmed.empty()) {
    return nullptr;
  }
  for (const CodecEntry &entry : kCodecTable) {
    for (size_t i = 0; i < entry.alias_count; ++i) {
      if (ascii_iequals(trimmed, entry.aliases[i])) {
        return &entry;
      }
    }
  }
  return nullptr;
}

}  // namespace

CodecInfo canonical_codec(const std::string &raw_name) {
  const std::string trimmed = trim_copy(raw_name);
  const CodecEntry *entry = find_entry(trimmed);
  if (entry == nullptr) {
    CodecInfo unknown;
    unknown.id = trimmed;
    unknown.default_clock_rate = 0;
    unknown.is_audio = false;
    unknown.is_video = false;
    unknown.is_event = false;
    return unknown;
  }
  CodecInfo known;
  known.id = entry->id;
  known.default_clock_rate = entry->default_clock_rate;
  known.is_audio = entry->is_audio;
  known.is_video = entry->is_video;
  known.is_event = entry->is_event;
  return known;
}

bool rtp_codec_is_known(const std::string &raw_name) {
  return find_entry(trim_copy(raw_name)) != nullptr;
}

const char *rtp_static_pt_codec_name(uint32_t pt) {
  switch (pt) {
    case 0:
      return "g711U";
    case 8:
      return "g711A";
    case 9:
      return "g722";
    case 10:
      return "L16";
    case 11:
      return "L16";
    case 13:
      return "CN";
    case 18:
      return "g729";
    case 19:
      return "CN";
    default:
      return nullptr;
  }
}

bool rtp_codec_is_supported_audio(const std::string &canonical_id) {
  for (const char *supported : kSupportedAudioCodecs) {
    if (canonical_id == supported) {
      return true;
    }
  }
  return false;
}

bool rtp_codec_is_event(const std::string &canonical_id) {
  return ascii_iequals(canonical_id, "CN") ||
         ascii_iequals(canonical_id, "telephone-event");
}

}  // namespace layanalyzer::rtp
