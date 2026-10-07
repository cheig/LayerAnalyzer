// RTP 负载类型覆盖表（RTP1-NAT-06）。
//
// 会话级（`WiresharkSession::rtp_overrides`）的「Decode As」覆盖表：用户手动把
// 某个动态 PT 指定为某个编码，优先级高于 SDP/静态表（见卡片 §「编码名与来源的
// 判定」的 override > sdp > static）。
//
// header-only、纯标准库 —— 会被 `session/WiresharkSession.h` include，必须保持
// 干净，不得依赖 Wireshark/GLib/JNI/nlohmann。
//
// 输入形状固定为：
//   {"overrides":[{"pt":96,"codec":"AMR-WB","clockRate":16000,"channels":1}]}
// host 单测要覆盖 set_from_json，而 host 上没有 nlohmann，所以这里自带一个
// **只认识这个形状** 的最小解析器：容忍空白、忽略未知字段、字符串支持转义
// （认识 \" 及 \\ 两种），任何结构性错误一律返回 false（fail-closed，不替换原表）。
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace layanalyzer::rtp {

struct RtpPayloadOverride {
  uint32_t pt = 0;
  std::string codec;   // 原始名字，接入 scanRtpStreams 时再经 canonical_codec 规范化
  int clock_rate = 0;  // 缺失时默认 0（0 视为「未指定」，落到下一级来源）
  int channels = 1;    // 缺失时默认 1
};

namespace detail {

inline void rtp_overrides_skip_ws(const std::string &text, size_t &pos) {
  while (pos < text.size()) {
    const char c = text[pos];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      ++pos;
    } else {
      break;
    }
  }
}

// 只认识 {"overrides":[...]} 的最小 JSON 读取器。任何失败都通过 error_ 记录，
// 调用方在解析失败时**不得**改动原表（fail-closed 由 RtpPayloadOverrides 保证）。
class RtpOverridesJsonReader {
 public:
  explicit RtpOverridesJsonReader(const std::string &text) : text_(text) {}

  // 成功返回 true 并填 out（已经完成校验与重复 pt 合并）；失败返回 false 并填 error。
  bool parse(std::vector<RtpPayloadOverride> &out, std::string &error) {
    if (!parse_root(out)) {
      error = error_.empty() ? "JSON 结构不合法" : error_;
      return false;
    }
    return true;
  }

 private:
  bool fail(const std::string &message) {
    if (error_.empty()) {
      error_ = message;
    }
    return false;
  }

  void skip() { rtp_overrides_skip_ws(text_, pos_); }

  char peek() {
    skip();
    return pos_ < text_.size() ? text_[pos_] : '\0';
  }

  bool expect(char expected) {
    skip();
    if (pos_ < text_.size() && text_[pos_] == expected) {
      ++pos_;
      return true;
    }
    return false;
  }

  // {"overrides":[...]}；顶层必须是对象且必须带 overrides 数组。
  bool parse_root(std::vector<RtpPayloadOverride> &out) {
    if (!expect('{')) {
      return fail("输入不是 JSON 对象");
    }
    bool have_overrides = false;
    while (true) {
      std::string key;
      if (!parse_string(key)) {
        return fail("对象键必须是字符串");
      }
      if (!expect(':')) {
        return fail("对象键后缺少 ':'");
      }
      if (key == "overrides") {
        if (have_overrides) {
          return fail("overrides 字段重复");
        }
        if (!parse_override_array(out)) {
          return false;
        }
        have_overrides = true;
      } else if (!skip_value()) {
        return fail("未知字段的值不是合法 JSON");
      }
      skip();
      if (expect(',')) {
        continue;
      }
      if (expect('}')) {
        break;
      }
      return fail("对象里缺少 ',' 或 '}'");
    }
    skip();
    if (pos_ != text_.size()) {
      return fail("JSON 结尾有多余内容");
    }
    if (!have_overrides) {
      return fail("缺少 overrides 字段");
    }
    return true;
  }

  bool parse_override_array(std::vector<RtpPayloadOverride> &out) {
    if (!expect('[')) {
      return fail("overrides 不是数组");
    }
    if (expect(']')) {
      out.clear();
      return true;
    }
    std::vector<RtpPayloadOverride> parsed;
    while (true) {
      RtpPayloadOverride item;
      if (!parse_override_object(item)) {
        return false;
      }
      // 重复 pt：后者覆盖前者（保持出现顺序，items() 再按 pt 排序）。
      bool replaced = false;
      for (RtpPayloadOverride &existing : parsed) {
        if (existing.pt == item.pt) {
          existing = item;
          replaced = true;
          break;
        }
      }
      if (!replaced) {
        parsed.push_back(item);
      }
      skip();
      if (expect(',')) {
        continue;
      }
      if (expect(']')) {
        break;
      }
      return fail("数组里缺少 ',' 或 ']'");
    }
    out = std::move(parsed);
    return true;
  }

  // {"pt":..,"codec":..,"clockRate":..,"channels":..}；未知字段忽略。
  bool parse_override_object(RtpPayloadOverride &out) {
    if (!expect('{')) {
      return fail("overrides 的元素不是对象");
    }
    int64_t pt = 0;
    int64_t clock_rate = 0;
    int64_t channels = 1;
    std::string codec;
    while (true) {
      std::string key;
      if (!parse_string(key)) {
        return fail("对象键必须是字符串");
      }
      if (!expect(':')) {
        return fail("对象键后缺少 ':'");
      }
      if (key == "pt") {
        if (!parse_integer(pt)) {
          return fail("pt 必须是整数");
        }
      } else if (key == "codec") {
        if (!parse_string(codec)) {
          return fail("codec 必须是字符串");
        }
      } else if (key == "clockRate") {
        if (!parse_integer(clock_rate)) {
          return fail("clockRate 必须是整数");
        }
      } else if (key == "channels") {
        if (!parse_integer(channels)) {
          return fail("channels 必须是整数");
        }
      } else if (!skip_value()) {
        return fail("未知字段的值不是合法 JSON");
      }
      skip();
      if (expect(',')) {
        continue;
      }
      if (expect('}')) {
        break;
      }
      return fail("对象里缺少 ',' 或 '}'");
    }

    // 校验：pt ∈ 0..255、codec 非空。clockRate 不在 {0,8000,16000,44100,48000}
    // 时只记 warning 但仍接受（warning 由 JNI 层在成功后记日志，本层不依赖日志）。
    if (pt < 0 || pt > 255) {
      return fail("pt " + std::to_string(pt) + " 超出 0..255");
    }
    if (codec.empty()) {
      return fail("codec 不能为空");
    }
    out.pt = static_cast<uint32_t>(pt);
    out.codec = std::move(codec);
    out.clock_rate = static_cast<int>(clock_rate);
    out.channels = static_cast<int>(channels);
    return true;
  }

  // 严格整数（不接受小数 / 指数），供 pt / clockRate / channels 使用。
  bool parse_integer(int64_t &out) {
    skip();
    const size_t start = pos_;
    bool negative = false;
    if (pos_ < text_.size() && text_[pos_] == '-') {
      negative = true;
      ++pos_;
    }
    const size_t digits_start = pos_;
    int64_t value = 0;
    while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
      // 防溢出：本接口只需要 0..255 / 时钟频率这种小整数，超出即判非法。
      if (value > 1000000000000LL) {
        pos_ = start;
        return false;
      }
      value = value * 10 + (text_[pos_] - '0');
      ++pos_;
    }
    if (pos_ == digits_start) {
      pos_ = start;
      return false;
    }
    if (pos_ < text_.size()) {
      const char next = text_[pos_];
      if (next == '.' || next == 'e' || next == 'E') {
        pos_ = start;
        return false;
      }
    }
    out = negative ? -value : value;
    return true;
  }

  bool parse_string(std::string &out) {
    skip();
    if (pos_ >= text_.size() || text_[pos_] != '"') {
      return false;
    }
    ++pos_;
    std::string result;
    while (pos_ < text_.size()) {
      const char c = text_[pos_++];
      if (c == '"') {
        out = std::move(result);
        return true;
      }
      if (c == '\\') {
        if (pos_ >= text_.size()) {
          return false;
        }
        const char escaped = text_[pos_++];
        if (escaped == '"') {
          result.push_back('"');
        } else if (escaped == '\\') {
          result.push_back('\\');
        } else {
          // 只约定认识 \" 与 \\；其它转义按字面保留（宽松，不视为结构错误）。
          result.push_back('\\');
          result.push_back(escaped);
        }
      } else {
        result.push_back(c);
      }
    }
    return false;  // 字符串没有闭合
  }

  bool skip_value() {
    skip();
    if (pos_ >= text_.size()) {
      return false;
    }
    const char c = text_[pos_];
    if (c == '"') {
      std::string ignored;
      return parse_string(ignored);
    }
    if (c == '{') {
      return skip_object();
    }
    if (c == '[') {
      return skip_array();
    }
    if (c == 't') {
      return skip_literal("true");
    }
    if (c == 'f') {
      return skip_literal("false");
    }
    if (c == 'n') {
      return skip_literal("null");
    }
    return skip_number();
  }

  bool skip_object() {
    if (!expect('{')) {
      return false;
    }
    if (expect('}')) {
      return true;
    }
    while (true) {
      std::string key;
      if (!parse_string(key)) {
        return false;
      }
      if (!expect(':')) {
        return false;
      }
      if (!skip_value()) {
        return false;
      }
      if (expect(',')) {
        continue;
      }
      if (expect('}')) {
        return true;
      }
      return false;
    }
  }

  bool skip_array() {
    if (!expect('[')) {
      return false;
    }
    if (expect(']')) {
      return true;
    }
    while (true) {
      if (!skip_value()) {
        return false;
      }
      if (expect(',')) {
        continue;
      }
      if (expect(']')) {
        return true;
      }
      return false;
    }
  }

  bool skip_literal(const char *literal) {
    const size_t length = std::char_traits<char>::length(literal);
    if (text_.compare(pos_, length, literal) != 0) {
      return false;
    }
    pos_ += length;
    return true;
  }

  bool skip_number() {
    skip();
    const size_t start = pos_;
    if (pos_ < text_.size() && text_[pos_] == '-') {
      ++pos_;
    }
    const size_t int_start = pos_;
    while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
      ++pos_;
    }
    if (pos_ == int_start) {
      pos_ = start;
      return false;
    }
    if (pos_ < text_.size() && text_[pos_] == '.') {
      ++pos_;
      const size_t frac_start = pos_;
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
        ++pos_;
      }
      if (pos_ == frac_start) {
        pos_ = start;
        return false;
      }
    }
    if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
      ++pos_;
      if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) {
        ++pos_;
      }
      const size_t exp_start = pos_;
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
        ++pos_;
      }
      if (pos_ == exp_start) {
        pos_ = start;
        return false;
      }
    }
    return true;
  }

  const std::string &text_;
  size_t pos_ = 0;
  std::string error_;
};

}  // namespace detail

struct RtpPayloadOverrides {
  // 整体替换。任何一条不合法（pt 越界 / codec 为空 / 结构错误）都返回 false、
  // 写入 error，并**保持原表不变**（fail-closed）。
  bool set_from_json(const std::string &json, std::string &error) {
    detail::RtpOverridesJsonReader reader(json);
    std::vector<RtpPayloadOverride> parsed;
    if (!reader.parse(parsed, error)) {
      return false;
    }
    overrides_ = std::move(parsed);
    return true;
  }

  const RtpPayloadOverride *find(uint32_t pt) const {
    for (const RtpPayloadOverride &item : overrides_) {
      if (item.pt == pt) {
        return &item;
      }
    }
    return nullptr;
  }

  void clear() { overrides_.clear(); }

  size_t size() const { return overrides_.size(); }

  // 按 pt 升序返回一份拷贝。
  std::vector<RtpPayloadOverride> items() const {
    std::vector<RtpPayloadOverride> result = overrides_;
    std::sort(result.begin(), result.end(),
              [](const RtpPayloadOverride &a, const RtpPayloadOverride &b) {
                return a.pt < b.pt;
              });
    return result;
  }

 private:
  std::vector<RtpPayloadOverride> overrides_;
};

}  // namespace layanalyzer::rtp
