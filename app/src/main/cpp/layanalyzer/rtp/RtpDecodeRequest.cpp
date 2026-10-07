// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "layanalyzer/rtp/RtpDecodeRequest.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace layanalyzer::rtp {
namespace {

void skip_whitespace(const std::string &text, size_t &position) {
  while (position < text.size()) {
    const char value = text[position];
    if (value == ' ' || value == '\t' || value == '\n' || value == '\r') {
      ++position;
    } else {
      break;
    }
  }
}

void append_utf8(std::string &out, uint32_t codepoint) {
  if (codepoint <= 0x7f) {
    out.push_back(static_cast<char>(codepoint));
  } else if (codepoint <= 0x7ff) {
    out.push_back(static_cast<char>(0xc0u | (codepoint >> 6u)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
  } else {
    out.push_back(static_cast<char>(0xe0u | (codepoint >> 12u)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 6u) & 0x3fu)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
  }
}

class DecodeRequestJsonReader {
 public:
  explicit DecodeRequestJsonReader(const std::string &text) : text_(text) {}

  bool parse(RtpDecodeRequest &out, std::string &error) {
    if (!parse_root(out)) {
      error = error_.empty() ? "Invalid JSON request." : error_;
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

  void skip() { skip_whitespace(text_, position_); }

  bool expect(char expected) {
    skip();
    if (position_ < text_.size() && text_[position_] == expected) {
      ++position_;
      return true;
    }
    return false;
  }

  bool parse_root(RtpDecodeRequest &out) {
    if (!expect('{')) {
      return fail("Request must be a JSON object.");
    }

    bool have_generation = false;
    bool have_streams = false;
    bool have_timing = false;
    bool have_jitter = false;
    bool have_dtmf = false;
    bool have_mix = false;

    skip();
    if (expect('}')) {
      return fail("Request is missing required fields.");
    }

    while (true) {
      std::string key;
      if (!parse_string(key)) {
        return fail("Object keys must be JSON strings.");
      }
      if (!expect(':')) {
        return fail("Missing ':' after an object key.");
      }

      if (key == "scanGeneration") {
        if (have_generation) {
          return fail("scanGeneration is duplicated.");
        }
        if (!parse_uint64(out.scan_generation)) {
          return fail("scanGeneration must be a non-negative integer.");
        }
        have_generation = true;
      } else if (key == "streams") {
        if (have_streams) {
          return fail("streams is duplicated.");
        }
        if (!parse_streams(out.stream_ids)) {
          return false;
        }
        have_streams = true;
      } else if (key == "timing") {
        if (have_timing) {
          return fail("timing is duplicated.");
        }
        if (!parse_timing(out.timing)) {
          return false;
        }
        have_timing = true;
      } else if (key == "jitterMs") {
        if (have_jitter) {
          return fail("jitterMs is duplicated.");
        }
        int64_t value = 0;
        if (!parse_integer(value) || value < 0 ||
            value > std::numeric_limits<int>::max()) {
          return fail("jitterMs must be a non-negative integer.");
        }
        out.jitter_ms = static_cast<int>(value);
        have_jitter = true;
      } else if (key == "dtmf") {
        if (have_dtmf) {
          return fail("dtmf is duplicated.");
        }
        if (!parse_boolean(out.dtmf)) {
          return fail("dtmf must be a boolean.");
        }
        have_dtmf = true;
      } else if (key == "mix") {
        if (have_mix) {
          return fail("mix is duplicated.");
        }
        if (!parse_mix(out.mix)) {
          return false;
        }
        have_mix = true;
      } else if (!skip_value()) {
        return fail("Unknown field contains invalid JSON.");
      }

      skip();
      if (expect(',')) {
        continue;
      }
      if (expect('}')) {
        break;
      }
      return fail("Object is missing ',' or '}'.");
    }

    skip();
    if (position_ != text_.size()) {
      return fail("Unexpected content after the JSON object.");
    }
    if (!have_generation) {
      return fail("scanGeneration is required.");
    }
    if (!have_streams) {
      return fail("streams is required.");
    }
    if (!have_timing) {
      return fail("timing is required.");
    }
    if (have_mix) {
      if (out.mix.left_stream_id == out.mix.right_stream_id) {
        return fail("mix.left and mix.right must be different streams.");
      }
      const auto contains_stream = [&](const std::string &stream_id) {
        return std::find(out.stream_ids.begin(), out.stream_ids.end(),
                         stream_id) != out.stream_ids.end();
      };
      if (!contains_stream(out.mix.left_stream_id) ||
          !contains_stream(out.mix.right_stream_id)) {
        return fail("mix streams must be included in streams.");
      }
      out.has_mix = true;
    }
    return true;
  }

  bool parse_streams(std::vector<std::string> &out) {
    if (!expect('[')) {
      return fail("streams must be an array.");
    }

    std::vector<std::string> parsed;
    skip();
    if (expect(']')) {
      out = std::move(parsed);
      return true;
    }

    while (true) {
      std::string stream_id;
      if (!parse_string(stream_id)) {
        return fail("Every streams entry must be a string.");
      }
      if (stream_id.empty()) {
        return fail("stream ids must not be empty.");
      }
      if (std::find(parsed.begin(), parsed.end(), stream_id) == parsed.end()) {
        parsed.push_back(std::move(stream_id));
      }

      skip();
      if (expect(',')) {
        continue;
      }
      if (expect(']')) {
        break;
      }
      return fail("streams is missing ',' or ']'.");
    }

    out = std::move(parsed);
    return true;
  }

  bool parse_timing(RtpTimingMode &out) {
    std::string timing;
    if (!parse_string(timing)) {
      return fail("timing must be a string.");
    }
    if (timing == "jitter") {
      out = RtpTimingMode::JitterBuffer;
      return true;
    }
    if (timing == "rtp") {
      out = RtpTimingMode::RtpTimestamp;
      return true;
    }
    if (timing == "uninterrupted") {
      out = RtpTimingMode::Uninterrupted;
      return true;
    }
    return fail("timing must be jitter, rtp, or uninterrupted.");
  }

  bool parse_mix(RtpMixRequest &out) {
    if (!expect('{')) {
      return fail("mix must be an object.");
    }

    bool have_left = false;
    bool have_right = false;
    bool have_align = false;
    skip();
    if (expect('}')) {
      return fail("mix is missing required fields.");
    }

    while (true) {
      std::string key;
      if (!parse_string(key)) {
        return fail("mix keys must be JSON strings.");
      }
      if (!expect(':')) {
        return fail("Missing ':' after a mix key.");
      }

      if (key == "left") {
        if (have_left) {
          return fail("mix.left is duplicated.");
        }
        if (!parse_string(out.left_stream_id) ||
            out.left_stream_id.empty()) {
          return fail("mix.left must be a non-empty string.");
        }
        have_left = true;
      } else if (key == "right") {
        if (have_right) {
          return fail("mix.right is duplicated.");
        }
        if (!parse_string(out.right_stream_id) ||
            out.right_stream_id.empty()) {
          return fail("mix.right must be a non-empty string.");
        }
        have_right = true;
      } else if (key == "align") {
        if (have_align) {
          return fail("mix.align is duplicated.");
        }
        std::string alignment;
        if (!parse_string(alignment) || alignment != "absArrival") {
          return fail("mix.align must be absArrival.");
        }
        out.align_abs_arrival = true;
        have_align = true;
      } else if (!skip_value()) {
        return fail("Unknown mix field contains invalid JSON.");
      }

      skip();
      if (expect(',')) {
        continue;
      }
      if (expect('}')) {
        break;
      }
      return fail("mix is missing ',' or '}'.");
    }

    if (!have_left || !have_right || !have_align) {
      return fail("mix requires left, right, and align.");
    }
    return true;
  }

  bool parse_uint64(uint64_t &out) {
    skip();
    const size_t start = position_;
    if (position_ >= text_.size() ||
        text_[position_] < '0' || text_[position_] > '9') {
      return false;
    }
    if (text_[position_] == '0' && position_ + 1 < text_.size() &&
        std::isdigit(static_cast<unsigned char>(text_[position_ + 1]))) {
      return false;
    }

    uint64_t value = 0;
    while (position_ < text_.size() &&
           std::isdigit(static_cast<unsigned char>(text_[position_]))) {
      const uint64_t digit =
          static_cast<uint64_t>(text_[position_] - '0');
      if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10u) {
        position_ = start;
        return false;
      }
      value = value * 10u + digit;
      ++position_;
    }

    if (position_ < text_.size()) {
      const char next = text_[position_];
      if (next == '.' || next == 'e' || next == 'E') {
        position_ = start;
        return false;
      }
    }
    out = value;
    return true;
  }

  bool parse_boolean(bool &out) {
    skip();
    if (text_.compare(position_, 4u, "true") == 0) {
      position_ += 4u;
      out = true;
      return true;
    }
    if (text_.compare(position_, 5u, "false") == 0) {
      position_ += 5u;
      out = false;
      return true;
    }
    return false;
  }

  bool parse_integer(int64_t &out) {
    skip();
    const size_t start = position_;
    bool negative = false;
    if (position_ < text_.size() && text_[position_] == '-') {
      negative = true;
      ++position_;
    }
    if (position_ >= text_.size() ||
        text_[position_] < '0' || text_[position_] > '9') {
      position_ = start;
      return false;
    }
    if (text_[position_] == '0' && position_ + 1 < text_.size() &&
        std::isdigit(static_cast<unsigned char>(text_[position_ + 1]))) {
      position_ = start;
      return false;
    }

    uint64_t magnitude = 0;
    while (position_ < text_.size() &&
           std::isdigit(static_cast<unsigned char>(text_[position_]))) {
      const uint64_t digit =
          static_cast<uint64_t>(text_[position_] - '0');
      const uint64_t limit =
          negative
              ? static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1u
              : static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
      if (magnitude > (limit - digit) / 10u) {
        position_ = start;
        return false;
      }
      magnitude = magnitude * 10u + digit;
      ++position_;
    }
    if (position_ < text_.size()) {
      const char next = text_[position_];
      if (next == '.' || next == 'e' || next == 'E') {
        position_ = start;
        return false;
      }
    }

    if (negative) {
      if (magnitude ==
          static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1u) {
        out = std::numeric_limits<int64_t>::min();
      } else {
        out = -static_cast<int64_t>(magnitude);
      }
    } else {
      out = static_cast<int64_t>(magnitude);
    }
    return true;
  }

  bool parse_string(std::string &out) {
    skip();
    if (position_ >= text_.size() || text_[position_] != '"') {
      return false;
    }
    ++position_;

    std::string result;
    while (position_ < text_.size()) {
      const unsigned char value =
          static_cast<unsigned char>(text_[position_++]);
      if (value == '"') {
        out = std::move(result);
        return true;
      }
      if (value < 0x20u) {
        return false;
      }
      if (value != '\\') {
        result.push_back(static_cast<char>(value));
        continue;
      }

      if (position_ >= text_.size()) {
        return false;
      }
      const char escaped = text_[position_++];
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          result.push_back(escaped);
          break;
        case 'b':
          result.push_back('\b');
          break;
        case 'f':
          result.push_back('\f');
          break;
        case 'n':
          result.push_back('\n');
          break;
        case 'r':
          result.push_back('\r');
          break;
        case 't':
          result.push_back('\t');
          break;
        case 'u': {
          uint32_t codepoint = 0;
          if (!parse_hex4(codepoint)) {
            return false;
          }
          if (codepoint >= 0xd800u && codepoint <= 0xdfffu) {
            // Stream ids in this contract are ASCII. Accept the escape as
            // valid JSON but avoid inventing a surrogate pair conversion.
            codepoint = 0xfffdu;
          }
          append_utf8(result, codepoint);
          break;
        }
        default:
          return false;
      }
    }
    return false;
  }

  bool parse_hex4(uint32_t &out) {
    if (position_ + 4u > text_.size()) {
      return false;
    }
    uint32_t value = 0;
    for (size_t index = 0; index < 4u; ++index) {
      const char digit = text_[position_++];
      value <<= 4u;
      if (digit >= '0' && digit <= '9') {
        value |= static_cast<uint32_t>(digit - '0');
      } else if (digit >= 'a' && digit <= 'f') {
        value |= static_cast<uint32_t>(digit - 'a' + 10);
      } else if (digit >= 'A' && digit <= 'F') {
        value |= static_cast<uint32_t>(digit - 'A' + 10);
      } else {
        return false;
      }
    }
    out = value;
    return true;
  }

  bool skip_value() {
    skip();
    if (position_ >= text_.size()) {
      return false;
    }
    const char value = text_[position_];
    if (value == '"') {
      std::string ignored;
      return parse_string(ignored);
    }
    if (value == '{') {
      return skip_object();
    }
    if (value == '[') {
      return skip_array();
    }
    if (value == 't') {
      return skip_literal("true");
    }
    if (value == 'f') {
      return skip_literal("false");
    }
    if (value == 'n') {
      return skip_literal("null");
    }
    return skip_number();
  }

  bool skip_object() {
    if (!expect('{')) {
      return false;
    }
    skip();
    if (expect('}')) {
      return true;
    }
    while (true) {
      std::string key;
      if (!parse_string(key) || !expect(':') || !skip_value()) {
        return false;
      }
      skip();
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
    skip();
    if (expect(']')) {
      return true;
    }
    while (true) {
      if (!skip_value()) {
        return false;
      }
      skip();
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
    if (text_.compare(position_, length, literal) != 0) {
      return false;
    }
    position_ += length;
    return true;
  }

  bool skip_number() {
    skip();
    const size_t start = position_;
    if (position_ < text_.size() && text_[position_] == '-') {
      ++position_;
    }
    if (position_ >= text_.size()) {
      position_ = start;
      return false;
    }
    if (text_[position_] == '0') {
      ++position_;
      if (position_ < text_.size() &&
          std::isdigit(static_cast<unsigned char>(text_[position_]))) {
        position_ = start;
        return false;
      }
    } else if (text_[position_] >= '1' && text_[position_] <= '9') {
      while (position_ < text_.size() &&
             std::isdigit(static_cast<unsigned char>(text_[position_]))) {
        ++position_;
      }
    } else {
      position_ = start;
      return false;
    }

    if (position_ < text_.size() && text_[position_] == '.') {
      ++position_;
      const size_t fraction_start = position_;
      while (position_ < text_.size() &&
             std::isdigit(static_cast<unsigned char>(text_[position_]))) {
        ++position_;
      }
      if (position_ == fraction_start) {
        position_ = start;
        return false;
      }
    }
    if (position_ < text_.size() &&
        (text_[position_] == 'e' || text_[position_] == 'E')) {
      ++position_;
      if (position_ < text_.size() &&
          (text_[position_] == '+' || text_[position_] == '-')) {
        ++position_;
      }
      const size_t exponent_start = position_;
      while (position_ < text_.size() &&
             std::isdigit(static_cast<unsigned char>(text_[position_]))) {
        ++position_;
      }
      if (position_ == exponent_start) {
        position_ = start;
        return false;
      }
    }
    return true;
  }

  const std::string &text_;
  size_t position_ = 0;
  std::string error_;
};

}  // namespace

bool parse_rtp_decode_request(const std::string &text,
                              RtpDecodeRequest &request,
                              std::string &error) {
  RtpDecodeRequest parsed;
  DecodeRequestJsonReader reader(text);
  if (!reader.parse(parsed, error)) {
    return false;
  }
  request = std::move(parsed);
  return true;
}

}  // namespace layanalyzer::rtp
