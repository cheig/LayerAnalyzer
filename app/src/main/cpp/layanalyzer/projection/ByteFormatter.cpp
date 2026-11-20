// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "ByteFormatter.h"

#include <glib.h>

#include "TextEncoding.h"

namespace layanalyzer::projection {

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string output;
  if (bytes.empty()) return output;
  output.reserve(bytes.size() * 3 - 1);
  for (size_t index = 0; index < bytes.size(); ++index) {
    if (index != 0) output.push_back(' ');
    const uint8_t value = bytes[index];
    output.push_back(kHex[(value >> 4) & 0x0F]);
    output.push_back(kHex[value & 0x0F]);
  }
  return output;
}

std::string bytes_to_ascii(const std::vector<uint8_t>& bytes) {
  std::string output;
  output.reserve(bytes.size());
  for (uint8_t value : bytes) {
    output.push_back(value >= 32 && value <= 126
                         ? static_cast<char>(value)
                         : '.');
  }
  return output;
}

// Text preview of a payload: follow-stream rows and the per-frame export carry
// the raw bytes in `hex` anyway, so this is the only place that has to be
// readable. P2-1: payloads that are GBK used to come back with every Chinese
// character turned into a replacement character; decoding is now charset-aware.
std::string bytes_to_utf8_text(const std::vector<uint8_t>& bytes) {
  if (bytes.empty()) return "";
  return to_display_utf8(reinterpret_cast<const char*>(bytes.data()),
                         bytes.size());
}

}  // namespace layanalyzer::projection

