// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "ByteFormatter.h"

#include <glib.h>

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

std::string bytes_to_utf8_text(const std::vector<uint8_t>& bytes) {
  if (bytes.empty()) return "";
  GError* error = nullptr;
  gchar* converted = g_utf8_make_valid(
      reinterpret_cast<const gchar*>(bytes.data()),
      static_cast<gssize>(bytes.size()));
  if (!converted) return bytes_to_ascii(bytes);

  gchar* normalized = g_convert_with_fallback(
      converted, -1, "UTF-8", "UTF-8", ".", nullptr, nullptr, &error);
  std::string output = normalized ? normalized : converted;
  if (error) g_error_free(error);
  g_free(normalized);
  g_free(converted);
  return output;
}

}  // namespace layanalyzer::projection

