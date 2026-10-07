// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Small string helpers shared by the legacy JNI modules. They were file-local
// statics in the former single translation unit; as inline functions they keep
// identical behaviour without adding a dedicated translation unit.
#pragma once
#include "layanalyzer/internal/Common.h"

inline std::string lowercase_copy(const std::string &value) {
  std::string out = value;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

inline std::string uppercase_copy(const std::string &value) {
  std::string out = value;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return out;
}

inline std::string trim_copy(const std::string &value) {
  const char *whitespace = " \t\r\n";
  size_t start = value.find_first_not_of(whitespace);
  if (start == std::string::npos) return "";
  size_t end = value.find_last_not_of(whitespace);
  return value.substr(start, end - start + 1);
}

inline bool contains_case_insensitive(const std::string &text,
                                      const std::string &needle) {
  if (needle.empty()) return true;
  if (needle.size() > text.size()) return false;
  // Most packet columns are ASCII. Compare in place so a full lowercase copy
  // of both strings is not allocated for every field/search/statistics check.
  for (size_t offset = 0; offset + needle.size() <= text.size(); ++offset) {
    size_t index = 0;
    for (; index < needle.size(); ++index) {
      const unsigned char left =
          static_cast<unsigned char>(text[offset + index]);
      const unsigned char right =
          static_cast<unsigned char>(needle[index]);
      if (std::tolower(left) != std::tolower(right)) break;
    }
    if (index == needle.size()) return true;
  }
  return false;
}
