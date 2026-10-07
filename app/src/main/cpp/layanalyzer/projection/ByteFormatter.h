// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::projection {

std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
std::string bytes_to_ascii(const std::vector<uint8_t>& bytes);
std::string bytes_to_utf8_text(const std::vector<uint8_t>& bytes);

}  // namespace layanalyzer::projection

