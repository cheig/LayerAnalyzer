#pragma once

#include <cstdint>
#include <cstdio>

namespace layanalyzer::exporter {

bool write_le16(FILE* file, uint16_t value);
bool write_le32(FILE* file, uint32_t value);
int link_type_for_encapsulation(int encapsulation);

}  // namespace layanalyzer::exporter

