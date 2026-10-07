// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "PcapWriter.h"
#include <wiretap/wtap.h>

namespace layanalyzer::exporter {

bool write_le16(FILE* file, uint16_t value) {
  const uint8_t bytes[] = {
      static_cast<uint8_t>(value & 0xff),
      static_cast<uint8_t>((value >> 8) & 0xff)};
  return file && fwrite(bytes, 1, sizeof(bytes), file) == sizeof(bytes);
}

bool write_le32(FILE* file, uint32_t value) {
  const uint8_t bytes[] = {
      static_cast<uint8_t>(value & 0xff),
      static_cast<uint8_t>((value >> 8) & 0xff),
      static_cast<uint8_t>((value >> 16) & 0xff),
      static_cast<uint8_t>((value >> 24) & 0xff)};
  return file && fwrite(bytes, 1, sizeof(bytes), file) == sizeof(bytes);
}

int link_type_for_encapsulation(int encapsulation) {
  switch (encapsulation) {
    case WTAP_ENCAP_ETHERNET: return 1;   // LINKTYPE_ETHERNET
    case WTAP_ENCAP_RAW_IP: return 101;   // LINKTYPE_RAW
    case WTAP_ENCAP_SLL: return 113;      // LINKTYPE_LINUX_SLL
#ifdef WTAP_ENCAP_SLL2
    case WTAP_ENCAP_SLL2: return 276;     // LINKTYPE_LINUX_SLL2
#endif
#ifdef WTAP_ENCAP_RAW_IP4
    case WTAP_ENCAP_RAW_IP4: return 228;  // LINKTYPE_IPV4
#endif
#ifdef WTAP_ENCAP_RAW_IP6
    case WTAP_ENCAP_RAW_IP6: return 229;  // LINKTYPE_IPV6
#endif
    default: return -1;
  }
}

}  // namespace layanalyzer::exporter
