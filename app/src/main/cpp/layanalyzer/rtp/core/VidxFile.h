// `.vidx` video access-unit index reader/writer (RTP5-NAT-03).
//
// One `.h264`/`.h265` elementary stream -- a raw Annex-B concatenation of access
// units with no header of its own -- is accompanied by one `.vidx` index that
// says where each access unit lives in it, what its presentation time is, and
// what is wrong with it. RTP5-KT-01 (the muxer) and RTP5-KT-03 (in-app preview)
// mirror this format in Kotlin and must agree with it octet for octet, so the
// layout below is frozen by the RTP5-NAT-03 card and task_rtp_m5_video.md
// section 3.2.
//
// Layout, little-endian throughout, packed with no padding or alignment
// anywhere:
//
//   "VID1"            4 octets
//   u32 count         number of records that follow
//   count x record    25 octets each, in this order:
//                       u64 offset       absolute byte offset into the ES file
//                       u32 len          access-unit length in octets
//                       u64 ptsUs        presentation time, microseconds
//                       u32 firstFrame   capture frame number of the first packet
//                       u8  flags        0x01 key, 0x02 corrupt, 0x04 hasParamSets
//
// The 25 octets are exact: 8 + 4 + 8 + 4 + 1. Every field is written and read
// octet by octet instead of by copying a struct, because a struct would
// silently pick up whatever padding the compiler chose and the host and the
// Android ABIs are not required to agree on any of it. The trap here is
// sharper than FidxFile's: `ptsUs` is a u64 sitting between two u32s and
// `firstFrame` is a u32 sitting right after it, so the natural C++ declaration
// order (`offset`, `len`, `ptsUs`, `firstFrame`, `flags`) is exactly the one a
// compiler would pad -- u32 len, then 4 octets of padding to align the u64, then
// u32, then 3 octets of tail padding -- and a struct copy would write 32 octets
// per record where the format says 25. `kVidxRecordSize` is what the reader
// checks the file against, and VidxFileTest.cpp pins the octets themselves.
//
// The field names here follow FidxFile.h rather than the format text: `length`
// is the format's `len`, and `offset` is `VideoAuRecord::byte_offset`. The values
// are copied over one for one by NAT-05, which is the only producer.
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

// One `.vidx` record. Field names match the Kotlin mirror used by RTP5-KT-01 /
// RTP5-KT-03:
//   VidxEntry(offset: Long, length: Int, ptsUs: Long, firstFrame: Int, flags: Int)
struct VidxEntry {
  uint64_t offset = 0;       // absolute byte offset into the ES file
  uint32_t length = 0;       // access-unit length in octets
  uint64_t pts_us = 0;       // presentation time, microseconds
  uint32_t first_frame = 0;  // capture frame number of the access unit's first packet
  uint8_t flags = 0;         // see kVidxFlag* below
};

// Octets per packed record. Deliberately a constant and not sizeof(VidxEntry):
// see the padding note in the file header -- sizeof() would be 32.
inline constexpr uint64_t kVidxRecordSize = 25;

// `flags` bits. The same three bits as VideoAuRecord's, so NAT-05 copies them
// across without a translation table.
inline constexpr uint8_t kVidxFlagKey = 0x01;        // IDR / IRAP access unit
inline constexpr uint8_t kVidxFlagCorrupt = 0x02;    // a packet of it was lost
inline constexpr uint8_t kVidxFlagParamSets = 0x04;  // contains parameter-set NALs

// Writes `"VID1"`, the count, then every record. Fails closed -- and removes the
// partial file -- on an empty path, on more records than the u32 count field can
// hold, and on any write error.
bool write_vidx_file(const std::string &path,
                     const std::vector<VidxEntry> &entries, std::string &error);

// Reads a whole `.vidx` back into `entries`, which is cleared first. Fails
// closed on a missing/empty path, an unreadable file, a bad magic, a truncated
// header, and a declared record count the file cannot hold (which is also what
// a truncated record reports). Octets beyond the declared count are ignored.
bool read_vidx_file(const std::string &path, std::vector<VidxEntry> &entries,
                    std::string &error);

}  // namespace layanalyzer::rtp
