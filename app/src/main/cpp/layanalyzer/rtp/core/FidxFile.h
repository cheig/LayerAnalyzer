// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// `.fidx` frame index reader/writer (RTP4-NAT-06).
//
// One `.frames` blob -- a raw concatenation of codec frames with no header --
// is accompanied by one `.fidx` index that says where each frame lives in it
// and what the renderer has to know about that frame. RTP4-KT-01 mirrors this
// format in Kotlin (FidxEntry / FidxFile) and the two must agree octet for
// octet, so the layout below is frozen.
//
// Layout, little-endian throughout, packed with no padding or alignment
// anywhere:
//
//   "FID1"            4 octets
//   u32 count         number of records that follow
//   count x record    33 octets each, in this order:
//                       u64 offset      absolute byte offset into the .frames file
//                       u32 len         frame length in octets
//                       u32 frame       capture frame number
//                       u64 extTs       RTP timestamp
//                       f64 arrivalRel  arrival time relative to capture frame 0, seconds
//                       u8  flags       0x01 lost, 0x02 sid, 0x04 late
//
// The 33 octets are exact: 8 + 4 + 4 + 8 + 8 + 1. Every field is written and
// read octet by octet instead of by copying a struct, because a struct would
// silently pick up whatever padding the compiler chose and the host and the
// Android ABIs are not required to agree on any of it.
//
// Why `frame` comes before `extTs`: task_rtp_m4_codecs.md section 3.2 lists the
// two the other way round, while the RTP4-NAT-06 card reverses them and states
// that the card wins. The Kotlin mirror follows the card, so this file does
// too. A field-order mistake is caught by FidxFileTest.cpp's byte-level case
// even if the reader and the writer were swapped consistently.
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

// One `.fidx` record. Field names match the Kotlin mirror in RTP4-KT-01:
//   FidxEntry(offset: Long, length: Int, frame: Long, extTs: Long,
//             arrivalRel: Double, flags: Int)
struct FidxEntry {
  uint64_t offset = 0;        // absolute byte offset into the .frames file
  uint32_t length = 0;        // frame length in octets (0 for a lost frame)
  uint32_t frame = 0;         // capture frame number
  uint64_t ext_ts = 0;        // RTP timestamp
  double arrival_rel = 0.0;   // seconds relative to capture frame 0
  uint8_t flags = 0;          // see kFidxFlag* below
};

// Octets per packed record. Deliberately a constant and not sizeof(FidxEntry):
// see the padding note in the file header.
inline constexpr uint64_t kFidxRecordSize = 33;

// `flags` bits.
inline constexpr uint8_t kFidxFlagLost = 0x01;  // no frame data at this slot
inline constexpr uint8_t kFidxFlagSid = 0x02;   // AMR SID (comfort noise) frame
inline constexpr uint8_t kFidxFlagLate = 0x04;  // arrival lag > 200 ms; annotation only

// Writes `"FID1"`, the count, then every record. Fails closed -- and removes
// the partial file -- on an empty path, on more records than the u32 count
// field can hold, and on any write error.
bool write_fidx_file(const std::string &path,
                     const std::vector<FidxEntry> &entries, std::string &error);

// Reads a whole `.fidx` back into `entries`, which is cleared first. Fails
// closed on a missing/empty path, an unreadable file, a bad magic, a truncated
// header, and a declared record count the file cannot hold (which is also what
// a truncated record reports). Octets beyond the declared count are ignored.
bool read_fidx_file(const std::string &path, std::vector<FidxEntry> &entries,
                    std::string &error);

}  // namespace layanalyzer::rtp
