// RTP5-NAT-06: GB28181 PS de-multiplexing (ISO 13818-1 program stream over RTP).
//
// **The PS byte streams in this file are hand-built.** There is no GB28181
// capture in the repository and none was available on the machine this was
// written on, so every pack header, system header, PSM and PES packet below is
// assembled field by field in the helpers at the top, straight out of the field
// layouts in GB/T 28181 and ISO 13818-1 (the bit diagrams are quoted at each
// helper). Nothing here is copied from a capture, and nothing here should be
// read as if it were: the helpers are what the tests are actually checking, so
// a wrong offset in a helper would be a wrong test.
//
// What is worth pinning here is not the happy path -- one PS packet, one PES
// packet, one NAL unit falls out of almost any implementation -- but the four
// things that do not:
//
//   * the lengths. `pack_stuffing_length`, `header_length`,
//     `program_stream_map_length` and `PES_header_data_length` all have to be
//     honoured, or the parser starts reading the inside of a header as ES data.
//     The stuffing and header-stuffing cases exist to be wrong loudly.
//   * the reassembly. A PS packet arrives in several RTP payloads and is only
//     complete at the marker bit, and a NAL unit can be split across two PES
//     packets, so the ES has to be scanned as one continuous byte stream --
//     which is exactly the thing a per-PES "parse the payload" implementation
//     gets wrong in a way that still produces plausible output.
//   * the boundary and the time. An access unit is a video PES packet, its PTS
//     is the PES PTS, and both have to survive into the class NAT-03 consumes.
//     The last case drives a real `VideoAccessUnitBuilder` with the demuxer's
//     output, which is the mapping the header documents.
//   * the things that are counted rather than raised: an unsupported
//     `stream_type`, audio, a resynchronisation. A demuxer that silently drops
//     them produces a shorter file with no explanation.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

#include "layanalyzer/rtp/depack/PsDemux.h"
#include "layanalyzer/rtp/depack/VideoAccessUnitBuilder.h"

using layanalyzer::rtp::PsAccessUnit;
using layanalyzer::rtp::PsDemux;
using layanalyzer::rtp::PsDemuxOutput;
using layanalyzer::rtp::PsDemuxStats;
using layanalyzer::rtp::PsStreamKind;
using layanalyzer::rtp::VideoAccessUnitBuilder;
using layanalyzer::rtp::VideoAuBuilderOptions;
using layanalyzer::rtp::VideoAuRecord;
using layanalyzer::rtp::VideoCodec;
using layanalyzer::rtp::kVideoAuFlagKey;

namespace {

// ---------------------------------------------------------------------------
// The byte-level builders. All of them append to a caller-owned vector so a PS
// packet can be assembled structure by structure, which is how the tests below
// stay readable.
// ---------------------------------------------------------------------------

void push_u16(std::vector<uint8_t> &out, size_t value) {
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
}

// ISO 13818-1 pack_header():
//   pack_start_code 32 | '01' 2 | SCR_base[32..30] 3 | marker 1 |
//   SCR_base[29..15] 15 | marker 1 | SCR_base[14..0] 15 | marker 1 |
//   SCR_extension 9 | marker 1 | program_mux_rate 22 | marker 1 | marker 1 |
//   reserved 5 | pack_stuffing_length 3
// Six octets of SCR and marker bits, three of program_mux_rate and marker bits,
// one of reserved bits and the stuffing length: fourteen in all, then the
// stuffing the last three bits declare.
void append_pack_header(std::vector<uint8_t> &out, size_t stuffing = 0) {
  const uint8_t fixed[13] = {
      0x00, 0x00, 0x01, 0xBA,
      0x44, 0x00, 0x04, 0x00, 0x04, 0x01,  // '01' + SCR base + markers, SCR ext
      0x00, 0x9C, 0x43};                   // program_mux_rate 10000 + markers
  out.insert(out.end(), fixed, fixed + sizeof(fixed));
  out.push_back(static_cast<uint8_t>(0xF8u | (stuffing & 0x07u)));
  out.insert(out.end(), stuffing, 0xFF);
}

// ISO 13818-1 system_header(): header_length (16) then, in the fixed six
// octets, marker_bit 1 | rate_bound 22 | marker_bit 1 | audio_bound 6 |
// fixed_flag 1 | CSPS_flag 1 | system_audio_lock_flag 1 | system_video_lock_flag
// 1 | marker_bit 1 | video_bound 5 | packet_rate_restriction_flag 1 |
// reserved_bits 7, then the P-STD buffer loop. Nothing downstream reads the
// fixed part, so only its length has to be right -- which is the point.
void append_system_header(std::vector<uint8_t> &out, size_t header_length = 6) {
  const uint32_t rate_bound = 1000000;  // 50 bytes/s units, 22 bits wide
  out.push_back(0x00);
  out.push_back(0x00);
  out.push_back(0x01);
  out.push_back(0xBB);
  push_u16(out, header_length);
  // marker, rate_bound, marker
  out.push_back(static_cast<uint8_t>(0x80u | ((rate_bound >> 15) & 0x7Fu)));
  out.push_back(static_cast<uint8_t>((rate_bound >> 7) & 0xFFu));
  out.push_back(static_cast<uint8_t>(((rate_bound << 1) & 0xFEu) | 0x01u));
  // audio_bound 0, fixed_flag 0, CSPS_flag 0
  out.push_back(0x00);
  // the two lock flags, the marker bit, video_bound 1
  out.push_back(0xE1);
  // packet_rate_restriction_flag 0, seven reserved bits
  out.push_back(0x7F);
  for (size_t i = 6; i < header_length; ++i) {
    out.push_back(0x00);  // whatever the P-STD buffer loop would have held
  }
}

// One elementary stream entry of a program stream map: its stream_type and the
// elementary_stream_id that carries it. A struct rather than a std::pair so the
// literals below can be written as they read in the standard, without a
// narrowing conversion through the pair's converting constructor.
struct PsmEntry {
  uint8_t stream_type;
  uint8_t es_id;
};

// ISO 13818-1 program_stream_map(): program_stream_map_length (16) counts
// everything after it up to and including the CRC_32, so it is
// 1 + 1 + 2 + program_stream_info_length + 2 + the map + 4.
void append_psm(std::vector<uint8_t> &out, std::initializer_list<PsmEntry> streams,
                uint8_t version = 0, bool current_next = true) {
  const size_t es_map_length = 4 * streams.size();
  out.push_back(0x00);
  out.push_back(0x00);
  out.push_back(0x01);
  out.push_back(0xBC);
  push_u16(out, 10 + es_map_length);
  // current_next_indicator 1 | reserved 2 | program_stream_map_version 5
  out.push_back(static_cast<uint8_t>((current_next ? 0x80u : 0x00u) | 0x60u |
                                     (static_cast<unsigned>(version) & 0x1Fu)));
  out.push_back(0xFF);  // reserved 7 bits | marker_bit 1
  push_u16(out, 0);     // program_stream_info_length
  push_u16(out, es_map_length);
  for (const PsmEntry &entry : streams) {
    out.push_back(entry.stream_type);
    out.push_back(entry.es_id);
    push_u16(out, 0);  // elementary_stream_info_length
  }
  for (int i = 0; i < 4; ++i) {
    out.push_back(0x00);  // CRC_32
  }
}

// The five-octet PTS field of a PES header (ISO 13818-1 table 2-21): a four-bit
// prefix, then three groups of timestamp bits separated by marker bits.
void append_pts(std::vector<uint8_t> &out, uint64_t pts) {
  out.push_back(static_cast<uint8_t>(
      0x21u | static_cast<uint8_t>((pts >> 29) & 0x0Eu)));
  out.push_back(static_cast<uint8_t>((pts >> 22) & 0xFFu));
  out.push_back(static_cast<uint8_t>(((pts >> 14) & 0xFEu) | 0x01u));
  out.push_back(static_cast<uint8_t>((pts >> 7) & 0xFFu));
  out.push_back(static_cast<uint8_t>(((pts << 1) & 0xFEu) | 0x01u));
}

struct PesOptions {
  bool with_pts = false;
  uint64_t pts = 0;
  // Extra octets counted by PES_header_data_length and skipped by it: where
  // ESCR, ES_rate, a trick-mode field, a CRC or a stuffing would sit.
  size_t header_extra = 0;
  // PES_packet_length = 0: legal for video, means "to the end of the PS packet".
  bool unbounded_length = false;
};

// ISO 13818-1 PES packet: start code prefix, stream_id, PES_packet_length, then
// '10' | scrambling 2 | priority 1 | data_alignment_indicator 1 | copyright 1 |
// original_or_copy 1, PTS_DTS_flags 2 | ESCR_flag 1 | ES_rate_flag 1 |
// DSM_trick_mode_flag 1 | additional_copy_info_flag 1 | PES_CRC_flag 1 |
// PES_extension_flag 1, PES_header_data_length 8, and the optional fields.
void append_pes(std::vector<uint8_t> &out, uint8_t stream_id,
                const std::vector<uint8_t> &es, const PesOptions &options = {}) {
  out.push_back(0x00);
  out.push_back(0x00);
  out.push_back(0x01);
  out.push_back(stream_id);
  const size_t header_length = (options.with_pts ? 5u : 0u) + options.header_extra;
  const size_t packet_length = 3 + header_length + es.size();
  if (options.unbounded_length) {
    push_u16(out, 0);
  } else {
    push_u16(out, packet_length);
  }
  out.push_back(0x80);  // '10', no scrambling, no priority, no alignment
  out.push_back(static_cast<uint8_t>(options.with_pts ? 0x80u : 0x00u));  // PTS only
  out.push_back(static_cast<uint8_t>(header_length));
  if (options.with_pts) {
    append_pts(out, options.pts);
  }
  out.insert(out.end(), options.header_extra, 0xFF);
  out.insert(out.end(), es.begin(), es.end());
}

// A NAL unit as it sits in the ES: a four-octet start code and then the bytes
// NAT-03 expects to receive *without* one.
std::vector<uint8_t> annex_b(const std::vector<uint8_t> &nal) {
  std::vector<uint8_t> out = {0x00, 0x00, 0x00, 0x01};
  out.insert(out.end(), nal.begin(), nal.end());
  return out;
}

// An H.264 IDR slice (nal_unit_type 5, so NAT-03 sees a keyframe) and a
// non-IDR slice (type 1). Both are short and made up; the tests only ever
// compare them against themselves. The non-IDR header is 0x61 rather than the
// more usual 0x41 because NAT-03's `VideoCodec::PS` path reads *both* codecs'
// type sets (its decision 14) and 0x41 is nal_unit_type 32 -- a VPS -- to H.265.
const std::vector<uint8_t> kIdrNal = {0x65, 0x88, 0x84, 0x21};
const std::vector<uint8_t> kNonIdrNal = {0x61, 0x9A, 0x02};

// One RTP payload as the caller would hand it over.
struct Payload {
  std::vector<uint8_t> bytes;
  bool marker = true;
  uint64_t ts = 0;
  uint32_t frame = 0;
  bool gap = false;
};

// Everything a test needs after a run: the access units in the order they were
// handed over, the per-call outputs, the first error, and the counters.
struct FeedResult {
  std::vector<PsAccessUnit> units;
  std::vector<PsDemuxOutput> outputs;  // one per payload, then finish()
  std::string first_error;
  PsDemuxStats stats;
  PsStreamKind kind = PsStreamKind::Unknown;
};

FeedResult feed(const std::vector<Payload> &payloads) {
  PsDemux demux;
  FeedResult result;
  for (const Payload &payload : payloads) {
    const PsDemuxOutput out =
        demux.onPacket(payload.bytes.data(), payload.bytes.size(), payload.marker,
                       payload.ts, payload.frame, payload.gap);
    if (result.first_error.empty() && !out.error.empty()) {
      result.first_error = out.error;
    }
    for (const PsAccessUnit &unit : out.access_units) {
      result.units.push_back(unit);
    }
    result.outputs.push_back(out);
  }
  const PsDemuxOutput tail = demux.finish();
  if (result.first_error.empty() && !tail.error.empty()) {
    result.first_error = tail.error;
  }
  for (const PsAccessUnit &unit : tail.access_units) {
    result.units.push_back(unit);
  }
  result.outputs.push_back(tail);
  result.stats = demux.stats();
  result.kind = demux.video_kind();
  return result;
}

// The common shape: one pack header, one H.264 video PES packet with one NAL
// unit. Returns the whole PS packet as one RTP payload, marker set.
Payload one_frame_packet(const std::vector<uint8_t> &nal, uint32_t frame,
                         uint64_t ts = 0) {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(nal));
  return Payload{ps, true, ts, frame, false};
}

}  // namespace

TEST_CASE("PsDemux: pack_header, its stuffing and one video PES yield one access unit") {
  // Seven stuffing octets after the pack header. A parser that ignored
  // pack_stuffing_length would start reading at a run of 0xFF, find no start
  // code and drop the packet with "noPackStart".
  std::vector<uint8_t> ps;
  append_pack_header(ps, 7);
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, true, 9000, 12, false}});
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].nals.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
  CHECK(result.units[0].first_frame == 12);
  CHECK(result.units[0].pts == 0);
  CHECK_FALSE(result.units[0].has_pts);
  CHECK_FALSE(result.units[0].corrupt);
  CHECK_FALSE(result.units[0].sequence_gap);
  CHECK(result.first_error.empty());
  CHECK(result.stats.rtp_payloads == 1);
  CHECK(result.stats.ps_packets == 1);
  CHECK(result.stats.ps_packets_dropped == 0);
  CHECK(result.stats.resyncs == 0);
  CHECK(result.stats.pes_video == 1);
  CHECK(result.stats.access_units == 1);

  // Decision 5: the access unit closes at the first start code *after* the PES
  // boundary, so the payload's own call carries nothing and finish() hands the
  // unit over.
  CHECK(result.outputs[0].access_units.empty());
  CHECK(result.outputs[0].error.empty());
  REQUIRE(result.outputs[1].access_units.size() == 1);
}

TEST_CASE("PsDemux: a system_header is skipped through its declared length") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_system_header(ps, 12);  // six fixed octets and six of the P-STD loop
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, true, 1, 1, false}});
  CHECK(result.stats.system_headers == 1);
  CHECK(result.first_error.empty());
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].nals.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
}

TEST_CASE("PsDemux: a system_header whose length runs past the packet is badSystemHeader") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  // 00 00 01 BB with header_length 0x00FF and nothing behind it.
  ps.insert(ps.end(), {0x00, 0x00, 0x01, 0xBB, 0x00, 0xFF});
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, true, 1, 1, false}});
  CHECK(result.first_error == "badSystemHeader");
  CHECK(result.units.empty());
  CHECK(result.stats.parse_errors == 1);
  CHECK(result.stats.system_headers == 0);
  // The video PES packet behind it is lost with the rest of the PS packet, and
  // the count is what says so.
  CHECK(result.stats.pes_video == 0);
}

TEST_CASE("PsDemux: a system_header shorter than its fixed part is badSystemHeader") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  // header_length 3 cannot cover the six octets of the fixed part.
  ps.insert(ps.end(), {0x00, 0x00, 0x01, 0xBB, 0x00, 0x03, 0x80, 0x00, 0x01});

  const FeedResult result = feed({Payload{ps, true, 1, 1, false}});
  CHECK(result.first_error == "badSystemHeader");
  CHECK(result.units.empty());
  CHECK(result.stats.parse_errors == 1);
}

TEST_CASE("PsDemux: the PSM names H.264/H.265/G.711A and counts an unsupported stream_type") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  // 0x1B = H.264, 0x24 = H.265, 0x90 = G.711A (GB28181's private value), and
  // 0x03 = MPEG-1 audio, which this class does not know.
  append_psm(ps, {{0x1B, 0xE0}, {0x24, 0xE1}, {0x90, 0xC0}, {0x03, 0xC1}});
  append_pes(ps, 0xE0, annex_b(kIdrNal));
  append_pes(ps, 0xE1, annex_b(kIdrNal));
  append_pes(ps, 0xC0, std::vector<uint8_t>(160, 0xD5));  // G.711A, dropped
  append_pes(ps, 0xC1, std::vector<uint8_t>(160, 0x00));  // unsupported, skipped

  const FeedResult result = feed({Payload{ps, true, 1, 3, false}});
  CHECK(result.first_error.empty());  // an unsupported stream_type is not an error
  CHECK(result.stats.psm_count == 1);
  CHECK(result.stats.pes_video == 2);
  CHECK(result.stats.pes_audio == 1);
  CHECK(result.stats.pes_unsupported == 1);
  CHECK(result.stats.access_units == 2);
  REQUIRE(result.units.size() == 2);
  CHECK(result.units[0].kind == PsStreamKind::H264);
  CHECK(result.units[0].nals.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
  CHECK(result.units[1].kind == PsStreamKind::H265);
  CHECK(result.units[1].nals[0] == kIdrNal);
  // The audio ES never reaches an access unit: 160 octets of 0xD5 are not NAL
  // units and must not be one either.
  for (const PsAccessUnit &unit : result.units) {
    CHECK(unit.nals.size() == 1);
  }
  CHECK(result.kind == PsStreamKind::H264);  // the lowest video id wins
  // The first unit closes at the second PES packet's start code, so this one
  // call carries it; the second waits for the next start code, which is finish.
  REQUIRE(result.outputs[0].access_units.size() == 1);
  REQUIRE(result.outputs[1].access_units.size() == 1);
}

TEST_CASE("PsDemux: one call can carry more than one access unit") {
  // Three video PES packets in one PS packet: the first closes at the second's
  // start code and the second at the third's, so one call hands over two units
  // and finish() the last. This is why the output is a vector and not a single
  // access unit (decision 6).
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));
  append_pes(ps, 0xE0, annex_b(kNonIdrNal));
  append_pes(ps, 0xE0, annex_b(kNonIdrNal));

  const FeedResult result = feed({Payload{ps, true, 1, 7, false}});
  CHECK(result.first_error.empty());
  CHECK(result.stats.access_units == 3);
  REQUIRE(result.outputs[0].access_units.size() == 2);
  REQUIRE(result.outputs[1].access_units.size() == 1);
  REQUIRE(result.units.size() == 3);
  CHECK(result.units[0].nals[0] == kIdrNal);
  CHECK(result.units[1].nals[0] == kNonIdrNal);
  CHECK(result.units[2].nals[0] == kNonIdrNal);
  // Every unit of the PS packet names the packet it came from.
  CHECK(result.units[0].first_frame == 7);
  CHECK(result.units[1].first_frame == 7);
}

TEST_CASE("PsDemux: PES_packet_length and PES_header_data_length are respected") {
  // The first PES packet has eight octets of header data (a run of 0xFF) that
  // PES_header_data_length skips, and the second follows it exactly. A parser
  // that ignored either length would read the 0xFF run as ES data and hand
  // NAT-03 a NAL unit that is not there.
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kNonIdrNal), PesOptions{true, 12345, 8, false});
  append_pes(ps, 0xE0, annex_b(kIdrNal), PesOptions{true, 54321, 0, false});

  const FeedResult result = feed({Payload{ps, true, 1, 2, false}});
  CHECK(result.first_error.empty());
  CHECK(result.stats.pes_video == 2);
  REQUIRE(result.units.size() == 2);
  CHECK(result.units[0].nals.size() == 1);
  CHECK(result.units[0].nals[0] == kNonIdrNal);
  CHECK(result.units[1].nals.size() == 1);
  CHECK(result.units[1].nals[0] == kIdrNal);
  // The PTS of each unit is the PTS of its own PES packet (decision 7).
  CHECK(result.units[0].has_pts);
  CHECK(result.units[0].pts == 12345);
  CHECK(result.units[1].has_pts);
  CHECK(result.units[1].pts == 54321);
}

TEST_CASE("PsDemux: a PES_packet_length of zero runs to the end of the PS packet") {
  std::vector<uint8_t> es = annex_b(kIdrNal);
  const std::vector<uint8_t> second = annex_b(kNonIdrNal);
  es.insert(es.end(), second.begin(), second.end());

  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, es, PesOptions{false, 0, 0, true});

  const FeedResult result = feed({Payload{ps, true, 1, 3, false}});
  CHECK(result.first_error.empty());
  REQUIRE(result.units.size() == 1);
  REQUIRE(result.units[0].nals.size() == 2);
  CHECK(result.units[0].nals[0] == kIdrNal);
  CHECK(result.units[0].nals[1] == kNonIdrNal);
}

TEST_CASE("PsDemux: a PS packet split over three RTP payloads is reassembled by the marker") {
  std::vector<uint8_t> ps;
  append_pack_header(ps, 3);
  append_pes(ps, 0xE0, annex_b(kIdrNal), PesOptions{true, 9000, 4, false});

  const size_t first = 9;
  const size_t second = ps.size() - 6;
  REQUIRE(first < second);
  const std::vector<uint8_t> part1(ps.begin(), ps.begin() + first);
  const std::vector<uint8_t> part2(ps.begin() + first, ps.begin() + second);
  const std::vector<uint8_t> part3(ps.begin() + second, ps.end());

  const FeedResult result = feed({
      Payload{part1, false, 9000, 40, false},
      Payload{part2, false, 9000, 41, false},
      Payload{part3, true, 9000, 42, false},
  });
  CHECK(result.first_error.empty());
  CHECK(result.stats.ps_packets == 1);
  CHECK(result.stats.marker_missing == 0);
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].nals.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
  // The unit's first_frame is the *first* RTP payload of the PS packet it came
  // from, which is what a viewer jumping to it wants to land on.
  CHECK(result.units[0].first_frame == 40);
  CHECK(result.units[0].pts == 9000);
  // The two payloads that only contributed bytes hand nothing over.
  CHECK(result.outputs[0].access_units.empty());
  CHECK(result.outputs[1].access_units.empty());
}

TEST_CASE("PsDemux: a NAL unit split across two PES packets comes out joined") {
  // The first PES packet carries a start code and the head of a NAL unit; the
  // second continues it and then starts the next NAL unit. The ES is scanned as
  // one byte stream, so the head and the tail are one NAL unit -- and the unit
  // it belongs to keeps the first PES packet's PTS.
  const std::vector<uint8_t> head = {0x65, 0x88, 0x84};
  const std::vector<uint8_t> tail = {0x21, 0x7F};
  std::vector<uint8_t> joined = head;
  joined.insert(joined.end(), tail.begin(), tail.end());

  std::vector<uint8_t> es1 = {0x00, 0x00, 0x00, 0x01};
  es1.insert(es1.end(), head.begin(), head.end());
  std::vector<uint8_t> es2 = tail;
  const std::vector<uint8_t> next = {0x00, 0x00, 0x01, 0x61, 0x9A};
  es2.insert(es2.end(), next.begin(), next.end());

  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, es1, PesOptions{true, 700, 0, false});
  append_pes(ps, 0xE0, es2, PesOptions{true, 800, 0, false});

  const FeedResult result = feed({Payload{ps, true, 1, 4, false}});
  CHECK(result.first_error.empty());
  CHECK(result.stats.pes_video == 2);
  REQUIRE(result.units.size() == 2);
  CHECK(result.units[0].nals.size() == 1);
  CHECK(result.units[0].nals[0] == joined);
  CHECK(result.units[0].pts == 700);
  CHECK(result.units[1].nals.size() == 1);
  CHECK(result.units[1].nals[0] == std::vector<uint8_t>({0x61, 0x9A}));
}

TEST_CASE("PsDemux: a NAL unit split across two PS packets comes out joined") {
  // The same split, one level up: the two PES packets are in two PS packets,
  // and the ES scanner's state crosses that boundary as well.
  std::vector<uint8_t> es1 = {0x00, 0x00, 0x01, 0x65, 0x88};
  const std::vector<uint8_t> es2 = {0x84, 0x21, 0x00, 0x00, 0x01, 0x61, 0x9A};

  std::vector<uint8_t> ps1;
  append_pack_header(ps1);
  append_pes(ps1, 0xE0, es1, PesOptions{false, 0, 0, false});
  std::vector<uint8_t> ps2;
  append_pack_header(ps2);
  append_pes(ps2, 0xE0, es2, PesOptions{false, 0, 0, false});

  const FeedResult result = feed({
      Payload{ps1, true, 10, 1, false},
      Payload{ps2, true, 20, 2, false},
  });
  CHECK(result.first_error.empty());
  CHECK(result.stats.ps_packets == 2);
  REQUIRE(result.units.size() == 2);
  CHECK(result.units[0].nals[0] == std::vector<uint8_t>({0x65, 0x88, 0x84, 0x21}));
  CHECK(result.units[0].first_frame == 1);
  CHECK(result.units[1].nals[0] == std::vector<uint8_t>({0x61, 0x9A}));
  CHECK(result.units[1].first_frame == 2);
}

TEST_CASE("PsDemux: a PES packet without a PTS inherits the last one and says so") {
  const FeedResult result = feed({
      one_frame_packet(kIdrNal, 1, 1000),
      one_frame_packet(kNonIdrNal, 2, 2000),
  });
  CHECK(result.first_error.empty());
  REQUIRE(result.units.size() == 2);
  // Neither PES packet carries one, so there is nothing to inherit and the
  // demuxer does not invent a time: pts stays 0 and has_pts stays false.
  CHECK_FALSE(result.units[0].has_pts);
  CHECK(result.units[0].pts == 0);
  CHECK_FALSE(result.units[1].has_pts);
  CHECK(result.units[1].pts == 0);

  // Now the same shape with a real PTS on the first packet only.
  std::vector<uint8_t> ps1;
  append_pack_header(ps1);
  append_pes(ps1, 0xE0, annex_b(kIdrNal), PesOptions{true, 90000, 0, false});
  std::vector<uint8_t> ps2;
  append_pack_header(ps2);
  append_pes(ps2, 0xE0, annex_b(kNonIdrNal), PesOptions{false, 0, 0, false});

  const FeedResult second = feed({
      Payload{ps1, true, 1000, 1, false},
      Payload{ps2, true, 2000, 2, false},
  });
  REQUIRE(second.units.size() == 2);
  CHECK(second.units[0].has_pts);
  CHECK(second.units[0].pts == 90000);
  CHECK_FALSE(second.units[1].has_pts);
  CHECK(second.units[1].pts == 90000);
}

TEST_CASE("PsDemux: a PS packet that does not start with a pack header is resynchronised") {
  // A capture that began in the middle of a PS packet: three octets of the
  // previous structure, then the pack header of the first complete one.
  std::vector<uint8_t> ps = {0xAA, 0xBB, 0xCC};
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, true, 1, 5, false}});
  CHECK(result.first_error.empty());  // recovered, so not an error
  CHECK(result.stats.resyncs == 1);
  CHECK(result.stats.ps_packets == 1);
  CHECK(result.stats.ps_packets_dropped == 0);
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
  CHECK(result.units[0].corrupt);  // the bytes before the resync are gone
}

TEST_CASE("PsDemux: a PS packet with no pack header at all is dropped as noPackStart") {
  const std::vector<uint8_t> ps = {0x11, 0x22, 0x33, 0x44, 0x55};
  const FeedResult result = feed({Payload{ps, true, 1, 1, false}});
  CHECK(result.first_error == "noPackStart");
  CHECK(result.units.empty());
  CHECK(result.stats.ps_packets == 1);
  CHECK(result.stats.ps_packets_dropped == 1);
  CHECK(result.stats.resyncs == 0);
  CHECK(result.stats.access_units == 0);
}

TEST_CASE("PsDemux: a pack header shorter than its fourteen octets is badPackHeader") {
  const std::vector<uint8_t> ps = {0x00, 0x00, 0x01, 0xBA, 0x44, 0x00, 0x04};
  const FeedResult result = feed({Payload{ps, true, 1, 1, false}});
  CHECK(result.first_error == "badPackHeader");
  CHECK(result.units.empty());
  CHECK(result.stats.ps_packets_dropped == 1);
  CHECK(result.stats.parse_errors == 1);
}

TEST_CASE("PsDemux: pack stuffing that runs past the packet is badPackHeader") {
  std::vector<uint8_t> ps;
  append_pack_header(ps, 5);
  // The header declares five stuffing octets; two of them are there.
  ps.resize(14 + 2);
  const FeedResult result = feed({Payload{ps, true, 1, 1, false}});
  CHECK(result.first_error == "badPackHeader");
  CHECK(result.units.empty());
  CHECK(result.stats.ps_packets_dropped == 1);
  CHECK(result.stats.parse_errors == 1);
}

TEST_CASE("PsDemux: a padding stream is skipped through its length and counted") {
  // 00 00 01 BE is padding_stream: no PES header at all, so the payload begins
  // right after the length field. Getting that wrong lands the parser inside
  // the padding and costs the video PES packet behind it.
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  ps.insert(ps.end(), {0x00, 0x00, 0x01, 0xBE, 0x00, 0x08});
  ps.insert(ps.end(), 8, 0xFF);  // the padding bytes themselves
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, true, 1, 20, false}});
  CHECK(result.first_error.empty());
  CHECK(result.stats.other_pes == 1);
  CHECK(result.stats.pes_video == 1);
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
}

TEST_CASE("PsDemux: a PES header that runs past its own packet is badPes") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));
  // 00 00 01 E0 with PES_packet_length 4 and PES_header_data_length 0xFF: the
  // header that length declares cannot be inside the packet.
  ps.insert(ps.end(), {0x00, 0x00, 0x01, 0xE0, 0x00, 0x04,
                       0x80, 0x00, 0xFF, 0x00});

  const FeedResult result = feed({Payload{ps, true, 1, 21, false}});
  CHECK(result.first_error == "badPes");
  CHECK(result.stats.parse_errors == 1);
  CHECK(result.stats.pes_video == 1);  // the well-formed PES packet before it
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
}

TEST_CASE("PsDemux: an unknown start code keeps what was parsed and reports it") {
  // 00 00 01 B0 is an MPEG-1 video start code: below 0xBD, so there is no length
  // field to skip it with and the rest of the PS packet is unusable.
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));
  ps.insert(ps.end(), {0x00, 0x00, 0x01, 0xB0, 0x11, 0x22});

  const FeedResult result = feed({Payload{ps, true, 1, 6, false}});
  CHECK(result.first_error == "unknownStartCode");
  CHECK(result.stats.unknown_start_codes == 1);
  CHECK(result.stats.pes_video == 1);
  // What came before the unknown start code was a complete PES packet, so the
  // access unit survives -- flagged, because the packet it was in did not end
  // where it should have.
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
  CHECK(result.units[0].corrupt);
}

TEST_CASE("PsDemux: a program_end_code ends the PS packet cleanly") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));
  ps.insert(ps.end(), {0x00, 0x00, 0x01, 0xB9});
  ps.insert(ps.end(), {0xDE, 0xAD, 0xBE, 0xEF});  // whatever follows is ignored

  const FeedResult result = feed({Payload{ps, true, 1, 8, false}});
  CHECK(result.first_error.empty());
  CHECK(result.units.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
  CHECK_FALSE(result.units[0].corrupt);
}

TEST_CASE("PsDemux: a PS packet cut short by a timestamp change is used and flagged") {
  // The marker bit never arrives, so the packet is one RTP payload short. The
  // bytes that are here are still real data: the unit comes out behind a
  // corrupt flag, the event is counted, and no error is raised (decision 1).
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({
      Payload{ps, false, 100, 1, false},
      Payload{ps, true, 200, 2, false},
  });
  CHECK(result.first_error.empty());
  CHECK(result.stats.marker_missing == 1);
  CHECK(result.stats.ps_packets == 2);
  CHECK(result.stats.access_units == 2);
  REQUIRE(result.units.size() == 2);
  CHECK(result.units[0].corrupt);
  CHECK_FALSE(result.units[1].corrupt);
}

TEST_CASE("PsDemux: a PS packet still open at finish is parsed and counted") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, false, 1, 9, false}});
  CHECK(result.first_error.empty());
  CHECK(result.stats.truncated_ps_packets == 1);
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
  CHECK(result.units[0].corrupt);
}

TEST_CASE("PsDemux: finish() is one-shot") {
  PsDemux demux;
  const Payload payload = one_frame_packet(kIdrNal, 1);
  demux.onPacket(payload.bytes.data(), payload.bytes.size(), payload.marker,
                 payload.ts, payload.frame, payload.gap);

  const PsDemuxOutput first = demux.finish();
  const PsDemuxOutput second = demux.finish();
  REQUIRE(first.access_units.size() == 1);
  CHECK(second.access_units.empty());
  CHECK(second.error.empty());
  CHECK(demux.stats().access_units == 1);
}

TEST_CASE("PsDemux: a zero-length RTP payload is empty and touches nothing else") {
  PsDemux demux;
  const PsDemuxOutput out = demux.onPacket(nullptr, 0, true, 5, 5, false);
  CHECK(out.error == "empty");
  CHECK(out.access_units.empty());
  CHECK(demux.stats().rtp_payloads == 1);
  CHECK(demux.stats().ps_packets == 0);
  CHECK(demux.stats().access_units == 0);
}

TEST_CASE("PsDemux: an empty NAL unit (two start codes in a row) is skipped") {
  std::vector<uint8_t> es = {0x00, 0x00, 0x01, 0x00, 0x00, 0x01};
  es.insert(es.end(), kIdrNal.begin(), kIdrNal.end());

  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, es);

  const FeedResult result = feed({Payload{ps, true, 1, 1, false}});
  CHECK(result.first_error.empty());
  REQUIRE(result.units.size() == 1);
  REQUIRE(result.units[0].nals.size() == 1);
  CHECK(result.units[0].nals[0] == kIdrNal);
}

TEST_CASE("PsDemux: the zeros in front of a four-octet start code are not NAL data") {
  // 00 00 00 01 is 00 00 01 preceded by leading_zero_8bits (ISO/IEC 14496-10
  // Annex B), so the fourth zero belongs to the start code and not to the NAL
  // unit that ends there.
  std::vector<uint8_t> es = annex_b({0x65, 0x88});
  const std::vector<uint8_t> second = annex_b({0x61, 0x9A});
  es.insert(es.end(), second.begin(), second.end());

  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, es);

  const FeedResult result = feed({Payload{ps, true, 1, 1, false}});
  CHECK(result.first_error.empty());
  REQUIRE(result.units.size() == 1);
  REQUIRE(result.units[0].nals.size() == 2);
  CHECK(result.units[0].nals[0] == std::vector<uint8_t>({0x65, 0x88}));
  CHECK(result.units[0].nals[1] == std::vector<uint8_t>({0x61, 0x9A}));
}

TEST_CASE("PsDemux: without a PSM the reserved stream id ranges decide") {
  // No PSM at all: 0xE0-0xEF is video and 0xC0-0xDF is audio, and the codec is
  // Unknown because nothing named it (decision 8).
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));
  append_pes(ps, 0xC0, std::vector<uint8_t>(80, 0xD5));

  const FeedResult result = feed({Payload{ps, true, 1, 11, false}});
  CHECK(result.first_error.empty());
  CHECK(result.stats.psm_count == 0);
  CHECK(result.stats.pes_video == 1);
  CHECK(result.stats.pes_audio == 1);
  CHECK(result.kind == PsStreamKind::Unknown);
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].kind == PsStreamKind::Unknown);
  CHECK(result.units[0].nals[0] == kIdrNal);
}

TEST_CASE("PsDemux: a PSM that is not current is ignored and counted") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_psm(ps, {{0x1B, 0xE0}}, 0, false);  // current_next_indicator = 0
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, true, 1, 13, false}});
  CHECK(result.first_error.empty());
  CHECK(result.stats.psm_ignored == 1);
  CHECK(result.stats.psm_count == 0);
  // The id-range fallback is still in force, so the video PES packet is not lost.
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].kind == PsStreamKind::Unknown);
  CHECK(result.units[0].nals[0] == kIdrNal);
}

TEST_CASE("PsDemux: a PSM that is not an exact fit is badPsm and does not replace the map") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  // A PSM whose elementary_stream_map_length (6) is two octets more than the
  // single four-octet entry that follows, so the loop cannot exactly fill the
  // length that declared it -- the map cannot be trusted entry for entry.
  ps.insert(ps.end(), {0x00, 0x00, 0x01, 0xBC,  // program_stream_map_start_code
                       0x00, 0x10,              // program_stream_map_length
                       0xE0, 0xFF,              // current_next + version, reserved + marker
                       0x00, 0x00,              // program_stream_info_length
                       0x00, 0x06,              // elementary_stream_map_length
                       0x1B, 0xE0, 0x00, 0x00,  // one whole entry: H.264 on 0xE0
                       0x00, 0x00,              // two octets that are not an entry
                       0x00, 0x00, 0x00, 0x00});  // CRC_32
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, true, 1, 14, false}});
  CHECK(result.first_error == "badPsm");
  CHECK(result.stats.psm_count == 0);
  CHECK(result.stats.parse_errors == 1);
  CHECK(result.units.empty());
}

TEST_CASE("PsDemux: a gap reported by the caller is carried on the access unit") {
  std::vector<uint8_t> ps;
  append_pack_header(ps);
  append_pes(ps, 0xE0, annex_b(kIdrNal));

  const FeedResult result = feed({Payload{ps, true, 1, 21, true}});
  CHECK(result.first_error.empty());
  REQUIRE(result.units.size() == 1);
  CHECK(result.units[0].sequence_gap);
  CHECK(result.units[0].corrupt);  // damage is damage, whichever flag raised it
}

TEST_CASE("PsDemux: a NAL unit past kMaxNalBytes is dropped and counted, not truncated") {
  // One NAL unit spread over five PS packets, a megabyte at a time: the cap is
  // crossed inside the fifth, so nothing about it may reach NAT-03 -- a
  // truncated NAL unit would look whole to it (decision 13).
  const size_t chunk = 1024u * 1024u;
  const std::vector<uint8_t> filler(chunk, 0xAA);

  std::vector<uint8_t> first;
  append_pack_header(first);
  std::vector<uint8_t> es = {0x00, 0x00, 0x00, 0x01};
  es.insert(es.end(), filler.begin(), filler.end());
  append_pes(first, 0xE0, es, PesOptions{false, 0, 0, true});

  std::vector<Payload> payloads;
  payloads.push_back(Payload{first, true, 1, 1, false});
  for (uint32_t i = 0; i < 4; ++i) {
    std::vector<uint8_t> more;
    append_pack_header(more);
    append_pes(more, 0xE0, filler, PesOptions{false, 0, 0, true});
    payloads.push_back(Payload{more, true, 1, 2 + i, false});
  }

  const FeedResult result = feed(payloads);
  CHECK(result.first_error == "nalTooLarge");
  CHECK(result.stats.nal_too_large == 1);
  CHECK(result.stats.ps_packets == 5);
  CHECK(result.units.empty());
  CHECK(result.stats.access_units == 0);
}

TEST_CASE("PsDemux: a PS packet past kMaxPsPacketBytes is dropped and counted") {
  PsDemux demux;
  const std::vector<uint8_t> huge(PsDemux::kMaxPsPacketBytes + 1, 0x00);
  const PsDemuxOutput out =
      demux.onPacket(huge.data(), huge.size(), false, 1, 1, false);
  CHECK(out.error == "psPacketTooLarge");
  CHECK(out.access_units.empty());
  CHECK(demux.stats().ps_packets_dropped == 1);
  CHECK(demux.stats().ps_packets == 0);

  // The reassembly is reset with the drop, so the next payload starts a new PS
  // packet rather than continuing the one that was abandoned.
  const Payload payload = one_frame_packet(kIdrNal, 2, 5);
  const PsDemuxOutput next = demux.onPacket(payload.bytes.data(),
                                            payload.bytes.size(), payload.marker,
                                            payload.ts, payload.frame, payload.gap);
  CHECK(next.error.empty());
  const PsDemuxOutput tail = demux.finish();
  REQUIRE(tail.access_units.size() == 1);
  CHECK(tail.access_units[0].nals[0] == kIdrNal);
  CHECK(demux.stats().ps_packets == 1);
}

TEST_CASE("PsDemux: the access units drive VideoAccessUnitBuilder as the mapping says") {
  // The end-to-end half of the contract: the demuxer's output goes straight into
  // NAT-03, with `marker = true`, `ext_ts = au.pts` in 90 kHz units and the
  // unit's own two flags. Two PS packets twenty milliseconds apart, the first
  // carrying an IDR.
  std::vector<uint8_t> ps1;
  append_pack_header(ps1);
  append_pes(ps1, 0xE0, annex_b(kIdrNal), PesOptions{true, 90000, 0, false});
  std::vector<uint8_t> ps2;
  append_pack_header(ps2);
  append_pes(ps2, 0xE0, annex_b(kNonIdrNal), PesOptions{true, 91800, 0, false});

  const FeedResult result = feed({
      Payload{ps1, true, 1000, 100, false},
      Payload{ps2, true, 2000, 120, false},
  });
  REQUIRE(result.units.size() == 2);

  VideoAuBuilderOptions options;
  options.codec = VideoCodec::PS;
  options.timestamp_rate = 90000;  // the PES PTS scale
  options.start_at_keyframe = true;
  VideoAccessUnitBuilder builder(options);
  for (const PsAccessUnit &unit : result.units) {
    builder.onPacket(unit.first_frame, unit.pts, true, unit.nals, unit.corrupt,
                     unit.sequence_gap);
  }
  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE(records.size() == 2);
  CHECK((records[0].flags & kVideoAuFlagKey) != 0);
  CHECK((records[1].flags & kVideoAuFlagKey) == 0);
  CHECK(records[0].first_frame == 100);
  CHECK(records[1].first_frame == 120);
  CHECK(records[0].pts_us == 0);
  CHECK(records[1].pts_us == 20000);  // 1800 ticks at 90 kHz

  std::vector<uint8_t> expected = annex_b(kIdrNal);
  const std::vector<uint8_t> tail = annex_b(kNonIdrNal);
  expected.insert(expected.end(), tail.begin(), tail.end());
  CHECK(es == expected);
  CHECK(records[0].byte_length == 4 + kIdrNal.size());
  CHECK(records[1].byte_offset == 4 + kIdrNal.size());
}
