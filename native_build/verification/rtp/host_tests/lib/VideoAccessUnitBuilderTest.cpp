// RTP5-NAT-03: access-unit assembly for the video export.
//
// What this file pins, and why each of it matters:
//
//   * Where one access unit ends. The boundary is the marker bit and the change
//     of RTP timestamp, and the packet that carries marker = 1 belongs to the
//     unit that *ends* there -- get that backwards and every frame is shifted by
//     one, which is silent in the byte stream and visible only as a stuttering
//     MP4. The lost-marker case is the same rule reached through the timestamp,
//     and both firing at once must still be one boundary.
//   * What the PTS is. Arrival order, no sorting, and the option-supplied rate
//     rather than a hard-coded 90 kHz. A B-frame stream is not monotonic, so the
//     test asserts both the exact microseconds *and* that the records were not
//     reordered to make them monotonic.
//   * Whether anything is injected. The parameter sets from the SDP go in only
//     when the stream never carried them in band, and the in-band case is
//     checked by rebuilding the same stream without the option and comparing the
//     two elementary streams byte for byte -- which is the comparison QA-01
//     makes against the Lua plugin.
//   * Which frames are written at all: start_at_keyframe, noKeyframe, and the
//     two drop_corrupt settings.
//
// Every input is a binary literal or built by a one-line helper that makes the
// NAL header readable, and every expected byte stream is either spelled out
// octet by octet or assembled from the same literals with an explicitly written
// start code.
//
// Case names all start with "VideoAccessUnitBuilder" so that
// `run_host_tests.ps1 -Test "*VideoAccessUnit*"` selects exactly this file's cases.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

#include "layanalyzer/rtp/depack/VideoAccessUnitBuilder.h"

using layanalyzer::rtp::kVideoAuFlagCorrupt;
using layanalyzer::rtp::kVideoAuFlagKey;
using layanalyzer::rtp::kVideoAuFlagParamSets;
using layanalyzer::rtp::VideoAccessUnitBuilder;
using layanalyzer::rtp::VideoAuBuilderOptions;
using layanalyzer::rtp::VideoAuRecord;
using layanalyzer::rtp::VideoCodec;

namespace {

// The four-octet Annex-B start code, written out here rather than taken from the
// implementation so that a change to the prefix is a test failure.
const std::vector<uint8_t> kStartCode = {0x00, 0x00, 0x00, 0x01};

// F = 0, NRI = 3, and the NAL type in the low five bits (RFC 6184 section 5.3's
// one-octet H.264 header).
std::vector<uint8_t> h264_nal(uint8_t type,
                              std::initializer_list<uint8_t> payload) {
  std::vector<uint8_t> nal;
  nal.push_back(static_cast<uint8_t>(0b01100000 | type));
  nal.insert(nal.end(), payload.begin(), payload.end());
  return nal;
}

// F = 0, nuh_layer_id = 0, nuh_temporal_id_plus1 = 1, type in bits 1-6 of the
// first octet (RFC 7798's two-octet H.265 header).
std::vector<uint8_t> h265_nal(uint8_t type,
                              std::initializer_list<uint8_t> payload) {
  std::vector<uint8_t> nal;
  nal.push_back(static_cast<uint8_t>(type << 1));
  nal.push_back(0b00000001);
  nal.insert(nal.end(), payload.begin(), payload.end());
  return nal;
}

// One access unit's Annex-B bytes as the builder has to write them: a start code
// in front of every NAL, nothing in between.
std::vector<uint8_t> annex_b(std::initializer_list<std::vector<uint8_t>> nals) {
  std::vector<uint8_t> out;
  for (const std::vector<uint8_t> &nal : nals) {
    out.insert(out.end(), kStartCode.begin(), kStartCode.end());
    out.insert(out.end(), nal.begin(), nal.end());
  }
  return out;
}

std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
  std::vector<uint8_t> out;
  for (const std::vector<uint8_t> &part : parts) {
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

// doctest has no stringification for std::vector<uint8_t> (it prints "{?}"), so
// CHECK_EQ on two byte strings would report nothing usable. This reports the
// first octet that differs instead.
bool bytes_equal(const std::vector<uint8_t> &actual,
                 const std::vector<uint8_t> &expected, size_t &first_difference) {
  const size_t common =
      actual.size() < expected.size() ? actual.size() : expected.size();
  for (size_t i = 0; i < common; ++i) {
    if (actual[i] != expected[i]) {
      first_difference = i;
      return false;
    }
  }
  if (actual.size() != expected.size()) {
    first_difference = common;
    return false;
  }
  first_difference = actual.size();
  return true;
}

#define CHECK_OCTETS(actual, expected)                                         \
  do {                                                                         \
    size_t au_difference = 0;                                                  \
    CHECK_MESSAGE(                                                             \
        bytes_equal((actual), (expected), au_difference),                      \
        "first difference at octet " << au_difference << " (got "              \
                                      << (actual).size() << " octets, want "   \
                                      << (expected).size() << ")");            \
  } while (false)

// The invariant every record list has to satisfy: the records tile the tail of
// the ES exactly, in order, with no gap and no overlap, starting at `first`.
// A wrong offset, a wrong length or a dropped byte range cannot pass this.
void check_tiles(const std::vector<VideoAuRecord> &records,
                 const std::vector<uint8_t> &es, uint64_t first) {
  uint64_t cursor = first;
  for (size_t index = 0; index < records.size(); ++index) {
    CHECK_EQ(records[index].byte_offset, cursor);
    cursor += records[index].byte_length;
  }
  CHECK_EQ(cursor, static_cast<uint64_t>(es.size()));
}

// Feeds one packet: NAT-01/NAT-02's output is what NAT-05 will pass in.
void feed(VideoAccessUnitBuilder &builder, uint32_t frame_number, uint64_t ext_ts,
          bool marker, const std::vector<std::vector<uint8_t>> &nals,
          bool corrupt = false, bool sequence_gap = false) {
  builder.onPacket(frame_number, ext_ts, marker, nals, corrupt, sequence_gap);
}

}  // namespace

TEST_CASE("VideoAccessUnitBuilder splits three access units on the marker bit") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88, 0x84});
  const std::vector<uint8_t> kTrailA = h264_nal(1, {0x11, 0x22});
  const std::vector<uint8_t> kTrailB = h264_nal(1, {0x33, 0x44});
  const std::vector<uint8_t> kTrailC = h264_nal(1, {0x55, 0x66});
  const std::vector<uint8_t> kTrailD = h264_nal(1, {0x77, 0x88});

  VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
  // Units 1 and 2 are two packets each: the boundary is the *packet that carries
  // the marker*, so both of its packets belong to the unit that ends there.
  feed(builder, 10, 9000, false, {kIdr});
  feed(builder, 11, 9000, true, {kTrailA});
  // Unit 2: the previous packet carried the marker *and* the timestamp changed.
  // That is one boundary, not two, and it must not leave an empty unit behind.
  feed(builder, 12, 18000, false, {kTrailB});
  feed(builder, 13, 18000, true, {kTrailC});
  // Unit 3.
  feed(builder, 14, 27000, true, {kTrailD});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 3u);

  // Spelled out octet by octet: 0b01100101 is the IDR NAL header, 0b01100001
  // the non-IDR one, and every NAL sits behind the same four-octet start code.
  const std::vector<uint8_t> expected = {
      0x00, 0x00, 0x00, 0x01, 0b01100101, 0x88, 0x84,  // unit 1, IDR
      0x00, 0x00, 0x00, 0x01, 0b01100001, 0x11, 0x22,  // unit 1, non-IDR
      0x00, 0x00, 0x00, 0x01, 0b01100001, 0x33, 0x44,  // unit 2, first packet
      0x00, 0x00, 0x00, 0x01, 0b01100001, 0x55, 0x66,  // unit 2, marker packet
      0x00, 0x00, 0x00, 0x01, 0b01100001, 0x77, 0x88,  // unit 3
  };
  CHECK_OCTETS(es, expected);

  // byte_offset increases and byte_length is the unit's real extent in the ES.
  CHECK_EQ(records[0].byte_offset, static_cast<uint64_t>(0));
  CHECK_EQ(records[0].byte_length, static_cast<uint32_t>(14));
  CHECK_EQ(records[1].byte_offset, static_cast<uint64_t>(14));
  CHECK_EQ(records[1].byte_length, static_cast<uint32_t>(14));
  CHECK_EQ(records[2].byte_offset, static_cast<uint64_t>(28));
  CHECK_EQ(records[2].byte_length, static_cast<uint32_t>(7));
  check_tiles(records, es, 0);

  // The units are the packets' own units: first_frame is the first packet of
  // each, and only unit 1 has an IDR.
  CHECK_EQ(records[0].first_frame, 10u);
  CHECK_EQ(records[1].first_frame, 12u);
  CHECK_EQ(records[2].first_frame, 14u);
  CHECK_EQ(static_cast<int>(records[0].flags & kVideoAuFlagKey),
           static_cast<int>(kVideoAuFlagKey));
  CHECK_EQ(static_cast<int>(records[1].flags), 0);
  CHECK_EQ(static_cast<int>(records[2].flags), 0);

  // PTS from the stream's first timestamp, at the default 90 kHz: 9000 ticks is
  // 0.1 s and 18000 is 0.2 s.
  CHECK_EQ(records[0].pts_us, static_cast<uint64_t>(0));
  CHECK_EQ(records[1].pts_us, static_cast<uint64_t>(100000));
  CHECK_EQ(records[2].pts_us, static_cast<uint64_t>(200000));
}

TEST_CASE("VideoAccessUnitBuilder splits on the timestamp when the marker was lost") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kA = h264_nal(1, {0xA1});
  const std::vector<uint8_t> kB = h264_nal(1, {0xB1});

  VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
  // No marker bit anywhere: a sender that never sets it still gets frame-accurate
  // access units, because the RTP timestamp is the other half of rule 1.
  feed(builder, 0, 0, false, {kIdr});
  feed(builder, 1, 3000, false, {kA});
  feed(builder, 2, 6000, false, {kB});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 3u);
  CHECK_OCTETS(es, concat({annex_b({kIdr}), annex_b({kA}), annex_b({kB})}));
  check_tiles(records, es, 0);
  CHECK_EQ(records[1].first_frame, 1u);
  CHECK_EQ(records[2].first_frame, 2u);
}

TEST_CASE("VideoAccessUnitBuilder writes B-frame timestamps unsorted") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kP = h264_nal(1, {0x01});
  const std::vector<uint8_t> kB = h264_nal(1, {0x02});
  const std::vector<uint8_t> kLast = h264_nal(1, {0x03});

  VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
  // A display order of I, P, B, next-P arrives as timestamps 0, 6000, 3000,
  // 9000: the B frame's timestamp is behind the P frame it follows.
  feed(builder, 100, 0, true, {kIdr});
  feed(builder, 101, 6000, true, {kP});
  feed(builder, 102, 3000, true, {kB});
  feed(builder, 103, 9000, true, {kLast});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 4u);
  // 6000 * 1000000 / 90000 = 66666.6 -> 66666, and 3000 -> 33333.
  CHECK_EQ(records[0].pts_us, static_cast<uint64_t>(0));
  CHECK_EQ(records[1].pts_us, static_cast<uint64_t>(66666));
  CHECK_EQ(records[2].pts_us, static_cast<uint64_t>(33333));
  CHECK_EQ(records[3].pts_us, static_cast<uint64_t>(100000));
  // The point of the case: the records were *not* reordered to make the PTS
  // monotonic (card rule 2, and the Lua plugin does the same). The arrival order
  // is still visible in first_frame, and the byte stream is unpermuted.
  CHECK(records[1].pts_us > records[2].pts_us);
  CHECK_EQ(records[0].first_frame, 100u);
  CHECK_EQ(records[1].first_frame, 101u);
  CHECK_EQ(records[2].first_frame, 102u);
  CHECK_EQ(records[3].first_frame, 103u);
  CHECK_OCTETS(es, concat({annex_b({kIdr}), annex_b({kP}), annex_b({kB}),
                           annex_b({kLast})}));
}

TEST_CASE("VideoAccessUnitBuilder clamps a timestamp behind the stream's first") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kEarly = h264_nal(1, {0x09});

  VideoAuBuilderOptions options;
  VideoAccessUnitBuilder builder{options};
  // A capture that starts mid-GOP: the first packet is not the earliest
  // presentation time. An unsigned difference would wrap to ~1.8e19 microseconds
  // and hand MediaMuxer a five-hundred-thousand-year track; the record keeps the
  // arrival order and reports the earliest time an unsigned PTS can hold.
  feed(builder, 0, 90000, true, {kIdr});
  feed(builder, 1, 30000, true, {kEarly});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 2u);
  CHECK_EQ(records[0].pts_us, static_cast<uint64_t>(0));
  CHECK_EQ(records[1].pts_us, static_cast<uint64_t>(0));
  CHECK_EQ(records[0].first_frame, 0u);
  CHECK_EQ(records[1].first_frame, 1u);
}

TEST_CASE("VideoAccessUnitBuilder uses the configured timestamp rate") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kA = h264_nal(1, {0x01});

  // A 1 kHz clock: one timestamp unit is one millisecond.
  VideoAuBuilderOptions options;
  options.timestamp_rate = 1000;
  VideoAccessUnitBuilder builder{options};
  feed(builder, 0, 0, true, {kIdr});
  feed(builder, 1, 3000, true, {kA});
  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);
  REQUIRE_EQ(records.size(), 2u);
  CHECK_EQ(records[1].pts_us, static_cast<uint64_t>(3000000));

  // A rate of 0 is not a timebase: the 90000 default stands in rather than a
  // division by zero (header decision 2; `video_timestamp_rate` is 0 for a codec
  // that is not a video codec, which is a caller error that must not crash).
  VideoAuBuilderOptions zero_rate;
  zero_rate.timestamp_rate = 0;
  VideoAccessUnitBuilder zero_builder{zero_rate};
  feed(zero_builder, 0, 0, true, {kIdr});
  feed(zero_builder, 1, 9000, true, {kA});
  std::vector<uint8_t> zero_es;
  const std::vector<VideoAuRecord> zero_records = zero_builder.finish(zero_es);
  REQUIRE_EQ(zero_records.size(), 2u);
  CHECK_EQ(zero_records[1].pts_us, static_cast<uint64_t>(100000));
}

TEST_CASE("VideoAccessUnitBuilder injects the SDP parameter sets at the front") {
  const std::vector<uint8_t> kSps = h264_nal(7, {0x64, 0x00});
  const std::vector<uint8_t> kPps = h264_nal(8, {0xAB});
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kTrail = h264_nal(1, {0x11});

  VideoAuBuilderOptions options;
  options.sps = {kSps};
  options.pps = {kPps};
  VideoAccessUnitBuilder builder{options};
  // No SPS or PPS anywhere in the stream, so the SDP's pair is the only copy.
  feed(builder, 0, 0, true, {kIdr});
  feed(builder, 1, 3000, true, {kTrail});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 3u);

  const std::vector<uint8_t> head = annex_b({kSps, kPps});
  const std::vector<uint8_t> first = annex_b({kIdr});
  const std::vector<uint8_t> second = annex_b({kTrail});
  CHECK_OCTETS(es, concat({head, first, second}));

  // Record 0 is the injected pseudo access unit: the parameter sets, flagged
  // 0x04, with the *stream's* first frame number -- not the first kept unit's,
  // which happens to be the same here because nothing was dropped.
  CHECK_EQ(records[0].byte_offset, static_cast<uint64_t>(0));
  CHECK_EQ(records[0].byte_length, static_cast<uint32_t>(head.size()));
  CHECK_EQ(static_cast<int>(records[0].flags),
           static_cast<int>(kVideoAuFlagParamSets));
  CHECK_EQ(records[0].first_frame, 0u);
  // It carries no time of its own: it takes the PTS of the unit it precedes.
  CHECK_EQ(records[0].pts_us, records[1].pts_us);
  check_tiles(records, es, 0);

  // The real access units follow it, shifted by its length.
  CHECK_EQ(records[1].byte_offset, static_cast<uint64_t>(head.size()));
  CHECK_EQ(static_cast<int>(records[1].flags),
           static_cast<int>(kVideoAuFlagKey));
  // 3000 ticks at 90 kHz is 33333.3... microseconds, truncated.
  CHECK_EQ(records[2].pts_us, static_cast<uint64_t>(33333));
  // The in-band sets' original position is untouched: the stream was written
  // exactly as it arrived, with the injected bytes prepended and nothing else.
  CHECK_EQ(records[1].byte_length, static_cast<uint32_t>(first.size()));
  CHECK_EQ(records[2].byte_length, static_cast<uint32_t>(second.size()));
}

TEST_CASE(
    "VideoAccessUnitBuilder keeps the injected pseudo access unit when the "
    "leading access units are dropped") {
  const std::vector<uint8_t> kSps = h264_nal(7, {0x64});
  const std::vector<uint8_t> kPps = h264_nal(8, {0xAB});
  const std::vector<uint8_t> kA = h264_nal(1, {0x01});
  const std::vector<uint8_t> kB = h264_nal(1, {0x02});
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});

  VideoAuBuilderOptions options;
  options.sps = {kSps};
  options.pps = {kPps};
  VideoAccessUnitBuilder builder{options};
  feed(builder, 4, 0, true, {kA});
  feed(builder, 5, 3000, true, {kB});
  feed(builder, 6, 6000, true, {kIdr});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 2u);

  const std::vector<uint8_t> head = annex_b({kSps, kPps});
  CHECK_OCTETS(es, concat({head, annex_b({kIdr})}));

  // Card rule 5: the pseudo access unit is not dropped with the access units in
  // front of the keyframe -- it is the only copy of the parameter sets.
  CHECK_EQ(static_cast<int>(records[0].flags),
           static_cast<int>(kVideoAuFlagParamSets));
  CHECK_EQ(records[0].first_frame, 4u);  // 流的第一帧, which was dropped
  CHECK_EQ(records[0].byte_offset, static_cast<uint64_t>(0));
  // Its PTS is the surviving unit's, so the export does not start with a three
  // second still frame that never existed.
  CHECK_EQ(records[0].pts_us, static_cast<uint64_t>(66666));
  CHECK_EQ(records[1].pts_us, static_cast<uint64_t>(66666));
  CHECK_EQ(records[1].first_frame, 6u);
  CHECK_EQ(static_cast<int>(records[1].flags),
           static_cast<int>(kVideoAuFlagKey));
  check_tiles(records, es, 0);
}

TEST_CASE(
    "VideoAccessUnitBuilder injects nothing when the parameter sets are in band") {
  const std::vector<uint8_t> kSps = h264_nal(7, {0x64, 0x00});
  const std::vector<uint8_t> kPps = h264_nal(8, {0xAB});
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kTrail = h264_nal(1, {0x11});
  // Deliberately different bytes: if either build injected anything, the two
  // elementary streams could not come out equal.
  const std::vector<uint8_t> kSdpSps = h264_nal(7, {0xDE, 0xAD});
  const std::vector<uint8_t> kSdpPps = h264_nal(8, {0xBE, 0xEF});

  // A: no parameter sets in the options at all.
  VideoAccessUnitBuilder plain{VideoAuBuilderOptions{}};
  // B: the SDP's sets, which this stream does not need.
  VideoAuBuilderOptions options;
  options.sps = {kSdpSps};
  options.pps = {kSdpPps};
  VideoAccessUnitBuilder with_sdp{options};

  // The stream carries its own SPS/PPS, in band, where they were sent.
  for (VideoAccessUnitBuilder *builder : {&plain, &with_sdp}) {
    feed(*builder, 0, 0, true, {kSps, kIdr});
    feed(*builder, 1, 3000, true, {kPps, kTrail});
  }

  std::vector<uint8_t> es_plain;
  std::vector<uint8_t> es_sdp;
  const std::vector<VideoAuRecord> records_plain = plain.finish(es_plain);
  const std::vector<VideoAuRecord> records_sdp = with_sdp.finish(es_sdp);

  CHECK(plain.error().empty());
  CHECK(with_sdp.error().empty());

  // Card rule 4's hard requirement: with in-band sets, not a single byte is
  // injected. QA-01's byte-for-byte comparison against the Lua plugin rests on
  // exactly this.
  CHECK_OCTETS(es_sdp, es_plain);
  CHECK_OCTETS(es_plain, concat({annex_b({kSps, kIdr}), annex_b({kPps, kTrail})}));
  REQUIRE_EQ(records_sdp.size(), records_plain.size());
  REQUIRE_EQ(records_plain.size(), 2u);
  for (size_t index = 0; index < records_plain.size(); ++index) {
    CHECK_EQ(records_sdp[index].byte_offset, records_plain[index].byte_offset);
    CHECK_EQ(records_sdp[index].byte_length, records_plain[index].byte_length);
    CHECK_EQ(static_cast<int>(records_sdp[index].flags),
             static_cast<int>(records_plain[index].flags));
  }
  // Nothing was prepended: the first record still starts at the ES's first octet
  // and carries the in-band SPS where the sender put it.
  CHECK_EQ(records_plain[0].byte_offset, static_cast<uint64_t>(0));
  CHECK_EQ(records_plain[0].byte_length,
           static_cast<uint32_t>(annex_b({kSps, kIdr}).size()));
  // 0x04 means "this access unit contains parameter-set NAL units", so an
  // in-band set is flagged too (header decision 8).
  CHECK_EQ(static_cast<int>(records_plain[0].flags),
           static_cast<int>(kVideoAuFlagKey | kVideoAuFlagParamSets));
  CHECK_EQ(static_cast<int>(records_plain[1].flags),
           static_cast<int>(kVideoAuFlagParamSets));
  check_tiles(records_plain, es_plain, 0);
}

TEST_CASE(
    "VideoAccessUnitBuilder drops the access units before the first keyframe") {
  const std::vector<uint8_t> kA = h264_nal(1, {0x01});
  const std::vector<uint8_t> kB = h264_nal(1, {0x02});
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x03});
  const std::vector<uint8_t> kC = h264_nal(1, {0x04});

  VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
  feed(builder, 20, 0, true, {kA});
  feed(builder, 21, 3000, true, {kB});
  feed(builder, 22, 6000, true, {kIdr});
  feed(builder, 23, 9000, true, {kC});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 2u);
  // The dropped units are not in the ES either: the survivor starts at octet 0.
  CHECK_OCTETS(es, concat({annex_b({kIdr}), annex_b({kC})}));
  CHECK_EQ(records[0].byte_offset, static_cast<uint64_t>(0));
  CHECK_EQ(records[0].byte_length, static_cast<uint32_t>(annex_b({kIdr}).size()));
  CHECK_EQ(records[0].first_frame, 22u);
  CHECK_EQ(records[0].pts_us, static_cast<uint64_t>(66666));
  CHECK_EQ(static_cast<int>(records[0].flags),
           static_cast<int>(kVideoAuFlagKey));
  CHECK_EQ(records[1].first_frame, 23u);
  check_tiles(records, es, 0);
}

TEST_CASE("VideoAccessUnitBuilder reports noKeyframe when the stream has none") {
  const std::vector<uint8_t> kA = h264_nal(1, {0x01});
  const std::vector<uint8_t> kB = h264_nal(1, {0x02});

  VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
  feed(builder, 0, 0, true, {kA});
  feed(builder, 1, 3000, true, {kB});

  // A pre-filled output vector, so that "finish returns nothing" also means
  // "finish appended nothing": a caller that honours error() cannot end up with
  // a half-written ES.
  std::vector<uint8_t> es = {0xAB};
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK_EQ(builder.error(), std::string("noKeyframe"));
  CHECK(records.empty());
  CHECK_OCTETS(es, std::vector<uint8_t>{0xAB});
}

TEST_CASE(
    "VideoAccessUnitBuilder exports a stream with no keyframe when "
    "start_at_keyframe is off") {
  const std::vector<uint8_t> kA = h264_nal(1, {0x01});
  const std::vector<uint8_t> kB = h264_nal(1, {0x02});

  // QA-01 runs with startAtKeyframe = false, and a capture that begins
  // mid-GOP has no IDR at all: nothing is dropped and nothing fails, because
  // the card's rule 5 is where "noKeyframe" lives (header decision 9).
  VideoAuBuilderOptions options;
  options.start_at_keyframe = false;
  VideoAccessUnitBuilder builder{options};
  feed(builder, 0, 0, true, {kA});
  feed(builder, 1, 3000, true, {kB});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 2u);
  CHECK_OCTETS(es, concat({annex_b({kA}), annex_b({kB})}));
  CHECK_EQ(static_cast<int>(records[0].flags), 0);
  CHECK_EQ(static_cast<int>(records[1].flags), 0);
  check_tiles(records, es, 0);
}

TEST_CASE("VideoAccessUnitBuilder obeys both drop_corrupt settings") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kDamaged = h264_nal(1, {0x11});
  const std::vector<uint8_t> kClean = h264_nal(1, {0x22});

  const std::vector<uint8_t> es_expected_plain =
      concat({annex_b({kIdr}), annex_b({kDamaged}), annex_b({kClean})});
  const std::vector<uint8_t> es_expected_dropped =
      concat({annex_b({kIdr}), annex_b({kClean})});

  // drop_corrupt = false (the default): the damaged unit is written, flagged.
  {
    VideoAuBuilderOptions options;
    options.start_at_keyframe = false;
    VideoAccessUnitBuilder builder{options};
    feed(builder, 0, 0, true, {kIdr});
    feed(builder, 1, 3000, true, {kDamaged}, /*corrupt=*/true);
    feed(builder, 2, 6000, true, {kClean});
    std::vector<uint8_t> es;
    const std::vector<VideoAuRecord> records = builder.finish(es);

    CHECK(builder.error().empty());
    REQUIRE_EQ(records.size(), 3u);
    // The incomplete NAL sequence stays in the stream: that is what QA-01
    // compares against the reference output. Record 0 is the IDR, record 1 the
    // damaged unit (and only that), record 2 the clean tail.
    CHECK_OCTETS(es, es_expected_plain);
    CHECK_EQ(static_cast<int>(records[1].flags),
             static_cast<int>(kVideoAuFlagCorrupt));
    CHECK_EQ(static_cast<int>(records[0].flags),
             static_cast<int>(kVideoAuFlagKey));
    CHECK_EQ(static_cast<int>(records[2].flags), 0);
    check_tiles(records, es, 0);
  }

  // drop_corrupt = true: dropped from the records *and* from the ES.
  {
    VideoAuBuilderOptions options;
    options.start_at_keyframe = false;
    options.drop_corrupt = true;
    VideoAccessUnitBuilder builder{options};
    feed(builder, 0, 0, true, {kIdr});
    feed(builder, 1, 3000, true, {kDamaged}, /*corrupt=*/true);
    feed(builder, 2, 6000, true, {kClean});
    std::vector<uint8_t> es;
    const std::vector<VideoAuRecord> records = builder.finish(es);

    CHECK(builder.error().empty());
    REQUIRE_EQ(records.size(), 2u);
    CHECK_OCTETS(es, es_expected_dropped);
    CHECK_EQ(records[0].first_frame, 0u);
    CHECK_EQ(records[1].first_frame, 2u);
    CHECK_EQ(static_cast<int>(records[0].flags & kVideoAuFlagCorrupt), 0);
    CHECK_EQ(static_cast<int>(records[1].flags & kVideoAuFlagCorrupt), 0);
    check_tiles(records, es, 0);
  }
}

TEST_CASE("VideoAccessUnitBuilder marks an access unit damaged by a gap alone") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kNext = h264_nal(1, {0x11});

  // The case NAT-01 was built around: a packet lost in the middle of an FU-A
  // leaves the depacketizer with nothing to emit, and it reports the loss on the
  // *next* packet that arrives -- which brings no NAL unit with it. The access
  // unit still has to be flagged, because the data that went missing inside it
  // is exactly what the marker says the frame needed.
  {
    VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
    feed(builder, 0, 0, false, {kIdr});
    feed(builder, 1, 0, true, /*nals=*/{}, /*corrupt=*/false,
         /*sequence_gap=*/true);
    std::vector<uint8_t> es;
    const std::vector<VideoAuRecord> records = builder.finish(es);
    CHECK(builder.error().empty());
    REQUIRE_EQ(records.size(), 1u);
    CHECK_EQ(static_cast<int>(records[0].flags),
             static_cast<int>(kVideoAuFlagKey | kVideoAuFlagCorrupt));
    // The packet that carried nothing is still the unit's last packet, so the
    // unit is what it always was: its NAL units and their start codes.
    CHECK_OCTETS(es, annex_b({kIdr}));
  }

  // A sequence_gap that NAT-01 reports on a packet which *does* carry a NAL unit
  // (its rule 3) reaches the unit the same way.
  {
    VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
    feed(builder, 0, 0, true, {kIdr}, /*corrupt=*/false, /*sequence_gap=*/true);
    std::vector<uint8_t> es;
    const std::vector<VideoAuRecord> records = builder.finish(es);
    REQUIRE_EQ(records.size(), 1u);
    CHECK_EQ(static_cast<int>(records[0].flags),
             static_cast<int>(kVideoAuFlagKey | kVideoAuFlagCorrupt));
  }

  // Damage does not leak across a boundary: the unit after the damaged one is
  // clean (header decision 5).
  {
    VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
    feed(builder, 0, 0, true, {kIdr}, /*corrupt=*/true);
    feed(builder, 1, 3000, true, {kNext});
    std::vector<uint8_t> es;
    const std::vector<VideoAuRecord> records = builder.finish(es);
    REQUIRE_EQ(records.size(), 2u);
    CHECK_EQ(static_cast<int>(records[0].flags & kVideoAuFlagCorrupt),
             static_cast<int>(kVideoAuFlagCorrupt));
    CHECK_EQ(static_cast<int>(records[1].flags), 0);
  }
}

TEST_CASE(
    "VideoAccessUnitBuilder reports noKeyframe when drop_corrupt removes every "
    "keyframe") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});

  // The caller asked for damaged frames to be dropped; the only keyframe the
  // stream has was damaged. An ES with no keyframe at all cannot be muxed, so
  // "noKeyframe" is the honest answer (header decision 10).
  VideoAuBuilderOptions options;
  options.drop_corrupt = true;  // start_at_keyframe defaults to true
  VideoAccessUnitBuilder builder{options};
  feed(builder, 0, 0, true, {kIdr}, /*corrupt=*/true);

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK_EQ(builder.error(), std::string("noKeyframe"));
  CHECK(records.empty());
  CHECK(es.empty());
}

TEST_CASE("VideoAccessUnitBuilder skips a zero-length NAL and opens no empty unit") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});
  const std::vector<uint8_t> kTrail = h264_nal(1, {0x11});

  VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
  feed(builder, 5, 0, true, {kIdr});
  // A packet that brought nothing but an empty NAL: it is still a packet of the
  // stream (and it moved the timestamp), but it cannot open an access unit, and
  // a start code with nothing behind it is not a NAL unit at all.
  feed(builder, 6, 3000, false, {std::vector<uint8_t>{}});
  feed(builder, 7, 3000, true, {kTrail});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 2u);
  CHECK_OCTETS(es, concat({annex_b({kIdr}), annex_b({kTrail})}));
  // first_frame is the unit's first *packet*: the one that brought nothing lies
  // between the same two boundaries, so it is where the unit starts (header
  // decision 11).
  CHECK_EQ(records[0].first_frame, 5u);
  CHECK_EQ(records[1].first_frame, 6u);
  CHECK_EQ(records[1].pts_us, static_cast<uint64_t>(33333));
  check_tiles(records, es, 0);

  // The same rule inside a unit that does have data: the empty NAL is skipped
  // and the real ones are written unchanged.
  const std::vector<uint8_t> kMixedIdr = h264_nal(5, {0x21});
  const std::vector<uint8_t> kMixedTrail = h264_nal(1, {0x22});
  VideoAccessUnitBuilder mixed{VideoAuBuilderOptions{}};
  feed(mixed, 0, 0, true, {kMixedIdr, std::vector<uint8_t>{}, kMixedTrail});
  std::vector<uint8_t> mixed_es;
  const std::vector<VideoAuRecord> mixed_records = mixed.finish(mixed_es);
  REQUIRE_EQ(mixed_records.size(), 1u);
  CHECK_OCTETS(mixed_es, annex_b({kMixedIdr, kMixedTrail}));
  CHECK_EQ(mixed_records[0].byte_length,
           static_cast<uint32_t>(annex_b({kMixedIdr, kMixedTrail}).size()));
  CHECK_EQ(static_cast<int>(mixed_records[0].flags),
           static_cast<int>(kVideoAuFlagKey));
}

TEST_CASE("VideoAccessUnitBuilder treats PS as either codec") {
  const std::vector<uint8_t> kHevcIdr = h265_nal(19, {0xAA});   // IDR_W_RADL
  const std::vector<uint8_t> kH264Idr = h264_nal(5, {0xBB});    // IDR
  const std::vector<uint8_t> kHevcTrail = h265_nal(1, {0xCC});  // TRAIL_R

  VideoAuBuilderOptions options;
  options.codec = VideoCodec::PS;
  options.start_at_keyframe = false;
  VideoAccessUnitBuilder builder{options};
  feed(builder, 0, 0, true, {kHevcIdr});
  feed(builder, 1, 3000, true, {kH264Idr});
  feed(builder, 2, 6000, true, {kHevcTrail});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 3u);
  // A PS stream is H.264 or H.265 depending on the PSM's stream_type, and the
  // demuxer hands over ES bytes without saying which, so both codecs' keyframe
  // types count (header decision 14).
  CHECK_EQ(static_cast<int>(records[0].flags),
           static_cast<int>(kVideoAuFlagKey));
  CHECK_EQ(static_cast<int>(records[1].flags),
           static_cast<int>(kVideoAuFlagKey));
  CHECK_EQ(static_cast<int>(records[2].flags), 0);
  check_tiles(records, es, 0);
}

TEST_CASE("VideoAccessUnitBuilder injects PS parameter sets in VPS, SPS, PPS order") {
  const std::vector<uint8_t> kVps = h265_nal(32, {0x01});
  const std::vector<uint8_t> kSps = h265_nal(33, {0x02});
  const std::vector<uint8_t> kPps = h265_nal(34, {0x03});
  const std::vector<uint8_t> kIdr = h265_nal(19, {0x04});

  VideoAuBuilderOptions options;
  options.codec = VideoCodec::PS;
  options.vps = {kVps};
  options.sps = {kSps};
  options.pps = {kPps};
  VideoAccessUnitBuilder builder{options};
  feed(builder, 0, 0, true, {kIdr});

  std::vector<uint8_t> es;
  const std::vector<VideoAuRecord> records = builder.finish(es);

  CHECK(builder.error().empty());
  REQUIRE_EQ(records.size(), 2u);
  // Card rule 4's order for a three-set codec.
  CHECK_OCTETS(es, concat({annex_b({kVps, kSps, kPps}), annex_b({kIdr})}));
  CHECK_EQ(records[0].byte_length,
           static_cast<uint32_t>(annex_b({kVps, kSps, kPps}).size()));
  CHECK_EQ(static_cast<int>(records[0].flags),
           static_cast<int>(kVideoAuFlagParamSets));
  CHECK_EQ(records[1].byte_offset, records[0].byte_length);
  check_tiles(records, es, 0);
}

TEST_CASE("VideoAccessUnitBuilder appends to the caller's buffer and finishes once") {
  const std::vector<uint8_t> kIdr = h264_nal(5, {0x88});

  VideoAccessUnitBuilder builder{VideoAuBuilderOptions{}};
  feed(builder, 0, 0, true, {kIdr});

  // A buffer that already holds something: the card says the ES bytes are
  // *appended* to out_es, so the offsets are absolute in the ES file the caller
  // writes -- including the prefix (header decision 13).
  std::vector<uint8_t> es = {0x7F, 0x7F};
  const std::vector<VideoAuRecord> records = builder.finish(es);

  REQUIRE_EQ(records.size(), 1u);
  CHECK_EQ(records[0].byte_offset, static_cast<uint64_t>(2));
  CHECK_OCTETS(es, concat({{0x7F, 0x7F}, annex_b({kIdr})}));
  check_tiles(records, es, 2);

  // finish() is a one-shot call: the ES bytes have been handed over already, so
  // a second call must not re-emit records pointing into a released buffer.
  const std::vector<VideoAuRecord> again = builder.finish(es);
  CHECK(again.empty());
  CHECK_OCTETS(es, concat({{0x7F, 0x7F}, annex_b({kIdr})}));
}
