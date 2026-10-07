// RTP4-NAT-04: AMR / AMR-WB de-packetization (RFC 4867).
//
// What can go wrong here is not the codec -- there is none, AmrDepack only
// reframes a payload -- it is the two payload formats. Octet-aligned mode
// (RFC 4867 section 4.4) is byte arithmetic, but bandwidth-efficient mode
// (section 4.3) is a bit string: the ToC starts at bit 4, not at bit 8, and
// every frame after the first begins wherever the previous one happened to
// stop. Two failures are invisible in casual testing and are pinned here:
//
//   * FT read without masking. In bandwidth-efficient mode the F bit sits
//     between CMR and FT, so `toc >> 3` alone gives a five-bit "FT" that is
//     wrong whenever F = 1 -- i.e. on every frame but the last one of a
//     multi-frame packet. The two-frame case below is what catches it.
//   * Frame data taken with the wrong alignment. The expected octets are
//     written out by hand (octet-aligned) or built bit by bit with binary
//     literals (bandwidth-efficient) so a shift error is visible in the test
//     rather than only in the app.
//
// The mode detector cases are the other half: "did this payload parse at all"
// is not enough to tell the formats apart, and the tests document what does
// tell them apart.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/depack/AmrDepack.h"

using layanalyzer::rtp::AmrDepackResult;
using layanalyzer::rtp::AmrMode;
using layanalyzer::rtp::AmrModeDetector;
using layanalyzer::rtp::depack_amr;

namespace {

// Frame sizes in bits and the data lengths they imply, ceil(bits / 8):
//   FT 7 (24.4 kbit/s)  244 bits -> 31 octets (the last one carries 4 bits)
//   FT 4 (12.2 kbit/s)  148 bits -> 19 octets (the last one carries 4 bits)
//   FT 8 (AMR-NB SID)    39 bits ->  5 octets (the last one carries 7 bits)
//   FT 9 (AMR-WB SID)    40 bits ->  5 octets
//   FT 8 (AMR-WB speech) 477 bits -> 60 octets (the last one carries 5 bits)
constexpr uint16_t kNbFt7Bits = 244;
constexpr uint16_t kNbFt4Bits = 148;
constexpr uint16_t kNbSidBits = 39;
constexpr uint16_t kWbSidBits = 40;
constexpr uint16_t kWbFt8Bits = 477;
constexpr size_t kNbFt7Octets = (kNbFt7Bits + 7) / 8;
constexpr size_t kNbFt4Octets = (kNbFt4Bits + 7) / 8;
constexpr size_t kNbSidOctets = (kNbSidBits + 7) / 8;
constexpr size_t kWbSidOctets = (kWbSidBits + 7) / 8;
constexpr size_t kWbFt8Octets = (kWbFt8Bits + 7) / 8;

// ToC octets written as the fields they carry, so the tests below read like
// RFC 4867's diagrams: bit 7 F, bits 6-3 FT, bit 2 Q, bits 1-0 padding.
constexpr uint8_t kTocNbFt7 = 0x38;   // 0b0_0111_0_00
constexpr uint8_t kTocNbFt4First = 0xA0;   // 0b1_0100_0_00, F = 1
constexpr uint8_t kTocNbFt4Last = 0x20;    // 0b0_0100_0_00
constexpr uint8_t kTocNbSpeechLost = 0x70;  // 0b0_1110_0_00, FT = 14
constexpr uint8_t kTocNbNoData = 0x78;      // 0b0_1111_0_00, FT = 15

// Builds a bandwidth-efficient payload one field at a time, MSB first, so the
// RFC 4867 section 4.3 layout (CMR, F, FT, Q, data bits) is visible in the test
// instead of hidden inside a hand-computed byte array.
class BitWriter {
 public:
  void push(uint32_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
      bits_.push_back(
          static_cast<uint8_t>((value >> (count - 1 - i)) & 0x01u));
    }
  }

  // Packs the bits MSB first; the last octet's spare low bits stay zero, which
  // is the padding RFC 4867 section 4.3 allows in a bandwidth-efficient
  // payload.
  std::vector<uint8_t> bytes() const {
    std::vector<uint8_t> out((bits_.size() + 7u) / 8u, 0x00);
    for (size_t i = 0; i < bits_.size(); ++i) {
      if (bits_[i] != 0) {
        out[i >> 3] |= static_cast<uint8_t>(0x80u >> (i & 7u));
      }
    }
    return out;
  }

 private:
  std::vector<uint8_t> bits_;
};

// Appends the first `bits` bits of `octets` (each octet MSB first) to `writer`
// -- the inverse of what make_frame() does to build AmrFrame::data.
void push_frame_bits(BitWriter &writer, const std::vector<uint8_t> &octets,
                     uint16_t bits) {
  size_t remaining = bits;
  for (const uint8_t octet : octets) {
    const unsigned take = static_cast<unsigned>(remaining < 8 ? remaining : 8);
    writer.push(static_cast<uint32_t>(octet >> (8u - take)), take);
    remaining -= take;
    if (remaining == 0) {
      break;
    }
  }
}

// One bandwidth-efficient frame: the ToC fields (F, FT, Q -- the CMR is pushed
// once at the start of the payload, not per frame) followed by the frame's
// `bits` data bits.
void push_be_frame(BitWriter &writer, uint32_t f, uint32_t ft, uint32_t q,
                   const std::vector<uint8_t> &data, uint16_t bits) {
  writer.push(f, 1);
  writer.push(ft, 4);
  writer.push(q, 1);
  push_frame_bits(writer, data, bits);
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

#define AMR_CHECK_OCTETS(actual, expected)                                     \
  do {                                                                         \
    size_t amr_difference = 0;                                                 \
    CHECK_MESSAGE(                                                             \
        bytes_equal((actual), (expected), amr_difference),                     \
        "first difference at octet " << amr_difference << " (got "             \
                                      << (actual).size() << " octets, want "   \
                                      << (expected).size() << ")");            \
  } while (false)

// The two payloads the detector cases feed in. Both are single-frame FT 7
// packets, and each one is *rejected* by the other mode's parser:
//   * the octet-aligned one re-reads as F = 0, FT = 0 (95 bits) and stops after
//     105 of its 264 bits, i.e. with more than an octet unaccounted for;
//   * the bandwidth-efficient one re-reads its data octets as ToCs and runs off
//     the end of the buffer.
// Anything shorter would not do: a 14-octet octet-aligned packet is 112 bits,
// which is 7 bits of padding past the 105 a bandwidth-efficient parse consumes,
// and it would count as valid under both modes.
std::vector<uint8_t> make_oa_ft7_packet() {
  std::vector<uint8_t> packet = {0x00, kTocNbFt7};
  packet.insert(packet.end(), kNbFt7Octets, 0xA5);
  return packet;
}

std::vector<uint8_t> make_be_ft7_packet() {
  BitWriter writer;
  writer.push(0b0001, 4);  // CMR = 1
  push_be_frame(writer, 0b0, 0b0111, 0b1, std::vector<uint8_t>(kNbFt7Octets, 0xA5),
                kNbFt7Bits);
  return writer.bytes();
}

}  // namespace

TEST_CASE("AmrDepack octet-aligned: one FT=7 frame") {
  // CMR 0x00 (reserved nibble zero), then ToC 0b0_0111_0_00 and 31 data octets.
  std::vector<uint8_t> data(kNbFt7Octets, 0xA5);
  // 244 bits is 30 octets plus 4 bits, so the last octet carries only its high
  // nibble. Setting the low nibble to all ones here pins the storage rule: the
  // spare bits are cleared, so the value MediaCodec sees is 0xF0, not 0xFF.
  data[kNbFt7Octets - 1] = 0xFF;

  std::vector<uint8_t> packet = {0x00, kTocNbFt7};
  packet.insert(packet.end(), data.begin(), data.end());
  REQUIRE_EQ(packet.size(), 2u + kNbFt7Octets);

  const AmrDepackResult result = depack_amr(packet.data(), packet.size(), false, true);
  REQUIRE(result.error.empty());
  REQUIRE_EQ(result.frames.size(), 1u);
  CHECK_EQ(result.frames[0].toc, kTocNbFt7);
  CHECK_EQ((result.frames[0].toc >> 3) & 0x0Fu, 7u);
  CHECK_EQ(result.frames[0].data.size(), kNbFt7Octets);
  CHECK_FALSE(result.frames[0].is_sid);
  CHECK_FALSE(result.frames[0].no_data);
  CHECK_FALSE(result.speech_lost);
  CHECK_FALSE(result.no_data);

  std::vector<uint8_t> expected = data;
  expected[kNbFt7Octets - 1] = 0xF0;  // the 4 spare bits are zeroed
  AMR_CHECK_OCTETS(result.frames[0].data, expected);
}

TEST_CASE("AmrDepack octet-aligned: two packaged FT=4 frames") {
  // F = 1 on the first ToC is what tells the parser a second ToC follows; the
  // 19 data octets in between belong to the first frame only.
  std::vector<uint8_t> first(kNbFt4Octets, 0x11);
  std::vector<uint8_t> second(kNbFt4Octets, 0x22);

  std::vector<uint8_t> packet = {0x00, kTocNbFt4First};
  packet.insert(packet.end(), first.begin(), first.end());
  packet.push_back(kTocNbFt4Last);
  packet.insert(packet.end(), second.begin(), second.end());

  const AmrDepackResult result = depack_amr(packet.data(), packet.size(), false, true);
  REQUIRE(result.error.empty());
  REQUIRE_EQ(result.frames.size(), 2u);
  CHECK_EQ(result.frames[0].toc, kTocNbFt4First);
  CHECK_EQ(result.frames[1].toc, kTocNbFt4Last);
  CHECK_EQ((result.frames[0].toc >> 3) & 0x0Fu, 4u);
  CHECK_EQ((result.frames[1].toc >> 3) & 0x0Fu, 4u);
  CHECK_EQ(result.frames[0].data.size(), kNbFt4Octets);
  CHECK_EQ(result.frames[1].data.size(), kNbFt4Octets);

  // 148 bits is 18 octets plus 4 bits, so the last octet of each frame keeps
  // only its high nibble.
  std::vector<uint8_t> first_expected = first;
  std::vector<uint8_t> second_expected = second;
  first_expected[kNbFt4Octets - 1] = 0x10;
  second_expected[kNbFt4Octets - 1] = 0x20;
  AMR_CHECK_OCTETS(result.frames[0].data, first_expected);
  AMR_CHECK_OCTETS(result.frames[1].data, second_expected);
}

TEST_CASE("AmrDepack bandwidth-efficient: one frame built bit by bit") {
  // CMR = 1, F = 0 (this is the last frame), FT = 7 (24.4 kbit/s), Q = 1.
  BitWriter writer;
  writer.push(0b0001, 4);   // CMR
  push_be_frame(writer, 0b0, 0b0111, 0b1,
                std::vector<uint8_t>(kNbFt7Octets, 0xA5), kNbFt7Bits);
  const std::vector<uint8_t> packet = writer.bytes();

  // 4 + 6 + 244 = 254 bits, so the payload is 32 octets and its last two bits
  // are padding.
  REQUIRE_EQ(packet.size(), 32u);

  const AmrDepackResult result = depack_amr(packet.data(), packet.size(), false, false);
  REQUIRE(result.error.empty());
  REQUIRE_EQ(result.frames.size(), 1u);

  // Storage ToC = F << 7 | FT << 3 | Q << 2 = 0b0_0111_1_00.
  CHECK_EQ(result.frames[0].toc, 0x3Cu);
  CHECK_EQ((result.frames[0].toc >> 3) & 0x0Fu, 7u);
  CHECK_EQ((result.frames[0].toc >> 2) & 0x01u, 1u);
  CHECK_FALSE(result.frames[0].is_sid);
  CHECK_EQ(result.frames[0].data.size(), kNbFt7Octets);

  // The same 244 bits came back byte aligned: 30 whole octets and a last octet
  // holding the 4 bits that had been squeezed into the bit stream.
  std::vector<uint8_t> expected(30, 0xA5);
  expected.push_back(0xA0);
  AMR_CHECK_OCTETS(result.frames[0].data, expected);
}

TEST_CASE("AmrDepack bandwidth-efficient: two frames keep their FT when F=1") {
  // This is the case that catches an unmasked FT read. With F = 1 the bits
  // between CMR and FT are non-zero, so `toc >> 3` without `& 0x0F` reads FT as
  // 0b10111 = 23 instead of 7 -- on the first frame here, and on every frame but
  // the last in any multi-frame packet.
  BitWriter writer;
  writer.push(0b0001, 4);  // CMR = 1
  push_be_frame(writer, 0b1, 0b0111, 0b0, std::vector<uint8_t>(kNbFt7Octets, 0x11),
                kNbFt7Bits);
  push_be_frame(writer, 0b0, 0b0111, 0b0, std::vector<uint8_t>(kNbFt7Octets, 0x22),
                kNbFt7Bits);
  const std::vector<uint8_t> packet = writer.bytes();

  // 4 + 6 + 244 + 6 + 244 = 504 bits = 63 octets exactly, no padding.
  REQUIRE_EQ(packet.size(), 63u);

  const AmrDepackResult result = depack_amr(packet.data(), packet.size(), false, false);
  REQUIRE(result.error.empty());
  REQUIRE_EQ(result.frames.size(), 2u);

  // The stored ToC keeps the transmitted F bit, so the first frame's is 0xB8.
  CHECK_EQ(result.frames[0].toc, 0xB8u);
  CHECK_EQ(result.frames[1].toc, kTocNbFt7);
  CHECK_EQ((result.frames[0].toc >> 3) & 0x0Fu, 7u);
  CHECK_EQ((result.frames[1].toc >> 3) & 0x0Fu, 7u);

  std::vector<uint8_t> first_expected(30, 0x11);
  first_expected.push_back(0x10);
  std::vector<uint8_t> second_expected(30, 0x22);
  second_expected.push_back(0x20);
  CHECK_EQ(result.frames[0].data.size(), kNbFt7Octets);
  CHECK_EQ(result.frames[1].data.size(), kNbFt7Octets);
  AMR_CHECK_OCTETS(result.frames[0].data, first_expected);
  AMR_CHECK_OCTETS(result.frames[1].data, second_expected);
}

TEST_CASE("AmrDepack FT=15 reports NO_DATA instead of a frame") {
  // Octet-aligned: ToC 0b0_1111_0_00. No data field follows an FT 15 frame, so
  // the packet is exactly two octets.
  const std::vector<uint8_t> oa = {0x00, kTocNbNoData};
  const AmrDepackResult oa_result = depack_amr(oa.data(), oa.size(), false, true);
  CHECK(oa_result.error.empty());
  CHECK(oa_result.no_data);
  CHECK(oa_result.frames.empty());
  CHECK_FALSE(oa_result.speech_lost);

  // Bandwidth-efficient: CMR = 0, F = 0, FT = 15, Q = 0 over 16 bits leaves 6
  // bits of padding -- still a well-formed payload.
  BitWriter writer;
  writer.push(0b0000, 4);  // CMR
  push_be_frame(writer, 0b0, 0b1111, 0b0, std::vector<uint8_t>(), 0);
  const std::vector<uint8_t> be = writer.bytes();
  REQUIRE_EQ(be.size(), 2u);
  const AmrDepackResult be_result = depack_amr(be.data(), be.size(), false, false);
  CHECK(be_result.error.empty());
  CHECK(be_result.no_data);
  CHECK(be_result.frames.empty());
  CHECK_FALSE(be_result.speech_lost);
}

TEST_CASE("AmrDepack FT=14 reports speech lost, but only in the AMR-NB band") {
  // AMR-NB: FT 14 is speech lost and carries no data, exactly like NO_DATA, so
  // no AmrFrame is produced and the packet-level flag is what the caller uses.
  const std::vector<uint8_t> oa = {0x00, kTocNbSpeechLost};
  const AmrDepackResult nb = depack_amr(oa.data(), oa.size(), false, true);
  CHECK(nb.error.empty());
  CHECK(nb.speech_lost);
  CHECK(nb.frames.empty());
  CHECK_FALSE(nb.no_data);

  // AMR-WB has no speech-lost FT: FT 14 there is a 40-bit SID frame, and the
  // packet carries its 5 data octets.
  std::vector<uint8_t> wb = {0x00, kTocNbSpeechLost};
  wb.insert(wb.end(), kWbSidOctets, 0x33);
  const AmrDepackResult wb_result = depack_amr(wb.data(), wb.size(), true, true);
  REQUIRE(wb_result.error.empty());
  REQUIRE_EQ(wb_result.frames.size(), 1u);
  CHECK(wb_result.frames[0].is_sid);
  CHECK_EQ(wb_result.frames[0].data.size(), kWbSidOctets);
  CHECK_FALSE(wb_result.speech_lost);
}

TEST_CASE("AmrDepack truncated payloads fail whole, never partially") {
  // Octet-aligned FT=7 wants 31 data octets; this packet declares it and then
  // supplies 10. A partial frame here would hand MediaCodec half a frame worth
  // of bits, so the whole payload has to be rejected.
  std::vector<uint8_t> short_oa = {0x00, kTocNbFt7};
  short_oa.insert(short_oa.end(), 10, 0x5A);
  const AmrDepackResult oa = depack_amr(short_oa.data(), short_oa.size(), false, true);
  CHECK_FALSE(oa.error.empty());
  CHECK(oa.frames.empty());
  CHECK_FALSE(oa.no_data);
  CHECK_FALSE(oa.speech_lost);

  // F = 1 promises a second frame and the payload ends instead.
  const std::vector<uint8_t> missing_toc = {0x00, kTocNbFt4First};
  const AmrDepackResult dangling =
      depack_amr(missing_toc.data(), missing_toc.size(), false, true);
  CHECK_FALSE(dangling.error.empty());
  CHECK(dangling.frames.empty());

  // Bandwidth-efficient, cut one octet short: 31 octets is 248 bits and the
  // frame needs 254.
  const std::vector<uint8_t> be_full = make_be_ft7_packet();
  const std::vector<uint8_t> be_short(be_full.begin(), be_full.end() - 1);
  const AmrDepackResult be = depack_amr(be_short.data(), be_short.size(), false, false);
  CHECK_FALSE(be.error.empty());
  CHECK(be.frames.empty());

  // Nothing to parse at all.
  CHECK_FALSE(depack_amr(nullptr, 0, false, true).error.empty());
  CHECK_FALSE(depack_amr(nullptr, 4, false, false).error.empty());
}

TEST_CASE("AmrDepack rejects payloads whose frames do not account for the whole packet") {
  // Octet-aligned: one whole FT=7 frame, then a stray octet past the F = 0 that
  // ended the frame list. Octet-aligned frames tile the payload exactly, so the
  // leftover octet is not a frame and guessing at it would invent data.
  std::vector<uint8_t> trailing_oa = {0x00, kTocNbFt7};
  trailing_oa.insert(trailing_oa.end(), kNbFt7Octets, 0xA5);
  trailing_oa.push_back(0x00);
  const AmrDepackResult oa =
      depack_amr(trailing_oa.data(), trailing_oa.size(), false, true);
  CHECK_FALSE(oa.error.empty());
  CHECK(oa.frames.empty());

  // Bandwidth-efficient: a whole octet of zeros past the end of the last frame.
  // At most 7 bits can be the final octet's padding, so this cannot be it.
  std::vector<uint8_t> trailing_be = make_be_ft7_packet();
  trailing_be.push_back(0x00);
  const AmrDepackResult be =
      depack_amr(trailing_be.data(), trailing_be.size(), false, false);
  CHECK_FALSE(be.error.empty());
  CHECK(be.frames.empty());

  // The same packet without the extra octet is accepted, so the rejection above
  // is the trailing octet and not something else about the packet.
  const std::vector<uint8_t> exact = make_be_ft7_packet();
  CHECK(depack_amr(exact.data(), exact.size(), false, false).error.empty());
}

TEST_CASE("AmrDepack AMR-WB uses its own FT table (FT 8 speech, FT 9 SID)") {
  // AMR-WB FT 9 is SID and 40 bits wide: five whole octets, no spare bits.
  std::vector<uint8_t> sid = {0x00, 0x4C};  // ToC 0b0_1001_1_00: FT 9, Q 1
  sid.insert(sid.end(), kWbSidOctets, 0x33);
  const AmrDepackResult wb_sid = depack_amr(sid.data(), sid.size(), true, true);
  REQUIRE(wb_sid.error.empty());
  REQUIRE_EQ(wb_sid.frames.size(), 1u);
  CHECK(wb_sid.frames[0].is_sid);
  CHECK_EQ(wb_sid.frames[0].toc, 0x4Cu);
  CHECK_EQ(wb_sid.frames[0].data.size(), kWbSidOctets);

  // The two bands disagree about FT 8 as well: 477 bits (60 octets) of AMR-WB
  // speech versus 39 bits of AMR-NB SID. Same ToC octet, different band -- so
  // this is what proves `is_wb` really selects a table rather than a label.
  std::vector<uint8_t> wb_ft8 = {0x00, 0x40};  // ToC 0b0_1000_0_00: FT 8, Q 0
  wb_ft8.insert(wb_ft8.end(), kWbFt8Octets, 0x3C);
  const AmrDepackResult wb = depack_amr(wb_ft8.data(), wb_ft8.size(), true, true);
  REQUIRE(wb.error.empty());
  REQUIRE_EQ(wb.frames.size(), 1u);
  CHECK_FALSE(wb.frames[0].is_sid);
  CHECK_EQ(wb.frames[0].data.size(), kWbFt8Octets);

  // Read as AMR-NB the same packet is a 5-octet SID frame followed by 55 octets
  // that no frame accounts for -- i.e. the NB table gives a different answer.
  CHECK_FALSE(depack_amr(wb_ft8.data(), wb_ft8.size(), false, true).error.empty());

  // ...and the AMR-NB SID frame really is 39 bits (5 octets, the last one with
  // a single spare bit, hence 0xFE staying 0xFE).
  std::vector<uint8_t> nb_sid = {0x00, 0x40};
  nb_sid.insert(nb_sid.end(), kNbSidOctets, 0xFE);
  const AmrDepackResult nb = depack_amr(nb_sid.data(), nb_sid.size(), false, true);
  REQUIRE(nb.error.empty());
  REQUIRE_EQ(nb.frames.size(), 1u);
  CHECK(nb.frames[0].is_sid);
  CHECK_EQ(nb.frames[0].data.size(), kNbSidOctets);
  CHECK_EQ(nb.frames[0].data.back(), 0xFEu);
}

TEST_CASE("AmrDepack AmrModeDetector picks the mode with more valid parses") {
  const std::vector<uint8_t> oa_packet = make_oa_ft7_packet();
  const std::vector<uint8_t> be_packet = make_be_ft7_packet();

  // Each packet parses under its own mode and is rejected by the other, which
  // the two "sanity" checks below pin so a detector case cannot pass because
  // both modes silently accepted everything.
  REQUIRE(depack_amr(oa_packet.data(), oa_packet.size(), false, true).error.empty());
  REQUIRE_FALSE(depack_amr(oa_packet.data(), oa_packet.size(), false, false).error.empty());
  REQUIRE(depack_amr(be_packet.data(), be_packet.size(), false, false).error.empty());
  REQUIRE_FALSE(depack_amr(be_packet.data(), be_packet.size(), false, true).error.empty());

  SUBCASE("50 octet-aligned packets") {
    AmrModeDetector detector;
    for (int i = 0; i < 50; ++i) {
      detector.observe(oa_packet.data(), oa_packet.size(), false);
    }
    CHECK(detector.result() == AmrMode::OctetAligned);
  }

  SUBCASE("50 bandwidth-efficient packets") {
    AmrModeDetector detector;
    for (int i = 0; i < 50; ++i) {
      detector.observe(be_packet.data(), be_packet.size(), false);
    }
    CHECK(detector.result() == AmrMode::BandwidthEfficient);
  }

  SUBCASE("25 of each: a tie resolves to bandwidth-efficient") {
    AmrModeDetector detector;
    for (int i = 0; i < 25; ++i) {
      detector.observe(oa_packet.data(), oa_packet.size(), false);
      detector.observe(be_packet.data(), be_packet.size(), false);
    }
    CHECK(detector.result() == AmrMode::BandwidthEfficient);
  }

  SUBCASE("no observations at all: a 0:0 tie, so bandwidth-efficient") {
    const AmrModeDetector detector;
    CHECK(detector.result() == AmrMode::BandwidthEfficient);
  }

  SUBCASE("observation stops at 50, so the verdict does not depend on the feed") {
    // 50 octet-aligned packets fill the detector, then 50 bandwidth-efficient
    // ones arrive. Without the cap those would tie at 50:50 and the answer
    // would flip to bandwidth-efficient, so this case fails if the cap is
    // dropped.
    AmrModeDetector detector;
    for (int i = 0; i < 50; ++i) {
      detector.observe(oa_packet.data(), oa_packet.size(), false);
    }
    for (int i = 0; i < 50; ++i) {
      detector.observe(be_packet.data(), be_packet.size(), false);
    }
    CHECK(detector.result() == AmrMode::OctetAligned);
  }

  SUBCASE("the band is part of the observation") {
    // The detector parses with the band it is told; a WB payload given the NB
    // table is not the same parse. Here the WB payload is a whole FT 9 SID
    // frame in either band, so the check is that is_wb = true still lands on
    // octet-aligned rather than erroring the packet away.
    std::vector<uint8_t> wb_packet = {0x00, 0x4C};
    wb_packet.insert(wb_packet.end(), kWbSidOctets, 0x33);
    REQUIRE(depack_amr(wb_packet.data(), wb_packet.size(), true, true).error.empty());
    AmrModeDetector detector;
    for (int i = 0; i < 50; ++i) {
      detector.observe(wb_packet.data(), wb_packet.size(), true);
    }
    CHECK(detector.result() == AmrMode::OctetAligned);
  }
}

TEST_CASE("AmrDepack rejects crc and interleaved streams as unsupported") {
  // crc=1 and robust-sorting=1 are SDP fmtp properties, so they are passed in
  // rather than sniffed from the payload; either one means the frames are not
  // laid out as a plain list (RFC 4867 section 4.4.3) and the stream has to be
  // reported unsupported instead of being mis-parsed.
  const std::vector<uint8_t> packet = make_oa_ft7_packet();

  const AmrDepackResult crc =
      depack_amr(packet.data(), packet.size(), false, true, true, false);
  CHECK_EQ(crc.error, "unsupported: crc");
  CHECK(crc.frames.empty());
  CHECK_FALSE(crc.speech_lost);
  CHECK_FALSE(crc.no_data);

  const AmrDepackResult interleaved =
      depack_amr(packet.data(), packet.size(), false, true, false, true);
  CHECK_EQ(interleaved.error, "unsupported: crc");
  CHECK(interleaved.frames.empty());

  // Both flags at once is the same answer, and the 4-argument form is the
  // 6-argument one with both flags false -- the same packet parses through it.
  CHECK_EQ(depack_amr(packet.data(), packet.size(), false, false, true, true).error,
           "unsupported: crc");
  const AmrDepackResult plain =
      depack_amr(packet.data(), packet.size(), false, true);
  REQUIRE(plain.error.empty());
  REQUIRE_EQ(plain.frames.size(), 1u);
}
