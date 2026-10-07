// RTP5-NAT-01: H.264 de-packetization (RFC 6184).
//
// What this class has to get right, and what the cases below pin:
//
//   * The three packetization modes are told apart by the *low five bits* of
//     the first payload octet, and those same five bits mean something
//     different in each mode: they are the NAL type in a single NAL unit
//     packet, the aggregation type (24) in a STAP-A, and the *fragment's* NAL
//     type in an FU-A, whose real header has to be rebuilt from the FU
//     indicator plus the FU header.
//   * A sequence gap is not one condition but three. In front of a single NAL
//     it costs nothing (the NAL is self-contained) but still has to be
//     reported; in the middle of an FU it invalidates the whole NAL being
//     assembled; and when the packet after the gap carries S = 1 it is a
//     legitimate new FU start, so the depacketizer must not throw it away with
//     the dead one.
//   * A packet this class cannot reassemble (FU-B here) must not disturb an FU
//     that is being assembled -- it belongs to a different packetization mode
//     and has nothing to do with the buffer.
//
// Every input is written as binary literals, as the card requires, so the bit
// fields (F, NRI, type, S, E) are readable in the test rather than hidden in
// hand-computed hex.
//
// Case names all start with "H264Depack" so that
// `run_host_tests.ps1 -Test "*H264*"` selects exactly this file's cases.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/depack/H264Depack.h"

using layanalyzer::rtp::H264Depack;
using layanalyzer::rtp::H264DepackOutput;

namespace {

// F = 0, NRI = 3. Every packet below uses the same NRI so that a rebuilt FU-A
// header is comparable with the single NAL unit's header byte by byte.
constexpr uint8_t kNri3 = 0b01100000;

// Types, as the low five bits of the first payload octet.
constexpr uint8_t kTypeIdr = 5;
constexpr uint8_t kTypeSps = 7;
constexpr uint8_t kTypePps = 8;
constexpr uint8_t kTypeStapA = 24;
constexpr uint8_t kTypeFuA = 28;
constexpr uint8_t kTypeFuB = 29;

// One whole IDR slice as a single NAL unit packet: NAL header 0b01100101
// (F = 0, NRI = 3, type = 5) followed by four slice octets.
const std::vector<uint8_t> kIdrNalUnit = {
    0b01100101,  // F = 0, NRI = 3, type = 5 (IDR)
    0b10000000,
    0b00000001,
    0b10101010,
    0b01010101,
};

// An SPS and a PPS as they appear inside a STAP-A: each is a complete NAL unit
// *including* its header (RFC 6184 section 5.7.1), which is why the bytes go up
// unchanged.
const std::vector<uint8_t> kSpsNalUnit = {
    0b01100111,  // F = 0, NRI = 3, type = 7 (SPS)
    0b01000000,
    0b00000001,
    0b00000010,
};
const std::vector<uint8_t> kPpsNalUnit = {
    0b01101000,  // F = 0, NRI = 3, type = 8 (PPS)
    0b10101010,
    0b01010101,
};

// The FU indicator for an FU-A carrying an NRI = 3 NAL: F = 0, NRI = 3,
// type = 28 -> 0b01111100. The FU header then carries S and E in its top two
// bits and the *fragmented* NAL's type in its low five.
constexpr uint8_t kFuAIndicatorNri3 = 0b01111100;
constexpr uint8_t kFuAStart = 0b10000000;
constexpr uint8_t kFuAEnd = 0b01000000;

// The three fragments of one IDR slice, in order. The data octets are distinct
// per fragment so that a concatenation bug shows up as a wrong octet rather
// than as a mis-sized NAL.
const std::vector<uint8_t> kFuAFirstFragment = {
    kFuAIndicatorNri3,
    static_cast<uint8_t>(kFuAStart | kTypeIdr),  // 0b10000101
    0b00000001,
    0b00000010,
};
const std::vector<uint8_t> kFuAMiddleFragment = {
    kFuAIndicatorNri3,
    static_cast<uint8_t>(kTypeIdr),  // 0b00000101: S = 0, E = 0
    0b00000011,
    0b00000100,
};
const std::vector<uint8_t> kFuALastFragment = {
    kFuAIndicatorNri3,
    static_cast<uint8_t>(kFuAEnd | kTypeIdr),  // 0b01000101
    0b00000101,
};

// What the three fragments above have to reassemble into: the rebuilt NAL
// header (NRI | type, so 0b01100000 | 0b00000101 = kIdrNalUnit's first octet)
// followed by every fragment's data octets in order.
const std::vector<uint8_t> kReassembledIdr = {
    0b01100101,
    0b00000001,
    0b00000010,
    0b00000011,
    0b00000100,
    0b00000101,
};

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

#define H264_CHECK_OCTETS(actual, expected)                                    \
  do {                                                                         \
    size_t h264_difference = 0;                                                \
    CHECK_MESSAGE(                                                             \
        bytes_equal((actual), (expected), h264_difference),                    \
        "first difference at octet " << h264_difference << " (got "            \
                                      << (actual).size() << " octets, want "   \
                                      << (expected).size() << ")");            \
  } while (false)

// Runs one payload through a depacketizer and hands back the result; the
// depacketizer itself is what carries state between calls, so the FU cases
// below call it directly instead.
H264DepackOutput feed(H264Depack &depack, const std::vector<uint8_t> &payload,
                      bool sequence_gap = false) {
  return depack.onPacket(payload.data(), payload.size(), sequence_gap);
}

}  // namespace

TEST_CASE("H264Depack single NAL: the payload is the whole NAL unit") {
  H264Depack depack;
  const H264DepackOutput out = feed(depack, kIdrNalUnit);

  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 1u);
  CHECK_EQ(out.nals[0].size(), kIdrNalUnit.size());
  H264_CHECK_OCTETS(out.nals[0], kIdrNalUnit);
  // The bytes are handed over as they arrived: no start code, no rewriting of
  // the NAL header (a single NAL unit packet already carries the real one).
  CHECK_EQ(out.nals[0][0], kIdrNalUnit[0]);
  CHECK_FALSE(out.corrupt);
  CHECK_EQ(out.unsupported_type, 0u);
  CHECK_FALSE(depack.hasPartialFu());
}

TEST_CASE("H264Depack single NAL behind a sequence gap: accepted, but corrupt") {
  H264Depack depack;
  const H264DepackOutput out = feed(depack, kIdrNalUnit, /*sequence_gap=*/true);

  // A single NAL unit is self-contained, so a gap in front of it does not
  // damage *this* packet's bytes: it is still handed over whole.
  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 1u);
  H264_CHECK_OCTETS(out.nals[0], kIdrNalUnit);
  // ...but the gap is reported, because the access unit this NAL belongs to
  // may be missing packets and NAT-03 has to be able to drop the whole frame.
  CHECK(out.corrupt);
}

TEST_CASE("H264Depack STAP-A: two aggregated NAL units split on 16-bit lengths") {
  // 0b00011000 is F = 0, NRI = 3, type = 24 (STAP-A). Then two 16-bit
  // big-endian lengths, each followed by one whole NAL unit.
  const std::vector<uint8_t> payload = {
      0b00011000,
      0b00000000, 0b00000100,  // length 4: the SPS above
      (kSpsNalUnit[0]), (kSpsNalUnit[1]), (kSpsNalUnit[2]), (kSpsNalUnit[3]),
      0b00000000, 0b00000011,  // length 3: the PPS above
      (kPpsNalUnit[0]), (kPpsNalUnit[1]), (kPpsNalUnit[2]),
  };

  H264Depack depack;
  const H264DepackOutput out = feed(depack, payload);

  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 2u);
  REQUIRE_EQ(out.nals[0].size(), kSpsNalUnit.size());
  REQUIRE_EQ(out.nals[1].size(), kPpsNalUnit.size());
  H264_CHECK_OCTETS(out.nals[0], kSpsNalUnit);
  H264_CHECK_OCTETS(out.nals[1], kPpsNalUnit);
  CHECK_FALSE(out.corrupt);
}

TEST_CASE("H264Depack STAP-A with a length that runs past the payload: badStap") {
  // The length says 8 octets but only 3 are left. Trusting it would hand up a
  // NAL that reaches into whatever follows in memory.
  const std::vector<uint8_t> truncated = {
      0b00011000,
      0b00000000, 0b00001000,
      0b01100111, 0b01000000, 0b00000001,
  };
  H264Depack depack;
  const H264DepackOutput overrun = feed(depack, truncated);
  CHECK_EQ(overrun.error, "badStap");
  CHECK(overrun.nals.empty());
  CHECK_FALSE(overrun.corrupt);

  // One complete entry followed by a lone octet: no room left for a 16-bit
  // length, so the trailing octet cannot be a NAL either.
  const std::vector<uint8_t> trailer = {
      0b00011000,
      0b00000000, 0b00000011,
      0b01101000, 0b10101010, 0b01010101,
      0b00000000,
  };
  const H264DepackOutput half_length = feed(depack, trailer);
  CHECK_EQ(half_length.error, "badStap");
  CHECK(half_length.nals.empty());
}

TEST_CASE("H264Depack FU-A: three fragments become one NAL with a rebuilt header") {
  H264Depack depack;

  const H264DepackOutput first = feed(depack, kFuAFirstFragment);
  CHECK(first.error.empty());
  CHECK(first.nals.empty());  // S = 1 alone is not a complete NAL
  CHECK(depack.hasPartialFu());

  const H264DepackOutput middle = feed(depack, kFuAMiddleFragment);
  CHECK(middle.error.empty());
  CHECK(middle.nals.empty());
  CHECK(depack.hasPartialFu());

  const H264DepackOutput last = feed(depack, kFuALastFragment);
  CHECK(last.error.empty());
  REQUIRE_EQ(last.nals.size(), 1u);
  CHECK_FALSE(depack.hasPartialFu());

  // The NAL header the fragments never carried: NRI comes from the FU
  // indicator, the type from the FU header -- so 0b01111100 and 0b01000101
  // become 0b01100101, the same header the unfragmented NAL would have had.
  REQUIRE_EQ(last.nals[0].size(), kReassembledIdr.size());
  CHECK_EQ(last.nals[0][0], static_cast<uint8_t>(kNri3 | kTypeIdr));
  H264_CHECK_OCTETS(last.nals[0], kReassembledIdr);
  CHECK_FALSE(last.corrupt);
}

TEST_CASE("H264Depack FU-A without a start fragment: fuWithoutStart") {
  H264Depack depack;

  // A middle fragment with nothing to attach to: its start was lost.
  const H264DepackOutput middle = feed(depack, kFuAMiddleFragment);
  CHECK_EQ(middle.error, "fuWithoutStart");
  CHECK(middle.nals.empty());
  CHECK_FALSE(depack.hasPartialFu());

  // An end fragment is no better on its own: without the earlier data there is
  // no NAL to complete, and emitting just this fragment's octets as one would
  // invent a NAL the sender never sent.
  const H264DepackOutput last = feed(depack, kFuALastFragment);
  CHECK_EQ(last.error, "fuWithoutStart");
  CHECK(last.nals.empty());
  CHECK_FALSE(depack.hasPartialFu());

  // The same two fragments after a start are fine, so the rejection above is
  // the missing start and not something else about them.
  H264Depack fresh;
  CHECK(feed(fresh, kFuAFirstFragment).error.empty());
  CHECK(feed(fresh, kFuAMiddleFragment).error.empty());
  const H264DepackOutput end = feed(fresh, kFuALastFragment);
  CHECK(end.error.empty());
  REQUIRE_EQ(end.nals.size(), 1u);
}

TEST_CASE("H264Depack FU-A with a sequence gap: the partial FU is discarded as corrupt") {
  H264Depack depack;
  CHECK(feed(depack, kFuAFirstFragment).error.empty());
  REQUIRE(depack.hasPartialFu());

  // The next fragment arrives after a gap: the packet that should have bridged
  // them is missing, so the NAL being assembled has a hole in it. It is
  // dropped rather than completed, and this packet -- a middle fragment of the
  // lost NAL, not a start of anything -- is not used to begin a new one.
  const H264DepackOutput after_gap =
      feed(depack, kFuAMiddleFragment, /*sequence_gap=*/true);
  CHECK_EQ(after_gap.error, "fuSequenceGap");
  CHECK(after_gap.corrupt);
  CHECK(after_gap.nals.empty());
  CHECK_FALSE(depack.hasPartialFu());

  // With the state dropped, the fragments that would have completed the dead
  // FU are rejected instead of being appended to it.
  const H264DepackOutput last = feed(depack, kFuALastFragment);
  CHECK_EQ(last.error, "fuWithoutStart");
  CHECK(last.nals.empty());
}

TEST_CASE("H264Depack FU-A resuming with S=1 after a gap: new FU, old one dropped, corrupt") {
  H264Depack depack;
  CHECK(feed(depack, kFuAFirstFragment).error.empty());
  REQUIRE(depack.hasPartialFu());

  // The stream resumes with a *start* fragment: the old FU is gone, but this
  // packet is a legitimate beginning of the next NAL, so it must not be thrown
  // away with the dead one. The gap is still reported (corrupt), because the
  // access unit around it is missing data.
  const std::vector<uint8_t> new_start = {
      kFuAIndicatorNri3,
      static_cast<uint8_t>(kFuAStart | kTypeIdr),
      0b00001010,
      0b00001011,
  };
  const H264DepackOutput resumed = feed(depack, new_start, /*sequence_gap=*/true);
  CHECK_EQ(resumed.error, "fuSequenceGap");
  CHECK(resumed.corrupt);
  CHECK(resumed.nals.empty());
  CHECK(depack.hasPartialFu());

  // Only the new fragment's data is in the buffer: completing the FU yields the
  // new slice, not a mixture of the two.
  const std::vector<uint8_t> new_end = {
      kFuAIndicatorNri3,
      static_cast<uint8_t>(kFuAEnd | kTypeIdr),
      0b00001100,
  };
  const H264DepackOutput completed = feed(depack, new_end);
  CHECK(completed.error.empty());
  REQUIRE_EQ(completed.nals.size(), 1u);
  const std::vector<uint8_t> expected = {
      0b01100101,  // rebuilt header, same NRI and type as before
      0b00001010,
      0b00001011,
      0b00001100,
  };
  H264_CHECK_OCTETS(completed.nals[0], expected);
  CHECK_FALSE(depack.hasPartialFu());
}

TEST_CASE("H264Depack STAP-A zero-length entry: skipped") {
  // A sender is allowed to pad an aggregation packet with zero-length entries.
  // They carry no NAL, so they must not turn into an empty NAL in the output
  // (which the Annex-B writer would then emit as a bare start code).
  const std::vector<uint8_t> payload = {
      0b00011000,
      0b00000000, 0b00000100,  // length 4: the SPS
      (kSpsNalUnit[0]), (kSpsNalUnit[1]), (kSpsNalUnit[2]), (kSpsNalUnit[3]),
      0b00000000, 0b00000000,  // length 0: nothing, skipped
      0b00000000, 0b00000011,  // length 3: the PPS
      (kPpsNalUnit[0]), (kPpsNalUnit[1]), (kPpsNalUnit[2]),
      0b00000000, 0b00000000,  // length 0 again, at the end
  };

  H264Depack depack;
  const H264DepackOutput out = feed(depack, payload);
  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 2u);
  H264_CHECK_OCTETS(out.nals[0], kSpsNalUnit);
  H264_CHECK_OCTETS(out.nals[1], kPpsNalUnit);

  // A STAP-A that carries *only* zero-length entries is an empty answer, not an
  // error: there is nothing malformed about it, there is just nothing in it.
  const std::vector<uint8_t> all_empty = {
      0b00011000,
      0b00000000, 0b00000000,
      0b00000000, 0b00000000,
  };
  const H264DepackOutput empty = feed(depack, all_empty);
  CHECK(empty.error.empty());
  CHECK(empty.nals.empty());
}

TEST_CASE("H264Depack FU larger than 4 MiB: nalTooLarge and the state is cleared") {
  // RTP payloads are bounded by the MTU, so the only way a NAL reaches the cap
  // is by being fragmented: this is the pathological stream the limit exists
  // for, and without it the assembler would grow until the process dies.
  constexpr size_t kFragmentData = 1024 * 1024;  // 1 MiB of data per fragment
  const std::vector<uint8_t> fragment_data(kFragmentData, 0b10101010);

  std::vector<uint8_t> start_fragment = {kFuAIndicatorNri3,
                                         static_cast<uint8_t>(kFuAStart | kTypeIdr)};
  start_fragment.insert(start_fragment.end(), fragment_data.begin(),
                        fragment_data.end());

  std::vector<uint8_t> middle_fragment = {kFuAIndicatorNri3,
                                          static_cast<uint8_t>(kTypeIdr)};
  middle_fragment.insert(middle_fragment.end(), fragment_data.begin(),
                         fragment_data.end());

  H264Depack depack;
  CHECK(feed(depack, start_fragment).error.empty());
  REQUIRE(depack.hasPartialFu());

  // 1 NAL header octet + 1 MiB per fragment: after the start fragment and two
  // middle ones the NAL is 1 + 3 * 1 MiB = 3145729 octets, still under the
  // 4 MiB cap. The third middle fragment would take it to 4194305, one octet
  // over, and that is where the cap has to fire.
  H264DepackOutput out = feed(depack, middle_fragment);
  CHECK(out.error.empty());
  out = feed(depack, middle_fragment);
  CHECK(out.error.empty());
  out = feed(depack, middle_fragment);
  CHECK_EQ(out.error, "nalTooLarge");
  CHECK(out.nals.empty());
  CHECK_FALSE(out.corrupt);

  // "Cleared" means the buffer is gone, not parked: an end fragment can no
  // longer complete anything, which is how a caller tells the two apart.
  CHECK_FALSE(depack.hasPartialFu());
  const H264DepackOutput after = feed(depack, kFuALastFragment);
  CHECK_EQ(after.error, "fuWithoutStart");

  // The depacketizer is still usable afterwards -- the cap drops the NAL being
  // assembled, not the stream.
  H264Depack fresh;
  const H264DepackOutput small = feed(fresh, kIdrNalUnit);
  CHECK(small.error.empty());
  REQUIRE_EQ(small.nals.size(), 1u);
}

TEST_CASE("H264Depack FU-B (type 29): counted as unsupported, never output") {
  // FU-B (RFC 6184 section 5.9) needs a DON field that this class does not
  // carry, so its fragments cannot be ordered or reassembled. They are counted
  // and nothing is emitted.
  const std::vector<uint8_t> fu_b = {
      0b01111101,  // F = 0, NRI = 3, type = 29 (FU-B)
      0b10000101,  // S = 1, type = 5
      0b00000000, 0b00000001,  // DON
      0b00000001,
      0b00000010,
  };
  H264Depack depack;
  const H264DepackOutput out = feed(depack, fu_b);
  CHECK_EQ(out.error, "unsupported");
  CHECK_EQ(out.unsupported_type, static_cast<uint32_t>(kTypeFuB));
  CHECK(out.nals.empty());
  CHECK_FALSE(out.corrupt);

  // The other types this class cannot reassemble take the same path. Type 0 is
  // RFC 6184's "unspecified": it has no packetization at all, so it is counted
  // like the rest, with `unsupported_type` left at its default 0 and the error
  // string as the only thing that distinguishes it from a clean packet.
  for (uint32_t type : {0u, 25u, 26u, 27u, 30u, 31u}) {
    const std::vector<uint8_t> packet = {
        static_cast<uint8_t>(kNri3 | type), 0b00000001};
    const H264DepackOutput other = feed(depack, packet);
    CHECK_EQ(other.error, "unsupported");
    CHECK_EQ(other.unsupported_type, type);
    CHECK(other.nals.empty());
  }

  // An unsupported packet is unrelated to an FU in progress, so it must not
  // clear it: an FU-B packet belongs to a different packetization mode and
  // carries nothing that could complete an FU-A.
  H264Depack running;
  CHECK(feed(running, kFuAFirstFragment).error.empty());
  REQUIRE(running.hasPartialFu());
  const H264DepackOutput interleaved = feed(running, fu_b);
  CHECK_EQ(interleaved.error, "unsupported");
  CHECK(running.hasPartialFu());

  // ...and the FU really is still the live one: the rest of its fragments
  // complete it into the same NAL as if the FU-B had never arrived.
  CHECK(feed(running, kFuAMiddleFragment).error.empty());
  const H264DepackOutput last = feed(running, kFuALastFragment);
  CHECK(last.error.empty());
  REQUIRE_EQ(last.nals.size(), 1u);
  H264_CHECK_OCTETS(last.nals[0], kReassembledIdr);
}
