// RTP5-NAT-02: H.265 de-packetization (RFC 7798).
//
// What this class has to get right, and what the cases below pin:
//
//   * The NAL unit header is *two* octets, not one. The 6-bit type shares
//     octet 0 with F and with the top bit of nuh_layer_id, so the type is
//     `(payload[0] >> 1) & 0x3F` and both of the other fields have to survive
//     into whatever this class rebuilds.
//   * The three packetization modes are told apart by the 6-bit type: it is the
//     NAL type itself in a single NAL unit packet (0-47, *including* 0, which
//     is HEVC's TRAIL_N and a real type, unlike H.264's unspecified 0), the
//     payload header's type (48) in an AP, and the *fragment's* type -- in the
//     FU header's low six bits, not five -- for an FU.
//   * A sequence gap is not one condition but three. In front of a single NAL
//     it costs nothing (the NAL is self-contained) but still has to be
//     reported; in the middle of an FU it invalidates the whole NAL being
//     assembled; and when the packet after the gap carries S = 1 it is a
//     legitimate new FU start, so the depacketizer must not throw it away with
//     the dead one.
//   * A packet this class cannot use (PACI, or an AP on a stream that has
//     DONL) must not disturb an FU that is being assembled -- it has nothing to
//     do with the buffer.
//
// Every input is written as binary literals, as the card requires, so the bit
// fields (F, type, layer id, temporal id, S, E) are readable in the test rather
// than hidden in hand-computed hex.
//
// Case names all start with "H265Depack" so that
// `run_host_tests.ps1 -Test "*H265*"` selects exactly this file's cases.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/depack/H265Depack.h"

using layanalyzer::rtp::H265Depack;
using layanalyzer::rtp::H265DepackOutput;

namespace {

// Types, as the 6-bit field of octet 0 (so octet 0 is `(type << 1) | layer bit`
// and the literal below shows the whole octet).
constexpr uint8_t kTypeIdrWRadl = 19;  // IDR_W_RADL, an IRAP (16-23) keyframe
constexpr uint8_t kTypeVps = 32;
constexpr uint8_t kTypeSps = 33;
constexpr uint8_t kTypePps = 34;
constexpr uint8_t kTypeAp = 48;
constexpr uint8_t kTypeFu = 49;
constexpr uint8_t kTypePaci = 50;

// One whole IDR_W_RADL slice as a single NAL unit packet: the 2-octet NAL unit
// header followed by four slice octets.
const std::vector<uint8_t> kIdrNalUnit = {
    0b00100110,  // F = 0, type = 19 (IDR_W_RADL), layer id top bit = 0
    0b00000001,  // layer id = 0 (low five bits), temporal id + 1 = 1
    0b10000000,
    0b00000001,
    0b10101010,
    0b01010101,
};

// A VPS, an SPS and a PPS as they appear inside an AP: each is a complete NAL
// unit *including* its 2-octet header, which is why the bytes go up unchanged.
// The three have different lengths so that a mis-read length shows up as a
// wrong octet rather than as a mis-sized NAL.
const std::vector<uint8_t> kVpsNalUnit = {
    0b01000000,  // F = 0, type = 32 (VPS)
    0b00000001,
    0b01000000,
    0b00000001,
    0b00000010,
};
const std::vector<uint8_t> kSpsNalUnit = {
    0b01000010,  // F = 0, type = 33 (SPS)
    0b00000001,
    0b10101010,
    0b01010101,
};
const std::vector<uint8_t> kPpsNalUnit = {
    0b01000100,  // F = 0, type = 34 (PPS)
    0b00000001,
    0b11110000,
};

// An AP carrying all three parameter sets. Its first two octets are the AP's
// own payload header -- octet 1 is where a DONL would go, and the lengths start
// after it, at octet 2 -- and each entry is a 16-bit big-endian length followed
// by that many octets of one whole NAL unit.
const std::vector<uint8_t> kApPayload = {
    0b01100000,  // F = 0, type = 48 (AP), layer id top bit = 0
    0b00000001,  // layer id = 0, temporal id + 1 = 1
    0b00000000, 0b00000101,  // length 5: the VPS
    (kVpsNalUnit[0]), (kVpsNalUnit[1]), (kVpsNalUnit[2]), (kVpsNalUnit[3]),
    (kVpsNalUnit[4]),
    0b00000000, 0b00000100,  // length 4: the SPS
    (kSpsNalUnit[0]), (kSpsNalUnit[1]), (kSpsNalUnit[2]), (kSpsNalUnit[3]),
    0b00000000, 0b00000011,  // length 3: the PPS
    (kPpsNalUnit[0]), (kPpsNalUnit[1]), (kPpsNalUnit[2]),
};

// RFC 7798 section 4.4.3: an FU packet is
//   [PayloadHdr: F | FuType(6) | nuh_layer_id bit0]  <- octet 0
//   [FU header:   S | E | FuType(6)]                 <- octet 1
//   [fragment data ...]                              <- octet 2 onwards
//
// **Two** header octets. The earlier version of this file modelled a *three*
// octet header (PayloadHdr, then a "header octet 1", then the FU header), and
// `H265Depack` was written to match -- so the unit test and the implementation
// agreed with each other and both disagreed with the RFC. A real H.265 stream
// then lost its first data octet per fragment: on device, `exportRtpVideo`
// reported `depackErrors=70` beside `frames=64`, and the MP4 built from the
// result had an `mdat` running past EOF (no `moov`), so no player could open
// it. A test that only feeds the implementation's own layout cannot catch this;
// the layout has to come from the RFC.
constexpr uint8_t kFuPayloadHeader = 0b01100010;  // F = 0, FuType = 49, layer id 0
constexpr uint8_t kFuStart = 0b10000000;
constexpr uint8_t kFuEnd = 0b01000000;

// The NAL unit header's own second octet, which is the *first data octet* of
// the start fragment (the FU header replaced only the type field). Its value is
// exactly what kIdrNalUnit carries in octet 1.
constexpr uint8_t kFuNalHeaderOctet1 = 0b00000001;

// The three fragments of one IDR slice, in order. The data octets are distinct
// per fragment so that a concatenation bug shows up as a wrong octet rather
// than as a mis-sized NAL.
const std::vector<uint8_t> kFuFirstFragment = {
    kFuPayloadHeader,
    static_cast<uint8_t>(kFuStart | kTypeIdrWRadl),  // FU header
    kFuNalHeaderOctet1,  // data[0] -- the NAL header's second octet
    0b00000010,          // data[1]
    0b00000011,          // data[2]
};
const std::vector<uint8_t> kFuMiddleFragment = {
    kFuPayloadHeader,
    static_cast<uint8_t>(kTypeIdrWRadl),  // FU header: S = 0, E = 0
    0b00000100,  // data[0]
    0b00000101,  // data[1]
};
const std::vector<uint8_t> kFuLastFragment = {
    kFuPayloadHeader,
    static_cast<uint8_t>(kFuEnd | kTypeIdrWRadl),  // FU header
    0b00000110,  // data[0]
};

// What the three fragments above have to reassemble into: the rebuilt 2-octet
// NAL unit header -- `(payload[0] & 0x81) | (19 << 1)` followed by the start
// fragment's first data octet, which is exactly the header kIdrNalUnit carries
// -- and then every fragment's data octets in order.
const std::vector<uint8_t> kReassembledIdr = {
    0b00100110,
    0b00000001,
    0b00000010,
    0b00000011,
    0b00000100,
    0b00000101,
    0b00000110,
};

// The same fragmentation with nuh_layer_id = 32 instead of 0. The layer id is
// six bits and straddles the two header octets, so its top bit is bit 0 of the
// FU packet's first octet -- the bit the rebuild's `& 0x81` has to carry over
// (header decision 2). With layer id 0 that bit is clear and this half of the
// formula cannot be observed at all, which is why this sub-case exists; the F
// bit is preserved by the same mask but is 0 in any conforming stream, so it
// stays 0 here too.
constexpr uint8_t kFuPayloadHeaderLayerId32 = 0b01100011;
const std::vector<uint8_t> kFuLayerId32Start = {
    kFuPayloadHeaderLayerId32,
    static_cast<uint8_t>(kFuStart | kTypeIdrWRadl), kFuNalHeaderOctet1, 0b00001010};
const std::vector<uint8_t> kFuLayerId32End = {
    kFuPayloadHeaderLayerId32,
    static_cast<uint8_t>(kFuEnd | kTypeIdrWRadl), 0b00001011};
const std::vector<uint8_t> kReassembledLayerId32 = {
    0b00100111,  // rebuilt octet 0: type 19, layer id's top bit = 1
    0b00000001,
    0b00001010,
    0b00001011,
};

// A PACI packet: a 2-octet payload header (F = 0, type = 50, layer id 0) and
// payload content information this class does not interpret.
const std::vector<uint8_t> kPaciPacket = {
    0b01100100,
    0b00000001,
    0b00000000,
};

// The 6-bit NAL unit type of a NAL unit header's first octet, spelled the way
// the depacketizer spells it. The type constants above are only useful if they
// agree with the octets the packets actually carry, so the cases below read the
// type back out of what came through instead of trusting the literals twice.
uint8_t nal_type_of(const std::vector<uint8_t> &nal) {
  return static_cast<uint8_t>((nal[0] >> 1) & 0x3Fu);
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

#define H265_CHECK_OCTETS(actual, expected)                                    \
  do {                                                                         \
    size_t h265_difference = 0;                                                \
    CHECK_MESSAGE(                                                             \
        bytes_equal((actual), (expected), h265_difference),                    \
        "first difference at octet " << h265_difference << " (got "            \
                                      << (actual).size() << " octets, want "   \
                                      << (expected).size() << ")");            \
  } while (false)

// Runs one payload through a depacketizer and hands back the result; the
// depacketizer itself is what carries state between calls, so the FU cases
// below call it directly instead.
H265DepackOutput feed(H265Depack &depack, const std::vector<uint8_t> &payload,
                      bool sequence_gap = false) {
  return depack.onPacket(payload.data(), payload.size(), sequence_gap);
}

}  // namespace

TEST_CASE("H265Depack single NAL: the payload is the whole NAL unit") {
  H265Depack depack;
  const H265DepackOutput out = feed(depack, kIdrNalUnit);

  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 1u);
  CHECK_EQ(out.nals[0].size(), kIdrNalUnit.size());
  H265_CHECK_OCTETS(out.nals[0], kIdrNalUnit);
  // The bytes are handed over as they arrived: no start code, and no rewriting
  // of either header octet (a single NAL unit packet already carries the real
  // two).
  CHECK_EQ(out.nals[0][0], kIdrNalUnit[0]);
  CHECK_EQ(out.nals[0][1], kIdrNalUnit[1]);
  CHECK_FALSE(out.corrupt);
  CHECK_EQ(out.unsupported_type, 0u);
  CHECK_FALSE(depack.hasPartialFu());
}

TEST_CASE("H265Depack single NAL: the range starts at type 0, which is a real type") {
  // H.264's type 0 is "unspecified" and takes the unsupported path. HEVC's is
  // TRAIL_N, an ordinary NAL unit type, so `(payload[0] >> 1) & 0x3F == 0` is a
  // single NAL unit packet like any other and has to be handed up whole.
  const std::vector<uint8_t> trail_n = {
      0b00000000,  // F = 0, type = 0 (TRAIL_N), layer id top bit = 0
      0b00000001,
      0b01010101,
  };
  H265Depack depack;
  const H265DepackOutput out = feed(depack, trail_n);

  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 1u);
  H265_CHECK_OCTETS(out.nals[0], trail_n);

  // The other end of the range, type 47, is also a single NAL unit packet: the
  // reserved values begin at 51, after the two packetization modes and PACI.
  const std::vector<uint8_t> type_47 = {
      0b01011110,  // F = 0, type = 47, layer id top bit = 0
      0b00000001,
      0b01010101,
  };
  const H265DepackOutput top_of_range = feed(depack, type_47);
  CHECK(top_of_range.error.empty());
  REQUIRE_EQ(top_of_range.nals.size(), 1u);
  H265_CHECK_OCTETS(top_of_range.nals[0], type_47);
}

TEST_CASE("H265Depack single NAL behind a sequence gap: accepted, but corrupt") {
  H265Depack depack;
  const H265DepackOutput out = feed(depack, kIdrNalUnit, /*sequence_gap=*/true);

  // A single NAL unit is self-contained, so a gap in front of it does not
  // damage *this* packet's bytes: it is still handed over whole.
  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 1u);
  H265_CHECK_OCTETS(out.nals[0], kIdrNalUnit);
  // ...but the gap is reported, because the access unit this NAL belongs to
  // may be missing packets and NAT-03 has to be able to drop the whole frame.
  CHECK(out.corrupt);
}

TEST_CASE("H265Depack AP: three aggregated NAL units split on 16-bit lengths") {
  H265Depack depack;
  const H265DepackOutput out = feed(depack, kApPayload);

  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 3u);
  REQUIRE_EQ(out.nals[0].size(), kVpsNalUnit.size());
  REQUIRE_EQ(out.nals[1].size(), kSpsNalUnit.size());
  REQUIRE_EQ(out.nals[2].size(), kPpsNalUnit.size());
  H265_CHECK_OCTETS(out.nals[0], kVpsNalUnit);
  H265_CHECK_OCTETS(out.nals[1], kSpsNalUnit);
  H265_CHECK_OCTETS(out.nals[2], kPpsNalUnit);
  // The aggregated NAL units keep their own types: the AP octet is an indicator
  // and nothing is inherited from it.
  CHECK_EQ(nal_type_of(out.nals[0]), kTypeVps);
  CHECK_EQ(nal_type_of(out.nals[1]), kTypeSps);
  CHECK_EQ(nal_type_of(out.nals[2]), kTypePps);
  CHECK_FALSE(out.corrupt);

  // An AP arriving while an FU is being assembled is unrelated to it: the AP's
  // NAL units are complete and are handed up on their own, and the fragments
  // already collected stay in the buffer, so the FU still completes into the
  // NAL it started (header decision 11).
  H265Depack running;
  CHECK(feed(running, kFuFirstFragment).error.empty());
  REQUIRE(running.hasPartialFu());
  const H265DepackOutput interleaved = feed(running, kApPayload);
  CHECK(interleaved.error.empty());
  CHECK_EQ(interleaved.nals.size(), 3u);
  CHECK(running.hasPartialFu());

  CHECK(feed(running, kFuMiddleFragment).error.empty());
  const H265DepackOutput last = feed(running, kFuLastFragment);
  CHECK(last.error.empty());
  REQUIRE_EQ(last.nals.size(), 1u);
  H265_CHECK_OCTETS(last.nals[0], kReassembledIdr);
}

TEST_CASE("H265Depack AP with a length that runs past the payload: badAp") {
  // The length says 8 octets but only 3 are left. Trusting it would hand up a
  // NAL that reaches into whatever follows in memory.
  const std::vector<uint8_t> truncated = {
      0b01100000,
      0b00000001,
      0b00000000, 0b00001000,
      0b01000010, 0b00000001, 0b10101010,
  };
  H265Depack depack;
  const H265DepackOutput overrun = feed(depack, truncated);
  CHECK_EQ(overrun.error, "badAp");
  CHECK(overrun.nals.empty());
  CHECK_FALSE(overrun.corrupt);

  // One complete entry followed by a lone octet: no room left for a 16-bit
  // length, so the trailing octet cannot be a NAL either.
  const std::vector<uint8_t> trailer = {
      0b01100000,
      0b00000001,
      0b00000000, 0b00000011,
      0b01000100, 0b00000001, 0b11110000,
      0b00000000,
  };
  const H265DepackOutput half_length = feed(depack, trailer);
  CHECK_EQ(half_length.error, "badAp");
  CHECK(half_length.nals.empty());
}

TEST_CASE("H265Depack FU: three fragments become one NAL with a rebuilt 2-octet header") {
  // The packet's own type field is 49; the fragmented NAL unit's type lives in
  // the FU header, six bits wide.
  CHECK_EQ(nal_type_of(kFuFirstFragment), kTypeFu);

  H265Depack depack;

  const H265DepackOutput first = feed(depack, kFuFirstFragment);
  CHECK(first.error.empty());
  CHECK(first.nals.empty());  // S = 1 alone is not a complete NAL
  CHECK(depack.hasPartialFu());

  const H265DepackOutput middle = feed(depack, kFuMiddleFragment);
  CHECK(middle.error.empty());
  CHECK(middle.nals.empty());
  CHECK(depack.hasPartialFu());

  const H265DepackOutput last = feed(depack, kFuLastFragment);
  CHECK(last.error.empty());
  REQUIRE_EQ(last.nals.size(), 1u);
  CHECK_FALSE(depack.hasPartialFu());

  // The header the fragments never carried, rebuilt as the card's formula --
  // `(payload[0] & 0x81) | (type << 1)` for octet 0 and the FU packet's own
  // octet 1 for the rest -- which is the same 2-octet header the unfragmented
  // NAL would have had. Both octets are checked, because a rebuild that stopped
  // after the type would leave the layer id and temporal id missing.
  REQUIRE_EQ(last.nals[0].size(), kReassembledIdr.size());
  CHECK_EQ(last.nals[0][0], static_cast<uint8_t>((kFuPayloadHeader & 0x81u) |
                                                 (kTypeIdrWRadl << 1)));
  CHECK_EQ(last.nals[0][1], kFuNalHeaderOctet1);
  H265_CHECK_OCTETS(last.nals[0], kReassembledIdr);
  CHECK_FALSE(last.corrupt);

  // The layer id's top bit lives in the FU packet's first octet, so the rebuild
  // has to carry it over: with nuh_layer_id = 32 octet 0 is 0b00100111, not the
  // 0b00100110 the same fragments would rebuild if the bit were dropped.
  H265Depack layer_id_32;
  CHECK(feed(layer_id_32, kFuLayerId32Start).error.empty());
  const H265DepackOutput rebuilt = feed(layer_id_32, kFuLayerId32End);
  CHECK(rebuilt.error.empty());
  REQUIRE_EQ(rebuilt.nals.size(), 1u);
  H265_CHECK_OCTETS(rebuilt.nals[0], kReassembledLayerId32);

  // A FU with no room for even one data octet -- the 2-octet payload header and
  // the FU header alone -- carries no fragment, so it is rejected rather than
  // started or appended to (header decision 6). The floor is three octets: the
  // two FU header octets plus at least one data octet. H.264's floor is also
  // three, because its FU header is a second octet on top of a *one*-octet
  // payload header, where HEVC's is a second octet on top of a one-octet
  // payload header too -- same total, different reason.
  const std::vector<uint8_t> header_only = {
      kFuPayloadHeader,
      static_cast<uint8_t>(kFuStart | kTypeIdrWRadl),
  };
  H265Depack no_data;
  const H265DepackOutput too_short = feed(no_data, header_only);
  CHECK_EQ(too_short.error, "badFu");
  CHECK(too_short.nals.empty());
  CHECK_FALSE(no_data.hasPartialFu());
}

TEST_CASE("H265Depack FU without a start fragment: fuWithoutStart") {
  H265Depack depack;

  // A middle fragment with nothing to attach to: its start was lost.
  const H265DepackOutput middle = feed(depack, kFuMiddleFragment);
  CHECK_EQ(middle.error, "fuWithoutStart");
  CHECK(middle.nals.empty());
  CHECK_FALSE(depack.hasPartialFu());

  // An end fragment is no better on its own: without the earlier data there is
  // no NAL to complete, and emitting just this fragment's octets as one would
  // invent a NAL the sender never sent.
  const H265DepackOutput last = feed(depack, kFuLastFragment);
  CHECK_EQ(last.error, "fuWithoutStart");
  CHECK(last.nals.empty());
  CHECK_FALSE(depack.hasPartialFu());

  // The same two fragments after a start are fine, so the rejection above is
  // the missing start and not something else about them.
  H265Depack fresh;
  CHECK(feed(fresh, kFuFirstFragment).error.empty());
  CHECK(feed(fresh, kFuMiddleFragment).error.empty());
  const H265DepackOutput end = feed(fresh, kFuLastFragment);
  CHECK(end.error.empty());
  REQUIRE_EQ(end.nals.size(), 1u);
}

TEST_CASE("H265Depack FU with a sequence gap: the partial FU is discarded as corrupt") {
  H265Depack depack;
  CHECK(feed(depack, kFuFirstFragment).error.empty());
  REQUIRE(depack.hasPartialFu());

  // The next fragment arrives after a gap: the packet that should have bridged
  // them is missing, so the NAL being assembled has a hole in it. It is
  // dropped rather than completed, and this packet -- a middle fragment of the
  // lost NAL, not a start of anything -- is not used to begin a new one.
  const H265DepackOutput after_gap =
      feed(depack, kFuMiddleFragment, /*sequence_gap=*/true);
  CHECK_EQ(after_gap.error, "fuSequenceGap");
  CHECK(after_gap.corrupt);
  CHECK(after_gap.nals.empty());
  CHECK_FALSE(depack.hasPartialFu());

  // With the state dropped, the fragments that would have completed the dead
  // FU are rejected instead of being appended to it.
  const H265DepackOutput last = feed(depack, kFuLastFragment);
  CHECK_EQ(last.error, "fuWithoutStart");
  CHECK(last.nals.empty());
}

TEST_CASE("H265Depack FU resuming with S=1 after a gap: new FU, old one dropped, corrupt") {
  H265Depack depack;
  CHECK(feed(depack, kFuFirstFragment).error.empty());
  REQUIRE(depack.hasPartialFu());

  // The stream resumes with a *start* fragment: the old FU is gone, but this
  // packet is a legitimate beginning of the next NAL, so it must not be thrown
  // away with the dead one. The gap is still reported (corrupt), because the
  // access unit around it is missing data.
  const std::vector<uint8_t> new_start = {
      kFuPayloadHeader,
      static_cast<uint8_t>(kFuStart | kTypeIdrWRadl),
      kFuNalHeaderOctet1,
      0b00001010,
      0b00001011,
  };
  const H265DepackOutput resumed = feed(depack, new_start, /*sequence_gap=*/true);
  CHECK_EQ(resumed.error, "fuSequenceGap");
  CHECK(resumed.corrupt);
  CHECK(resumed.nals.empty());
  CHECK(depack.hasPartialFu());

  // Only the new fragment's data is in the buffer: completing the FU yields the
  // new slice, not a mixture of the two.
  const std::vector<uint8_t> new_end = {
      kFuPayloadHeader,
      static_cast<uint8_t>(kFuEnd | kTypeIdrWRadl),
      0b00001100,
  };
  const H265DepackOutput completed = feed(depack, new_end);
  CHECK(completed.error.empty());
  REQUIRE_EQ(completed.nals.size(), 1u);
  const std::vector<uint8_t> expected = {
      0b00100110,  // rebuilt header, same type and layer id as before
      0b00000001,
      0b00001010,
      0b00001011,
      0b00001100,
  };
  H265_CHECK_OCTETS(completed.nals[0], expected);
  CHECK_FALSE(depack.hasPartialFu());
}

TEST_CASE("H265Depack AP zero-length entry: skipped") {
  // A sender is allowed to pad an aggregation packet with zero-length entries.
  // They carry no NAL, so they must not turn into an empty NAL in the output
  // (which the Annex-B writer would then emit as a bare start code).
  const std::vector<uint8_t> payload = {
      0b01100000,
      0b00000001,
      0b00000000, 0b00000100,  // length 4: the SPS
      (kSpsNalUnit[0]), (kSpsNalUnit[1]), (kSpsNalUnit[2]), (kSpsNalUnit[3]),
      0b00000000, 0b00000000,  // length 0: nothing, skipped
      0b00000000, 0b00000011,  // length 3: the PPS
      (kPpsNalUnit[0]), (kPpsNalUnit[1]), (kPpsNalUnit[2]),
      0b00000000, 0b00000000,  // length 0 again, at the end
  };

  H265Depack depack;
  const H265DepackOutput out = feed(depack, payload);
  CHECK(out.error.empty());
  REQUIRE_EQ(out.nals.size(), 2u);
  H265_CHECK_OCTETS(out.nals[0], kSpsNalUnit);
  H265_CHECK_OCTETS(out.nals[1], kPpsNalUnit);

  // An AP that carries *only* zero-length entries is an empty answer, not an
  // error: there is nothing malformed about it, there is just nothing in it.
  const std::vector<uint8_t> all_empty = {
      0b01100000,
      0b00000001,
      0b00000000, 0b00000000,
      0b00000000, 0b00000000,
  };
  const H265DepackOutput empty = feed(depack, all_empty);
  CHECK(empty.error.empty());
  CHECK(empty.nals.empty());
}

TEST_CASE("H265Depack FU larger than 4 MiB: nalTooLarge and the state is cleared") {
  // RTP payloads are bounded by the MTU, so the only way a NAL reaches the cap
  // is by being fragmented: this is the pathological stream the limit exists
  // for, and without it the assembler would grow until the process dies.
  constexpr size_t kFragmentData = 1024 * 1024;  // 1 MiB of data per fragment
  const std::vector<uint8_t> fragment_data(kFragmentData, 0b10101010);

  std::vector<uint8_t> start_fragment = {kFuPayloadHeader,
                                         static_cast<uint8_t>(kFuStart |
                                                              kTypeIdrWRadl),
                                         kFuNalHeaderOctet1};
  start_fragment.insert(start_fragment.end(), fragment_data.begin(),
                        fragment_data.end());

  std::vector<uint8_t> middle_fragment = {
      kFuPayloadHeader,
      static_cast<uint8_t>(kTypeIdrWRadl)};
  middle_fragment.insert(middle_fragment.end(), fragment_data.begin(),
                         fragment_data.end());

  H265Depack depack;
  CHECK(feed(depack, start_fragment).error.empty());
  REQUIRE(depack.hasPartialFu());

  // 2 rebuilt header octets + 1 MiB per fragment: after the start fragment and
  // two middle ones the NAL is 2 + 3 * 1 MiB = 3145730 octets, still under the
  // 4 MiB cap. The third middle fragment would take it to 4194306, two octets
  // over -- one for each header octet, which is why the H.264 case fires one
  // fragment later -- and that is where the cap has to fire.
  H265DepackOutput out = feed(depack, middle_fragment);
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
  const H265DepackOutput after = feed(depack, kFuLastFragment);
  CHECK_EQ(after.error, "fuWithoutStart");

  // The depacketizer is still usable afterwards -- the cap drops the NAL being
  // assembled, not the stream.
  H265Depack fresh;
  const H265DepackOutput small = feed(fresh, kIdrNalUnit);
  CHECK(small.error.empty());
  REQUIRE_EQ(small.nals.size(), 1u);
}

TEST_CASE("H265Depack PACI and the reserved types: counted as unsupported, never output") {
  // PACI (type 50) carries payload content information, not a NAL unit, so
  // there is nothing to hand up. It is counted like H.264's unusable
  // packetization modes and emits nothing.
  H265Depack depack;
  const H265DepackOutput out = feed(depack, kPaciPacket);
  CHECK_EQ(out.error, "unsupported");
  CHECK_EQ(out.unsupported_type, static_cast<uint32_t>(kTypePaci));
  CHECK(out.nals.empty());
  CHECK_FALSE(out.corrupt);

  // The reserved values 51-63 take the same path. The type is counted in every
  // case, and it is the only thing that distinguishes them from PACI.
  for (uint32_t type = 51; type <= 63; ++type) {
    const std::vector<uint8_t> packet = {
        static_cast<uint8_t>(type << 1), 0b00000001};
    const H265DepackOutput other = feed(depack, packet);
    CHECK_EQ(other.error, "unsupported");
    CHECK_EQ(other.unsupported_type, type);
    CHECK(other.nals.empty());
  }

  // An unsupported packet is unrelated to an FU in progress, so it must not
  // clear it: it belongs to a different packetization mode and carries nothing
  // that could complete an FU.
  H265Depack running;
  CHECK(feed(running, kFuFirstFragment).error.empty());
  REQUIRE(running.hasPartialFu());
  const H265DepackOutput interleaved = feed(running, kPaciPacket);
  CHECK_EQ(interleaved.error, "unsupported");
  CHECK(running.hasPartialFu());

  // ...and the FU really is still the live one: the rest of its fragments
  // complete it into the same NAL as if the PACI had never arrived.
  CHECK(feed(running, kFuMiddleFragment).error.empty());
  const H265DepackOutput last = feed(running, kFuLastFragment);
  CHECK(last.error.empty());
  REQUIRE_EQ(last.nals.size(), 1u);
  H265_CHECK_OCTETS(last.nals[0], kReassembledIdr);
}

TEST_CASE("H265Depack with donl_present: an AP is rejected as unsupported:donl") {
  // Without DONL the same AP is an ordinary aggregation packet...
  H265Depack plain;
  const H265DepackOutput parsed = feed(plain, kApPayload);
  CHECK(parsed.error.empty());
  REQUIRE_EQ(parsed.nals.size(), 3u);

  // ...and with it the stream orders its NAL units with a decoding order number
  // that this class does not model, so the packet is rejected whole: nothing is
  // parsed out of it and nothing is guessed at.
  H265Depack with_donl(/*donl_present=*/true);
  const H265DepackOutput rejected = feed(with_donl, kApPayload);
  CHECK_EQ(rejected.error, "unsupported:donl");
  CHECK(rejected.nals.empty());
  CHECK_FALSE(rejected.corrupt);
  // The packet is also counted as the unsupported type it is, so a caller
  // reporting "packets that produced nothing" reports these (header decision 4).
  CHECK_EQ(rejected.unsupported_type, static_cast<uint32_t>(kTypeAp));

  // DONL lives in the AP payload header and nowhere else, so the same stream's
  // single NAL unit and FU packets de-packetize normally: the property makes
  // the AP unusable, not the stream (header decision 3).
  H265Depack donl_stream(/*donl_present=*/true);
  const H265DepackOutput single = feed(donl_stream, kIdrNalUnit);
  CHECK(single.error.empty());
  REQUIRE_EQ(single.nals.size(), 1u);
  CHECK(feed(donl_stream, kFuFirstFragment).error.empty());
  CHECK(feed(donl_stream, kFuMiddleFragment).error.empty());
  const H265DepackOutput fragmented = feed(donl_stream, kFuLastFragment);
  CHECK(fragmented.error.empty());
  REQUIRE_EQ(fragmented.nals.size(), 1u);
  H265_CHECK_OCTETS(fragmented.nals[0], kReassembledIdr);

  // A rejected AP is unrelated to an FU being assembled and must not disturb
  // it, exactly like an unsupported packet type (header decision 5).
  H265Depack running(/*donl_present=*/true);
  CHECK(feed(running, kFuFirstFragment).error.empty());
  REQUIRE(running.hasPartialFu());
  const H265DepackOutput interleaved = feed(running, kApPayload);
  CHECK_EQ(interleaved.error, "unsupported:donl");
  CHECK(running.hasPartialFu());
  CHECK(feed(running, kFuMiddleFragment).error.empty());
  const H265DepackOutput last = feed(running, kFuLastFragment);
  CHECK(last.error.empty());
  REQUIRE_EQ(last.nals.size(), 1u);
  H265_CHECK_OCTETS(last.nals[0], kReassembledIdr);
}
