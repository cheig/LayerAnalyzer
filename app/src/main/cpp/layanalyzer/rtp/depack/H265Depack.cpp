// H.265 de-packetization (RFC 7798) -- RTP5-NAT-02.
// See H265Depack.h for the contract and for the decisions the task card left
// open; this file is the state machine itself.

#include "layanalyzer/rtp/depack/H265Depack.h"

namespace layanalyzer::rtp {
namespace {

// RFC 7798 section 4.4's packetization modes, as the NAL unit type that
// identifies each one. Types 0-47 are the NAL unit types themselves, so the
// single-NAL case is a range rather than one value, and it starts at zero:
// HEVC's first NAL unit type (TRAIL_N) is 0, unlike H.264's.
constexpr uint8_t kSingleNalMaxType = 47;
constexpr uint8_t kApType = 48;
constexpr uint8_t kFuType = 49;

// Every failure path returns through one of these three, so "error non-empty
// implies the rest is empty and false" holds by construction and cannot drift.
// The unsupported case needs its own builder only because it reports *which*
// type it could not reassemble; the DONL case needs its own because it reports
// both the type it dropped (48) and the reason it could not use it. The FU gap
// path in onPacket is the one place that deliberately does not go through here,
// because there the error reports the gap while the packet itself is still
// usable.
H265DepackOutput fail(const char *message) {
  H265DepackOutput out;
  out.error = message;
  return out;
}

H265DepackOutput fail_unsupported(uint8_t nal_type) {
  H265DepackOutput out;
  out.unsupported_type = nal_type;
  out.error = "unsupported";
  return out;
}

// A stream whose sprop-max-don-diff is positive orders its NAL units with a
// decoding order number, which the AP payload header carries in a field this
// class does not model -- see header decision 4 for why the type is counted
// alongside the error.
H265DepackOutput fail_donl() {
  H265DepackOutput out;
  out.unsupported_type = kApType;
  out.error = "unsupported:donl";
  return out;
}

// Rule 3 (AP). payload[0] is the AP's own indicator and payload[1] the second
// octet of its 2-octet payload header; from payload[2] on it is a sequence of
// 16-bit big-endian lengths, each followed by that many octets of a complete
// NAL unit -- header included, and H.265's header is two octets, so every
// aggregated NAL unit goes up with its own two header octets unchanged (the AP
// octet itself is an indicator, not a NAL header, so nothing is inherited from
// it). The DONL field is *not* handled here: a packet that would have carried
// one was rejected before this function was called (header decision 3), so the
// first length always starts at payload[2] and payload[1] never shifts it.
H265DepackOutput depack_ap(const uint8_t *payload, size_t length) {
  H265DepackOutput out;
  size_t pos = 2;
  while (pos < length) {
    // The length field itself has to fit; a lone trailing octet is not a NAL
    // and cannot be guessed at. (The loop condition above keeps pos <= length,
    // so the subtraction cannot wrap.)
    if (length - pos < 2) {
      return fail("badAp");
    }
    const size_t nal_length = (static_cast<size_t>(payload[pos]) << 8) |
                              static_cast<size_t>(payload[pos + 1]);
    pos += 2;
    if (nal_length == 0) {
      // Zero-length entries are skipped (card rule 3, the same rule as NAT-01's
      // STAP-A). A sender that pads an AP with them still gets the NAL units it
      // really sent.
      continue;
    }
    if (nal_length > length - pos) {
      return fail("badAp");
    }
    out.nals.emplace_back(payload + pos, payload + pos + nal_length);
    pos += nal_length;
  }
  return out;
}

}  // namespace

H265Depack::H265Depack(bool donl_present) : donl_present_(donl_present) {}

H265DepackOutput H265Depack::onPacket(const uint8_t *payload, size_t length,
                                      bool sequence_gap) {
  // A payload with no octets carries neither a NAL unit nor a packet type, so
  // nothing beyond the error can be reported; the rule and its string ("empty")
  // are H264Depack's, which the H.265 card keeps. A null pointer is folded into
  // the same answer: it cannot name a type either, and reading payload[0]
  // through it would be undefined.
  if (payload == nullptr || length == 0) {
    return fail("empty");
  }

  // Rule 1. In every mode this class handles the 6-bit NAL unit type sits in
  // bits 1-6 of the payload's first octet: it *is* the NAL header's type for a
  // single NAL unit packet, the AP PayloadHdr's type (48), the FU PayloadHdr's
  // type (49) or the PACI PayloadHdr's type (50). Bit 0 of that octet belongs
  // to nuh_layer_id and bit 7 to F, so the type is not the whole octet and
  // neither of those may be folded into it.
  const uint8_t nal_type = static_cast<uint8_t>((payload[0] >> 1) & 0x3Fu);

  // Rule 2: a single NAL unit packet, types 0-47. The payload is the whole NAL,
  // so there is nothing to reassemble and a gap in the sequence numbers does
  // not damage it -- it is self-contained. The gap is still reported, because
  // the access unit this NAL belongs to may have lost other packets; NAT-03
  // decides whether that makes the frame unusable.
  if (nal_type <= kSingleNalMaxType) {
    H265DepackOutput out;
    out.nals.emplace_back(payload, payload + length);
    out.corrupt = sequence_gap;
    return out;
  }

  if (nal_type == kApType) {
    // Header decision 3: the DONL check comes first and rejects the packet
    // whole -- there is no partial answer for an aggregation packet whose NAL
    // units are ordered by a number this class cannot honour.
    if (donl_present_) {
      return fail_donl();
    }
    return depack_ap(payload, length);
  }

  // Rule 4: FU.
  if (nal_type == kFuType) {
    // RFC 7798 section 4.4.3: an FU packet is
    //   [PayloadHdr: F | FuType(6) | nuh_layer_id bit0][FU header][data...]
    // -- **two** header octets, not three. The FU header carries S, E and
    // FuType; the NAL unit's own second header octet is the *first byte of the
    // data*, which is why `fu_buffer_` gets it back from the data below.
    //
    // This used to read the FU header from `payload[2]` and append from
    // `payload + 3`, as if the PayloadHdr were two octets. Every fragment then
    // lost its first data octet and mistook the second for the S/E/type byte,
    // so reassembly produced garbage: a real H.265 stream came out as
    // `depackErrors` on most packets, and the MP4 built from it had an `mdat`
    // running past the end of the file -- no `moov`, so no player could open
    // it. The tell was `depackErrors=70` next to `frames=64` in the JNI log.
    //
    // Two header octets plus at least one data octet is the floor; without
    // three there is nothing to append even if the S/E bits say otherwise.
    if (length < 3) {
      return fail("badFu");
    }
    const uint8_t fu_header = payload[1];
    const bool start = (fu_header & 0x80u) != 0;
    const bool end = (fu_header & 0x40u) != 0;
    const uint8_t fragment_type = static_cast<uint8_t>(fu_header & 0x3Fu);

    H265DepackOutput out;

    // Rule 4, gap bullet: a gap invalidates the FU being assembled -- the
    // fragment that would have completed it never arrived, and completing it
    // with what is in the buffer would hand the access unit a NAL with a hole
    // in the middle. The current packet is not treated as the FU's start unless
    // it says so itself with S = 1; a middle fragment of the *lost* NAL is not
    // a start fragment of anything.
    if (sequence_gap && fu_in_progress_) {
      fu_buffer_.clear();
      fu_in_progress_ = false;
      out.corrupt = true;
      out.error = "fuSequenceGap";
      if (!start) {
        return out;
      }
      // Falls through with `corrupt` already set: this packet carries S = 1, so
      // it is a legitimate new FU start and is reassembled normally.
    }

    if (start) {
      // A new FU replaces whatever was being assembled (card rule 4, first
      // bullet): the NAL unit header is rebuilt as the card's formula, two
      // octets at a time -- see header decision 2 for which bits of the FU
      // indicator survive. The second octet is `payload[2]`: the FU header
      // replaced only the type field of the NAL header, so the layer id's low
      // bits and the temporal id ride at the front of the fragment data.
      fu_buffer_.clear();
      fu_buffer_.push_back(
          static_cast<uint8_t>((payload[0] & 0x81u) | (fragment_type << 1)));
      fu_buffer_.push_back(payload[2]);
      fu_in_progress_ = true;
    } else if (!fu_in_progress_) {
      // A middle or end fragment with no FU to attach to: its start was lost or
      // never seen, and an end fragment alone cannot reconstruct a NAL.
      return fail("fuWithoutStart");
    }

    const size_t data_length = length - 2;
    // Checked before appending, so a runaway stream cannot drive this class
    // past the cap by one packet (header decision 9; the two rebuilt header
    // octets are already in the buffer and count with it). The card requires
    // the state to be dropped, not kept for a later fragment.
    if (fu_buffer_.size() + data_length > kMaxNalBytes) {
      fu_buffer_.clear();
      fu_in_progress_ = false;
      return fail("nalTooLarge");
    }
    // The start fragment already consumed `payload[2]` above -- it is the NAL
    // unit header's second octet -- so appending from `payload + 2` would
    // duplicate that octet; every later fragment appends from the same place.
    fu_buffer_.insert(
        fu_buffer_.end(), payload + (start ? 3 : 2), payload + length);

    if (end) {
      // The E fragment ends the NAL: hand it over and go back to idle, ready
      // for the next FU (a single packet can only ever complete one NAL).
      out.nals.push_back(std::move(fu_buffer_));
      fu_buffer_.clear();  // moved-from, but left explicitly empty
      fu_in_progress_ = false;
    }
    return out;
  }

  // Rule 5: PACI (50) and, through the same path, the reserved values 51-63
  // that no version of RFC 7798 assigns. They are counted and nothing is
  // emitted, and just as importantly the FU being assembled is left alone:
  // these packets have nothing to do with it, and RFC 7798 would only
  // interleave a different packetization mode on a stream that has already
  // stopped sending FU packets.
  return fail_unsupported(nal_type);
}

void H265Depack::reset() {
  fu_buffer_.clear();
  fu_in_progress_ = false;
}

bool H265Depack::hasPartialFu() const { return fu_in_progress_; }

}  // namespace layanalyzer::rtp
