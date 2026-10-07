// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// H.264 de-packetization (RFC 6184) -- RTP5-NAT-01.
// See H264Depack.h for the contract and for the decisions the task card left
// open; this file is the state machine itself.

#include "layanalyzer/rtp/depack/H264Depack.h"

namespace layanalyzer::rtp {
namespace {

// RFC 6184 section 5.4's packetization modes, as the NAL unit type that
// identifies each one. Types 1-23 are the NAL unit types themselves, so the
// single-NAL case is a range rather than one value.
constexpr uint8_t kSingleNalMaxType = 23;
constexpr uint8_t kStapAType = 24;
constexpr uint8_t kFuAType = 28;

// Every failure path returns through one of these two, so "error non-empty
// implies the rest is empty and false" holds by construction and cannot drift.
// The unsupported case needs its own builder only because it reports *which*
// type it could not reassemble. The FU gap path in onPacket is the one place
// that deliberately does not go through here, because there the error reports
// the gap while the packet itself is still usable.
H264DepackOutput fail(const char *message) {
  H264DepackOutput out;
  out.error = message;
  return out;
}

H264DepackOutput fail_unsupported(uint8_t nal_type) {
  H264DepackOutput out;
  out.unsupported_type = nal_type;
  out.error = "unsupported";
  return out;
}

// Rule 4 (STAP-A). payload[0] is the aggregation packet's own indicator; from
// payload[1] on it is a sequence of 16-bit big-endian lengths, each followed by
// that many octets of a complete NAL unit -- header included, so the bytes go
// up unchanged (RFC 6184 section 5.7.1: the aggregated NAL units keep their own
// headers and may carry any NRI, which is why nothing is inherited from the
// STAP-A octet).
H264DepackOutput depack_stap_a(const uint8_t *payload, size_t length) {
  H264DepackOutput out;
  size_t pos = 1;
  while (pos < length) {
    // The length field itself has to fit; a lone trailing octet is not a NAL
    // and cannot be guessed at.
    if (length - pos < 2) {
      return fail("badStap");
    }
    const size_t nal_length = (static_cast<size_t>(payload[pos]) << 8) |
                              static_cast<size_t>(payload[pos + 1]);
    pos += 2;
    if (nal_length == 0) {
      // Zero-length entries are skipped (card rule 4). A sender that pads a
      // STAP-A with them still gets the NAL units it really sent.
      continue;
    }
    if (nal_length > length - pos) {
      return fail("badStap");
    }
    out.nals.emplace_back(payload + pos, payload + pos + nal_length);
    pos += nal_length;
  }
  return out;
}

}  // namespace

H264DepackOutput H264Depack::onPacket(const uint8_t *payload, size_t length,
                                      bool sequence_gap) {
  // Rule 1. A zero-length payload carries neither a NAL unit nor a packet type,
  // so nothing beyond the error can be reported. A null pointer is folded into
  // the same answer: it cannot name a type either, and reading payload[0]
  // through it would be undefined.
  if (payload == nullptr || length == 0) {
    return fail("empty");
  }

  // Rule 2. In every mode this class handles the NAL unit type sits in the low
  // five bits of the payload's first octet (RFC 6184 section 5.3): it *is* the
  // NAL header for types 1-23, the FU indicator's Type field for FU-A, and the
  // STAP-A indicator's Type field (24) for an aggregation packet.
  const uint8_t nal_type = static_cast<uint8_t>(payload[0] & 0x1Fu);

  // Rule 3: a single NAL unit packet. The payload is the whole NAL, so there is
  // nothing to reassemble and a gap in the sequence numbers does not damage it
  // -- it is self-contained. The gap is still reported, because the access unit
  // this NAL belongs to may have lost other packets; NAT-03 decides whether that
  // makes the frame unusable.
  if (nal_type >= 1 && nal_type <= kSingleNalMaxType) {
    H264DepackOutput out;
    out.nals.emplace_back(payload, payload + length);
    out.corrupt = sequence_gap;
    return out;
  }

  if (nal_type == kStapAType) {
    return depack_stap_a(payload, length);
  }

  // Rule 5: FU-A.
  if (nal_type == kFuAType) {
    // Indicator + header + at least one data octet; see header note 5. Without
    // three octets there is no fragment to append even if the S/E bits say
    // otherwise.
    if (length < 3) {
      return fail("badFu");
    }
    const uint8_t fu_indicator = payload[0];
    const uint8_t fu_header = payload[1];
    const bool start = (fu_header & 0x80u) != 0;
    const bool end = (fu_header & 0x40u) != 0;
    const uint8_t fragment_type = static_cast<uint8_t>(fu_header & 0x1Fu);
    const uint8_t nri = static_cast<uint8_t>(fu_indicator & 0x60u);

    H264DepackOutput out;

    // Rule 5, gap bullet: a gap invalidates the FU being assembled -- the
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
      // A new FU replaces whatever was being assembled (card rule 5, first
      // bullet): the NAL header is rebuilt from the FU indicator's NRI and the
      // FU header's type -- see header note 1 for why F is not copied -- and
      // the fragment's data follows.
      fu_buffer_.clear();
      fu_buffer_.push_back(static_cast<uint8_t>(nri | fragment_type));
      fu_in_progress_ = true;
    } else if (!fu_in_progress_) {
      // A middle or end fragment with no FU to attach to: its start was lost or
      // never seen, and an end fragment alone cannot reconstruct a NAL.
      return fail("fuWithoutStart");
    }

    const size_t data_length = length - 2;
    // Checked before appending, so a runaway stream cannot drive this class
    // past the cap by one packet (header note 4). The card requires the state
    // to be dropped, not kept for a later fragment.
    if (fu_buffer_.size() + data_length > kMaxNalBytes) {
      fu_buffer_.clear();
      fu_in_progress_ = false;
      return fail("nalTooLarge");
    }
    fu_buffer_.insert(fu_buffer_.end(), payload + 2, payload + length);

    if (end) {
      // The E fragment ends the NAL: hand it over and go back to idle, ready
      // for the next FU (a single packet can only ever complete one NAL).
      out.nals.push_back(std::move(fu_buffer_));
      fu_buffer_.clear();  // moved-from, but left explicitly empty
      fu_in_progress_ = false;
    }
    return out;
  }

  // Rule 6: the packet types this class cannot reassemble -- STAP-B (25),
  // MTAP16 (26), MTAP24 (27), FU-B (29) and the two reserved values (30, 31),
  // plus type 0 (header note 3). They are counted and nothing is emitted, and
  // just as importantly the FU being assembled is left alone: this packet has
  // nothing to do with it, and RFC 6184 would only interleave a different
  // packetization mode on a stream that has already stopped sending FU-A.
  return fail_unsupported(nal_type);
}

void H264Depack::reset() {
  fu_buffer_.clear();
  fu_in_progress_ = false;
}

bool H264Depack::hasPartialFu() const { return fu_in_progress_; }

}  // namespace layanalyzer::rtp
