// AMR / AMR-WB de-packetization (RFC 4867) -- RTP4-NAT-04.
// See AmrDepack.h for the contract; this file is the format handling itself.

#include "layanalyzer/rtp/depack/AmrDepack.h"

namespace layanalyzer::rtp {
namespace {

// Frame sizes in bits for the active band, indexed by the ToC's FT field
// (RFC 4867 tables 1a and 1b). ceil(bits / 8) is the frame's data length in
// storage format.
//
// AMR-NB
//   FT 0-7   95 / 103 / 118 / 134 / 148 / 159 / 204 / 244 bits
//   FT 8     SID, 39 bits
//   FT 9-13  RFC 4867 table 1a marks these "reserved for future use". The task
//            card deliberately folds them into the SID range (39 bits), and
//            that is what is implemented here: no real AMR-NB stream carries
//            them, and treating them as SID keeps a length-legal packet
//            decodable as comfort noise instead of failing the whole payload.
//   FT 14    speech lost. Carries no data at all (RFC 4867 section 4.4.1), so
//            this entry is 0 -- the card says so explicitly, and that explicit
//            statement beats the "8-14 = SID 39 bits" shorthand in its format
//            bullet. The card's host test 6 pins the behaviour.
//   FT 15    NO_DATA, also without data.
//
// AMR-WB
//   FT 0-8   132 / 177 / 253 / 285 / 317 / 365 / 397 / 461 / 477 bits
//   FT 9-14  SID, 40 bits. AMR-WB has no speech-lost FT (the card's WB table
//            says so), so FT 14 is comfort noise here, not a lost frame.
//   FT 15    NO_DATA.
constexpr uint16_t kFrameBitsNb[16] = {
    95, 103, 118, 134, 148, 159, 204, 244,  // FT 0-7
    39, 39, 39, 39, 39, 39,                 // FT 8-13, see above
    0, 0,                                   // FT 14 speech lost, FT 15 NO_DATA
};

constexpr uint16_t kFrameBitsWb[16] = {
    132, 177, 253, 285, 317, 365, 397, 461, 477,  // FT 0-8
    40, 40, 40, 40, 40, 40,                       // FT 9-14 SID
    0,                                            // FT 15 NO_DATA
};

constexpr uint8_t kFtSpeechLost = 14;
constexpr uint8_t kFtNoData = 15;

// The bandwidth-efficient ToC is F + FT + Q, i.e. 6 bits. The first one starts
// right after the 4-bit CMR; every later one starts right after the previous
// frame's data bits.
constexpr unsigned kTocBits = 6;
constexpr size_t kFirstTocBit = 4;

// A bandwidth-efficient payload is a bit string, so its last octet may be
// padded (RFC 4867 section 4.3). At most 7 bits can be padding; more than that
// means the parse stopped at a bit position the sender never wrote a frame
// boundary at, i.e. the frames were mis-read and the rest of the payload is
// unaccounted for. That check is what keeps an octet-aligned packet from also
// validating as bandwidth-efficient -- see depack_be().
constexpr size_t kMaxTrailingBits = 7;

struct FrameInfo {
  uint16_t bits = 0;        // data bits carried by this frame
  bool is_sid = false;      // FT is a SID code point of the active band
  bool speech_lost = false; // FT 14, AMR-NB only
  bool no_data = false;     // FT 15
};

FrameInfo lookup(uint8_t ft, bool is_wb) {
  FrameInfo info;
  info.bits = is_wb ? kFrameBitsWb[ft] : kFrameBitsNb[ft];
  info.no_data = (ft == kFtNoData);
  // AMR-WB has no speech-lost FT: its FT 14 is a SID frame of the WB band.
  info.speech_lost = (!is_wb && ft == kFtSpeechLost);
  info.is_sid = is_wb ? (ft >= 9 && ft <= 14) : (ft >= 8 && ft <= 13);
  return info;
}

// Reads `count` (<= 8) bits starting at bit position `bit_pos`, where bit 0 is
// the MSB of payload[0] -- the bit numbering RFC 4867 section 4.3 uses. Returns
// false when the requested bits run past the end of the buffer, so every caller
// can turn that into an error instead of a partial frame.
//
// One helper rather than shifts scattered over the parser: the bandwidth-
// efficient layout is the part of this file that is easiest to get wrong, and
// having exactly one implementation of "which bit is at position N" means there
// is exactly one place to check.
bool read_bits(const uint8_t *payload, size_t length, size_t bit_pos,
               unsigned count, uint8_t &out) {
  if (count == 0 || count > 8) {
    return false;
  }
  if (bit_pos + count > length * 8) {
    return false;
  }
  uint32_t value = 0;
  for (unsigned i = 0; i < count; ++i) {
    const size_t bit = bit_pos + i;
    const uint8_t octet = payload[bit >> 3];
    const unsigned shift = 7u - static_cast<unsigned>(bit & 7u);
    value = (value << 1) | ((octet >> shift) & 0x01u);
  }
  out = static_cast<uint8_t>(value);
  return true;
}

// Every failure path returns through here, so "error non-empty implies
// everything else is empty/false" holds by construction and cannot drift.
AmrDepackResult fail(const char *message) {
  AmrDepackResult result;
  result.error = message;
  return result;
}

// Builds the storage-format frame for one ToC + data field. Shared by both
// parse modes so their output cannot diverge.
//
// `data` has `ceil(bits/8)` octets taken from the payload; when `bits` is not a
// multiple of 8 the spare low bits of the last octet are cleared, which is what
// the storage format specifies. A conforming sender already zeroes them in
// octet-aligned mode (RFC 4867 section 4.4.2), and clearing them here makes an
// octet-aligned and a bandwidth-efficient packet carrying the same frame
// produce byte-identical storage, which is what NAT-06 and the .amr export
// compare against.
AmrFrame make_frame(uint8_t toc, const FrameInfo &info,
                    std::vector<uint8_t> data) {
  AmrFrame frame;
  frame.toc = toc;
  frame.data = std::move(data);
  const uint16_t spare = static_cast<uint16_t>(info.bits % 8);
  if (spare != 0 && !frame.data.empty()) {
    frame.data.back() &= static_cast<uint8_t>(0xFFu << (8 - spare));
  }
  frame.is_sid = info.is_sid;
  // Always false, and set explicitly so it stays that way: an FT 15 frame is
  // never turned into an AmrFrame (the card's test 5 pins `frames` empty for
  // such a packet), so NO_DATA has to be reported at result level -- one flag
  // for the packet -- and a frame that does exist is never a NO_DATA frame.
  frame.no_data = false;
  return frame;
}

// RFC 4867 section 4.4: payload[0] is CMR in the high nibble and four reserved
// bits in the low nibble; then each frame is a whole ToC octet followed by
// ceil(bits/8) data octets. Because every field ends on an octet boundary this
// parse is byte arithmetic -- there is no bit cursor here on purpose.
//
// The reserved nibble is read (it occupies payload[0] either way) but never
// validated: the card says not to fail on it, and a sender that sets it is
// still perfectly parseable.
AmrDepackResult depack_oa(const uint8_t *payload, size_t length, bool is_wb) {
  AmrDepackResult result;
  if (length < 2) {
    // One octet is CMR alone: RFC 4867 always has at least one ToC, so there is
    // no frame to hand back.
    return fail("truncated: missing ToC");
  }

  size_t pos = 1;  // payload[0] is the CMR octet
  while (true) {
    if (pos >= length) {
      return fail("truncated: missing ToC");
    }
    const uint8_t raw = payload[pos++];
    // The transmitted ToC is F(1) FT(4) Q(1) P(2); the storage ToC is
    // F << 7 | FT << 3 | Q << 2 with the two padding bits zero, i.e. raw with
    // its low two bits cleared.
    const uint8_t toc = static_cast<uint8_t>(raw & 0xFCu);
    const uint8_t f = static_cast<uint8_t>(raw & 0x80u);
    const uint8_t ft = static_cast<uint8_t>((raw >> 3) & 0x0Fu);
    const FrameInfo info = lookup(ft, is_wb);

    if (info.no_data) {
      // FT 15 carries no data field, so no octets are consumed and no AmrFrame
      // is produced; the packet-level flag is what the caller needs (the frame
      // still has to move the stream clock forward).
      result.no_data = true;
    } else if (info.speech_lost) {
      // FT 14 likewise has no data field of its own (RFC 4867 section 4.4.1);
      // the caller fills the gap from the previous good frame.
      result.speech_lost = true;
    } else {
      const size_t octets = (info.bits + 7u) / 8u;
      if (pos + octets > length) {
        return fail("truncated: frame data");
      }
      result.frames.push_back(make_frame(
          toc, info, std::vector<uint8_t>(payload + pos, payload + pos + octets)));
      pos += octets;
    }

    if (f == 0) {
      break;
    }
  }

  if (pos != length) {
    // F = 0 said "last frame", yet octets remain. In octet-aligned mode the
    // frames tile the payload exactly, so anything left over is not a frame:
    // guessing would hand MediaCodec bytes the sender never wrote as frames.
    return fail("invalid: trailing data");
  }
  return result;
}

// RFC 4867 section 4.3. With bit positions counted from the MSB of payload[0]:
//
//   bits 0-3   CMR
//   bit  4     F                       (the card's payload[0] & 0x08)
//   bits 5-8   FT
//   bit  9     Q
//   bit  10..  frame data, then the next frame's 6-bit ToC immediately after it
//
// That is the same thing as the card's integer form
//   toc = ((payload[0] & 0x0F) << 4) | (payload[1] >> 4)
// but expressed as one 6-bit read at bit offset 4, so the two extractions
// (header and data) go through the same read_bits() helper.
AmrDepackResult depack_be(const uint8_t *payload, size_t length, bool is_wb) {
  // Two octets is the shortest payload that can hold CMR + a whole ToC.
  if (length < 2) {
    return fail("truncated: missing ToC");
  }

  AmrDepackResult result;
  const size_t total_bits = length * 8;
  size_t bit_pos = kFirstTocBit;

  while (true) {
    uint8_t toc6 = 0;
    if (!read_bits(payload, length, bit_pos, kTocBits, toc6)) {
      return fail("truncated: missing ToC");
    }
    bit_pos += kTocBits;

    const uint8_t f = static_cast<uint8_t>((toc6 >> 5) & 0x01u);
    // The mask is not optional. Without it the F bit (bit 4 of the 6-bit ToC)
    // stays in the result and FT is read as five bits, so every frame with
    // F = 1 -- i.e. every frame except the last one of a multi-frame packet --
    // gets a bogus FT. The card's snippet calls this out for its 8-bit `toc`
    // form; it applies identically here.
    const uint8_t ft = static_cast<uint8_t>((toc6 >> 1) & 0x0Fu);
    const uint8_t q = static_cast<uint8_t>(toc6 & 0x01u);
    const uint8_t toc =
        static_cast<uint8_t>((f << 7) | (ft << 3) | (q << 2));
    const FrameInfo info = lookup(ft, is_wb);

    if (info.no_data) {
      result.no_data = true;  // no data field, so no AmrFrame -- as in depack_oa()
    } else if (info.speech_lost) {
      result.speech_lost = true;
    } else {
      if (bit_pos + info.bits > total_bits) {
        return fail("truncated: frame data");
      }
      std::vector<uint8_t> data((info.bits + 7u) / 8u, 0x00);
      for (uint16_t i = 0; i < info.bits; ++i) {
        uint8_t bit = 0;
        if (!read_bits(payload, length, bit_pos + i, 1, bit)) {
          return fail("truncated: frame data");
        }
        if (bit != 0) {
          // MSB first inside each octet, exactly how make_frame() reads it back.
          data[i >> 3] |= static_cast<uint8_t>(0x80u >> (i & 7u));
        }
      }
      result.frames.push_back(make_frame(toc, info, std::move(data)));
      bit_pos += info.bits;
    }

    if (f == 0) {
      break;
    }
  }

  // F = 0 ends the frame list, so what is left over is the payload's final
  // octet padding at most. A whole octet or more of leftovers means the frames
  // were read at the wrong offsets; accepting it would emit frames that are not
  // the sender's, and -- just as importantly -- would make every octet-aligned
  // packet look like a valid bandwidth-efficient one, leaving the mode detector
  // unable to ever answer OctetAligned.
  if (total_bits - bit_pos > kMaxTrailingBits) {
    return fail("invalid: trailing data");
  }
  return result;
}

}  // namespace

AmrDepackResult depack_amr(const uint8_t *payload, size_t length, bool is_wb,
                           bool octet_aligned, bool crc, bool interleaved) {
  if (crc || interleaved) {
    // CRC and interleaving are stream properties from the SDP fmtp (crc=1,
    // robust-sorting=1); a payload cannot reveal them. Both change what the
    // bits mean (RFC 4867 section 4.4.3 appends a CRC and interleaves the
    // frames), so this is fail-closed: the caller marks the stream unsupported
    // rather than having the frames silently mis-parsed. The card fixes this
    // exact string for both flags.
    return fail("unsupported: crc");
  }
  if (payload == nullptr || length == 0) {
    return fail("invalid: empty payload");
  }
  return octet_aligned ? depack_oa(payload, length, is_wb)
                       : depack_be(payload, length, is_wb);
}

AmrDepackResult depack_amr(const uint8_t *payload, size_t length, bool is_wb,
                           bool octet_aligned) {
  return depack_amr(payload, length, is_wb, octet_aligned, false, false);
}

void AmrModeDetector::observe(const uint8_t *payload, size_t length, bool is_wb) {
  if (observations_ >= kMaxObservations) {
    return;  // the verdict is already fixed; see the header
  }
  ++observations_;
  if (depack_amr(payload, length, is_wb, true).error.empty()) {
    ++octet_aligned_valid_;
  }
  if (depack_amr(payload, length, is_wb, false).error.empty()) {
    ++bandwidth_efficient_valid_;
  }
}

AmrMode AmrModeDetector::result() const {
  // Strictly greater, so a tie (and an empty detector's 0:0) resolves to
  // bandwidth-efficient, which is the rule the card mandates.
  return octet_aligned_valid_ > bandwidth_efficient_valid_
             ? AmrMode::OctetAligned
             : AmrMode::BandwidthEfficient;
}

}  // namespace layanalyzer::rtp
