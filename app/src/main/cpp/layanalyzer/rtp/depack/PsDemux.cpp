// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// PS (program stream) de-multiplexing for GB28181 -- RTP5-NAT-06.
// See PsDemux.h for the contract and for the decisions the task card left open;
// this file is the demultiplexer itself.

#include "layanalyzer/rtp/depack/PsDemux.h"

namespace layanalyzer::rtp {
namespace {

// The ISO 13818-1 start codes this class acts on. Everything else in a PS packet
// is skipped through a length field (decision 3).
constexpr uint8_t kPackStartCode = 0xBA;
constexpr uint8_t kSystemHeaderStartCode = 0xBB;
constexpr uint8_t kProgramStreamMapStartCode = 0xBC;
constexpr uint8_t kProgramEndStartCode = 0xB9;

// The two stream ids that have no PES header of their own: the length field is
// followed immediately by the payload.
constexpr uint8_t kPaddingStreamId = 0xBE;
constexpr uint8_t kPrivateStream2Id = 0xBF;

// The fixed part of a pack_header after its four-octet start code: six octets of
// SCR and marker bits, three of program_mux_rate and marker bits, one of reserved
// bits and pack_stuffing_length (ISO 13818-1 section 2.5.3.4). 4 + 10 = 14.
constexpr size_t kPackHeaderBytes = 14;

// The fixed part of a system_header: the marker bit, rate_bound, audio_bound, the
// flags, video_bound, the restriction flag and the reserved bits.
constexpr size_t kSystemHeaderFixedBytes = 6;

constexpr size_t kNotFound = static_cast<size_t>(-1);

// An Annex-B start code: `00 00 01`. The four-octet `00 00 00 01` of a NAL unit
// boundary is this one preceded by a zero (decision 4), so one test covers both.
bool is_start_code(const uint8_t *bytes, size_t size, size_t pos) {
  return pos + 3 <= size && bytes[pos] == 0x00 && bytes[pos + 1] == 0x00 &&
         bytes[pos + 2] == 0x01;
}

// The offset of the next `00 00 01 BA` at or after `from`, or kNotFound. Used to
// resynchronise (decision 2) and to find a second pack header inside one buffer.
size_t find_pack_start_code(const uint8_t *bytes, size_t size, size_t from) {
  for (size_t pos = from; pos + 4 <= size; ++pos) {
    if (bytes[pos] == 0x00 && bytes[pos + 1] == 0x00 &&
        bytes[pos + 2] == 0x01 && bytes[pos + 3] == kPackStartCode) {
      return pos;
    }
  }
  return kNotFound;
}

// Every stream id at or above 0xBD carries an ISO 13818-1 length field at offset
// 4 and can therefore be skipped even when this class does not know it; below
// that are the pack/system/PSM start codes (handled) and the MPEG-1 video and
// slice start codes, which cannot appear in a PS packet that is still aligned
// (decision 3).
bool is_pes_like(uint8_t stream_id) { return stream_id >= 0xBD; }

size_t read_u16(const uint8_t *bytes, size_t pos) {
  return (static_cast<size_t>(bytes[pos]) << 8) |
         static_cast<size_t>(bytes[pos + 1]);
}

// A 33-bit PTS from its five-octet field: '0010' or '0011', then the three
// groups of timestamp bits separated by marker bits (ISO 13818-1 table 2-21).
uint64_t read_pts(const uint8_t *bytes) {
  return ((static_cast<uint64_t>(bytes[0] >> 1) & 0x07u) << 30) |
         (static_cast<uint64_t>(bytes[1]) << 22) |
         ((static_cast<uint64_t>(bytes[2] >> 1) & 0x7Fu) << 15) |
         (static_cast<uint64_t>(bytes[3]) << 7) |
         (static_cast<uint64_t>(bytes[4] >> 1) & 0x7Fu);
}

// The stream_type table this class recognises (decision 8). 0x1B and 0x24 are
// ISO 13818-1's H.264 and H.265; 0x90 is the private value GB/T 28181 uses for
// G.711A. Everything else is `Other`: named by a PSM, and skipped and counted
// when its PES packets arrive.
PsStreamKind classify_stream_type(uint8_t stream_type) {
  switch (stream_type) {
    case 0x1B:
      return PsStreamKind::H264;
    case 0x24:
      return PsStreamKind::H265;
    case 0x90:
      return PsStreamKind::G711A;
    default:
      return PsStreamKind::Other;
  }
}

}  // namespace

PsDemuxOutput PsDemux::onPacket(const uint8_t *payload, size_t length,
                                bool marker, uint64_t ext_ts,
                                uint32_t frame_number, bool sequence_gap) {
  released_.clear();
  call_error_.clear();
  PsDemuxOutput out;
  stats_.rtp_payloads++;

  if (length == 0) {
    // Nothing to reassemble. Reported like the depacketizers' "empty" and not
    // counted as damage: there is no PS packet to lose.
    out.error = "empty";
    return out;
  }

  // Decision 1: a timestamp change proves the sender moved on, so a PS packet
  // that is still open was never marked. It is parsed best-effort rather than
  // discarded, and flagged corrupt.
  if (ps_have_ts_ && ext_ts != ps_ext_ts_) {
    if (!ps_buffer_.empty()) {
      stats_.marker_missing++;
      mark_damage(false);
      parse_ps_packet(ps_buffer_.size());
      ps_buffer_.clear();
    }
    ps_have_ts_ = false;
  }

  if (!ps_have_ts_) {
    ps_have_ts_ = true;
    ps_ext_ts_ = ext_ts;
    ps_first_frame_ = frame_number;
  }

  // Decision 13: the cap is checked before the bytes are appended, so a runaway
  // stream cannot make the reassembly buffer allocate past it.
  if (ps_buffer_.size() + length > kMaxPsPacketBytes) {
    stats_.ps_packets_dropped++;
    ps_buffer_.clear();
    ps_have_ts_ = false;
    set_error("psPacketTooLarge");
    out.error = call_error_;
    out.access_units = std::move(released_);
    return out;
  }
  ps_buffer_.insert(ps_buffer_.end(), payload, payload + length);

  // Decision 11: the caller's RTP-level flag is damage like any other, charged to
  // the access unit that is open while this payload is being handled.
  if (sequence_gap) {
    mark_damage(true);
  }

  if (marker) {
    // Decision 1: the marker bit completes the PS packet.
    parse_ps_packet(ps_buffer_.size());
    ps_buffer_.clear();
    ps_have_ts_ = false;
  }

  out.error = call_error_;
  out.access_units = std::move(released_);
  return out;
}

PsDemuxOutput PsDemux::finish() {
  released_.clear();
  call_error_.clear();
  PsDemuxOutput out;
  // Decision 14: one-shot. The second call has nothing left to hand over.
  if (finished_) {
    return out;
  }
  finished_ = true;

  if (!ps_buffer_.empty()) {
    stats_.truncated_ps_packets++;
    mark_damage(false);
    parse_ps_packet(ps_buffer_.size());
    ps_buffer_.clear();
  }
  ps_have_ts_ = false;

  // The end of the stream terminates the last NAL unit (decision 4) and closes
  // the access unit that was still open (decision 5).
  flush_pending_nal();
  close_access_unit();

  out.error = call_error_;
  out.access_units = std::move(released_);
  return out;
}

PsStreamKind PsDemux::video_kind() const {
  // Decision 8: `std::map` iterates in key order, so the lowest elementary
  // stream id wins and the answer does not depend on the PSM's entry order.
  for (const auto &entry : es_map_) {
    if (entry.second == PsStreamKind::H264 || entry.second == PsStreamKind::H265) {
      return entry.second;
    }
  }
  return PsStreamKind::Unknown;
}

PsStreamKind PsDemux::classify_es_id(uint8_t es_id) const {
  const auto it = es_map_.find(es_id);
  if (it != es_map_.end()) {
    return it->second;
  }
  // Decision 8: an id no PSM named (or a PES that arrived before the first PSM)
  // keeps ISO 13818-1's reserved range.
  return PsStreamKind::Unknown;
}

void PsDemux::parse_ps_packet(size_t size) {
  const uint8_t *b = ps_buffer_.data();
  parsing_frame_ = ps_first_frame_;
  stats_.ps_packets++;

  size_t pos = 0;
  const bool starts_with_pack_header =
      size >= 4 && is_start_code(b, size, 0) && b[3] == kPackStartCode;
  if (!starts_with_pack_header) {
    // Decision 2: resynchronise on the next pack header.
    const size_t found = find_pack_start_code(b, size, 0);
    if (found == kNotFound) {
      stats_.ps_packets_dropped++;
      set_error("noPackStart");
      return;
    }
    stats_.resyncs++;
    mark_damage(false);
    pos = found;
  }

  // The pack header: 14 octets, then the stuffing its last three bits declare.
  if (size - pos < kPackHeaderBytes) {
    stats_.ps_packets_dropped++;
    stats_.parse_errors++;
    set_error("badPackHeader");
    return;
  }
  const size_t stuffing = static_cast<size_t>(b[pos + 13] & 0x07u);
  pos += kPackHeaderBytes;
  if (pos + stuffing > size) {
    stats_.ps_packets_dropped++;
    stats_.parse_errors++;
    set_error("badPackHeader");
    return;
  }
  pos += stuffing;

  while (pos + 4 <= size) {
    if (!is_start_code(b, size, pos)) {
      // The structure was lost inside the packet. Decision 2 again, but from
      // here: the only thing to align on is another pack header.
      const size_t found = find_pack_start_code(b, size, pos + 1);
      if (found == kNotFound) {
        // Everything from here on is unusable and cannot be skipped: the bytes
        // already parsed are kept (they came from complete structures).
        stats_.unknown_start_codes++;
        set_error("unknownStartCode");
        return;
      }
      stats_.resyncs++;
      mark_damage(false);
      pos = found;
      continue;
    }

    const uint8_t code = b[pos + 3];

    if (code == kPackStartCode) {
      // A second pack header inside one buffer: skip it and its stuffing. This
      // is where the resynchronisation above lands.
      if (size - pos < kPackHeaderBytes) {
        stats_.parse_errors++;
        set_error("badPackHeader");
        return;
      }
      const size_t more = static_cast<size_t>(b[pos + 13] & 0x07u);
      if (pos + kPackHeaderBytes + more > size) {
        stats_.parse_errors++;
        set_error("badPackHeader");
        return;
      }
      pos += kPackHeaderBytes + more;
      continue;
    }

    if (code == kSystemHeaderStartCode) {
      if (pos + 6 > size) {
        stats_.parse_errors++;
        set_error("badSystemHeader");
        return;
      }
      const size_t header_length = read_u16(b, pos + 4);
      // ISO 13818-1 section 2.5.3.5: header_length counts everything after it,
      // and the fixed part alone is six octets. The P-STD buffer loop that
      // follows is not consumed by anything in this pipeline, so the length is
      // the only field that has to be right -- and it is what makes the skip
      // correct.
      if (header_length < kSystemHeaderFixedBytes ||
          pos + 6 + header_length > size) {
        stats_.parse_errors++;
        set_error("badSystemHeader");
        return;
      }
      stats_.system_headers++;
      pos += 6 + header_length;
      continue;
    }

    if (code == kProgramStreamMapStartCode) {
      if (pos + 6 > size) {
        stats_.parse_errors++;
        set_error("badPsm");
        return;
      }
      const size_t map_length = read_u16(b, pos + 4);
      // program_stream_map_length covers everything after it up to and including
      // the CRC_32.
      if (map_length < 8 || pos + 6 + map_length > size) {
        stats_.parse_errors++;
        set_error("badPsm");
        return;
      }
      const size_t map_end = pos + 6 + map_length;
      if (pos + 10 > map_end) {
        stats_.parse_errors++;
        set_error("badPsm");
        return;
      }
      const uint8_t current_next = static_cast<uint8_t>((b[pos + 6] >> 7) & 0x01u);
      const size_t program_info_length = read_u16(b, pos + 8);
      size_t cursor = pos + 10 + program_info_length;
      if (cursor + 2 > map_end) {
        stats_.parse_errors++;
        set_error("badPsm");
        return;
      }
      const size_t es_map_length = read_u16(b, cursor);
      cursor += 2;
      if (cursor + es_map_length > map_end) {
        stats_.parse_errors++;
        set_error("badPsm");
        return;
      }

      // The map is built beside the live one so that a malformed PSM cannot
      // leave half of itself in force.
      std::map<uint8_t, PsStreamKind> map;
      const size_t loop_end = cursor + es_map_length;
      size_t entry = cursor;
      while (entry + 4 <= loop_end) {
        const uint8_t stream_type = b[entry];
        const uint8_t es_id = b[entry + 1];
        const size_t info_length = read_u16(b, entry + 2);
        if (entry + 4 + info_length > loop_end) {
          stats_.parse_errors++;
          set_error("badPsm");
          return;
        }
        map[es_id] = classify_stream_type(stream_type);
        entry += 4 + info_length;
      }
      if (entry != loop_end) {
        // The elementary stream loop does not exactly fill the length that
        // declared it, so the map cannot be trusted entry for entry.
        stats_.parse_errors++;
        set_error("badPsm");
        return;
      }

      if (current_next == 0) {
        // Decision 17: a map that is not in effect yet.
        stats_.psm_ignored++;
      } else {
        es_map_ = map;  // decision 17: an applied PSM replaces the map
        stats_.psm_count++;
      }
      pos = map_end;
      continue;
    }

    if (code == kProgramEndStartCode) {
      // The PS packet is complete. Nothing to skip and nothing to report.
      return;
    }

    if (is_pes_like(code)) {
      PesInfo info;
      if (!parse_pes(pos, size, &info)) {
        return;
      }
      const PsStreamKind kind = classify_es_id(code);
      if (kind == PsStreamKind::H264 || kind == PsStreamKind::H265) {
        stats_.pes_video++;
        feed_video_es(b + info.payload_begin, info.pes_end - info.payload_begin,
                      info.pts, info.has_pts, kind);
      } else if (kind == PsStreamKind::G711A) {
        // Decision 9: audio is dropped, counted, never exposed.
        stats_.pes_audio++;
      } else if (kind == PsStreamKind::Other) {
        // Decision 10: named by a PSM but not a stream type this class knows.
        stats_.pes_unsupported++;
      } else if (code >= 0xE0 && code <= 0xEF) {
        // Decision 8: no PSM (yet) -- the reserved id range decides.
        stats_.pes_video++;
        feed_video_es(b + info.payload_begin, info.pes_end - info.payload_begin,
                      info.pts, info.has_pts, PsStreamKind::Unknown);
      } else if (code >= 0xC0 && code <= 0xDF) {
        stats_.pes_audio++;
      } else {
        stats_.other_pes++;
      }
      pos = info.pes_end;
      continue;
    }

    // Decision 3: below 0xBD there is no length to skip, so the rest of the
    // packet is abandoned -- what was parsed before this point is kept.
    stats_.unknown_start_codes++;
    set_error("unknownStartCode");
    return;
  }
}

bool PsDemux::parse_pes(size_t pos, size_t size, PesInfo *info) {
  const uint8_t *b = ps_buffer_.data();
  const uint8_t stream_id = b[pos + 3];
  const size_t pes_length = read_u16(b, pos + 4);
  // PES_packet_length == 0 is legal for video only and means "this PES packet
  // runs to the end of the PS packet".
  size_t pes_end = (pes_length == 0) ? size : pos + 6 + pes_length;
  if (pes_end > size) {
    // The declared length runs past the PS packet, so the payload is short. The
    // bytes that are here are still real data (decision 1's reasoning), so the
    // packet is used and flagged rather than dropped.
    stats_.parse_errors++;
    set_error("badPes");
    pes_end = size;
  }
  info->pes_end = pes_end;

  if (stream_id == kPaddingStreamId || stream_id == kPrivateStream2Id) {
    // No PES header: the payload follows the length field immediately.
    info->has_header = false;
    info->payload_begin = (pos + 6 <= pes_end) ? pos + 6 : pes_end;
    return true;
  }

  if (pos + 9 > pes_end) {
    stats_.parse_errors++;
    set_error("badPes");
    return false;
  }
  // `'10'` in the two top bits: without it the header is not where it claims to
  // be and nothing after this point can be trusted.
  if ((b[pos + 6] & 0xC0u) != 0x80u) {
    stats_.parse_errors++;
    set_error("badPes");
    return false;
  }
  const uint8_t flags2 = b[pos + 7];
  const size_t header_length = static_cast<size_t>(b[pos + 8]);
  if (pos + 9 + header_length > pes_end) {
    stats_.parse_errors++;
    set_error("badPes");
    return false;
  }
  const uint8_t pts_dts_flags = static_cast<uint8_t>((flags2 >> 6) & 0x03u);
  if (pts_dts_flags != 0) {
    // Decision 16: 0b11 carries a DTS after the PTS; only the PTS is read.
    if (pos + 14 > pes_end) {
      stats_.parse_errors++;
      set_error("badPes");
      return false;
    }
    info->has_pts = true;
    info->pts = read_pts(b + pos + 9);
  }
  info->has_header = true;
  // Every other flag's data (ESCR, ES_rate, trick mode, additional copy info,
  // CRC, extension) lives inside PES_header_data_length and is skipped by it.
  info->payload_begin = pos + 9 + header_length;
  return true;
}

void PsDemux::feed_video_es(const uint8_t *es, size_t length, uint64_t pts,
                            bool has_pts, PsStreamKind kind) {
  // Decision 7: a PES packet without a PTS hands on the last one, and says so
  // through `has_pts` rather than by inventing a time.
  if (has_pts) {
    last_pts_ = pts;
  }
  const uint64_t resolved_pts = has_pts ? pts : last_pts_;

  if (!candidate_set_) {
    // The stream's first bytes were not a start code (a capture that began
    // mid-NAL): the unit that opens on them belongs to this PES packet.
    candidate_pts_ = resolved_pts;
    candidate_has_pts_ = has_pts;
    candidate_frame_ = parsing_frame_;
    candidate_kind_ = kind;
    candidate_set_ = true;
  }

  size_t cursor = 0;
  size_t pos = 0;
  while (pos + 3 <= length) {
    if (is_start_code(es, length, pos)) {
      if (pos > cursor) {
        append_pending(es + cursor, pos - cursor);
      }
      cursor = pos + 3;
      pos = cursor;
      // The start code terminated the NAL unit that was being scanned, so if a
      // PES boundary is waiting on it, the access unit ends here (decision 5).
      flush_pending_nal();
      if (close_pending_) {
        close_access_unit();
        close_pending_ = false;
      }
      // The NAL unit that begins here belongs to this PES packet (decision 7).
      candidate_pts_ = resolved_pts;
      candidate_has_pts_ = has_pts;
      candidate_frame_ = parsing_frame_;
      candidate_kind_ = kind;
      candidate_set_ = true;
    } else {
      ++pos;
    }
  }
  if (length > cursor) {
    append_pending(es + cursor, length - cursor);
  }

  // Decision 5: the next start code is what closes this access unit.
  close_pending_ = true;
}

void PsDemux::append_pending(const uint8_t *bytes, size_t length) {
  if (discarding_nal_) {
    return;
  }
  // Decision 13: checked before appending, so a runaway NAL unit cannot make
  // this buffer allocate past the cap.
  if (pending_.size() + length > kMaxNalBytes) {
    pending_.clear();
    discarding_nal_ = true;
    stats_.nal_too_large++;
    set_error("nalTooLarge");
    return;
  }
  pending_.insert(pending_.end(), bytes, bytes + length);
}

void PsDemux::flush_pending_nal() {
  if (discarding_nal_) {
    // The bytes of this NAL unit were dropped at the cap; everything up to the
    // start code that got here is skipped with them (decision 13).
    discarding_nal_ = false;
    pending_.clear();
    return;
  }
  size_t keep = pending_.size();
  // Decision 4: trailing zero octets belong to the start code that follows them
  // (Annex B's trailing_zero_8bits), not to the NAL unit.
  while (keep > 0 && pending_[keep - 1] == 0x00) {
    --keep;
  }
  if (keep > 0) {
    if (!au_open_) {
      open_access_unit();
    }
    au_nals_.push_back(std::vector<uint8_t>(pending_.begin(),
                                            pending_.begin() +
                                                static_cast<std::ptrdiff_t>(keep)));
  }
  pending_.clear();
}

void PsDemux::open_access_unit() {
  au_open_ = true;
  au_first_frame_ = candidate_frame_;
  au_pts_ = candidate_pts_;
  au_has_pts_ = candidate_has_pts_;
  au_kind_ = candidate_kind_;
  // Decision 11: damage that arrived while no unit was open belongs to this one.
  au_corrupt_ = damage_for_next_au_;
  au_gap_ = gap_for_next_au_;
  damage_for_next_au_ = false;
  gap_for_next_au_ = false;
}

void PsDemux::close_access_unit() {
  if (au_open_ && !au_nals_.empty()) {
    // Decision 5: an access unit with no NAL units is not an access unit
    // (NAT-03's decision 12 makes the same call on its side).
    PsAccessUnit unit;
    unit.nals = std::move(au_nals_);
    unit.first_frame = au_first_frame_;
    unit.pts = au_pts_;
    unit.has_pts = au_has_pts_;
    unit.corrupt = au_corrupt_;
    unit.sequence_gap = au_gap_;
    unit.kind = au_kind_;
    released_.push_back(std::move(unit));
    stats_.access_units++;
  }
  au_nals_.clear();
  au_open_ = false;
  au_corrupt_ = false;
  au_gap_ = false;
}

void PsDemux::mark_damage(bool gap) {
  // Decision 11: charge the damage to the unit that is open, or to the next one
  // that opens. Forwarded to NAT-03 as it stands; both flags matter there.
  if (au_open_) {
    au_corrupt_ = true;
    if (gap) {
      au_gap_ = true;
    }
  } else {
    damage_for_next_au_ = true;
    if (gap) {
      gap_for_next_au_ = true;
    }
  }
}

void PsDemux::set_error(const std::string &error) {
  // Decision 12: the first error of a call wins, and every one of them is damage
  // to whatever access unit is being collected.
  if (call_error_.empty()) {
    call_error_ = error;
  }
  mark_damage(false);
}

}  // namespace layanalyzer::rtp
