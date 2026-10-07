// Projection: text helpers, protocol label resolution, packet-list summary
// projection and the RAW-IP/Ethernet protocol inference fallback.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/session/CaptureSession.h"
#include "layanalyzer/projection/FieldReader.h"

std::string lowercase_copy(const std::string &value) {
  std::string out = value;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

std::string uppercase_copy(const std::string &value) {
  std::string out = value;
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return out;
}

std::string trim_copy(const std::string &value) {
  const char *whitespace = " \t\r\n";
  size_t start = value.find_first_not_of(whitespace);
  if (start == std::string::npos) return "";
  size_t end = value.find_last_not_of(whitespace);
  return value.substr(start, end - start + 1);
}

bool contains_case_insensitive(const std::string &text,
                               const std::string &needle) {
  if (needle.empty()) return true;
  if (needle.size() > text.size()) return false;
  // Most packet columns are ASCII. Compare in place so a full lowercase copy
  // of both strings is not allocated for every field/search/statistics check.
  for (size_t offset = 0; offset + needle.size() <= text.size(); ++offset) {
    size_t index = 0;
    for (; index < needle.size(); ++index) {
      const unsigned char left =
          static_cast<unsigned char>(text[offset + index]);
      const unsigned char right =
          static_cast<unsigned char>(needle[index]);
      if (std::tolower(left) != std::tolower(right)) break;
    }
    if (index == needle.size()) return true;
  }
  return false;
}

static guint16 read_be16(const guint8 *data, guint offset, guint length) {
  if (!data || offset + 1 >= length) return 0;
  return static_cast<guint16>((data[offset] << 8) | data[offset + 1]);
}

static std::string protocol_from_ip_header(const guint8 *data, guint length,
                                           guint offset) {
  if (!data || offset >= length) return "";
  guint8 version = static_cast<guint8>(data[offset] >> 4);
  if (version == 4) {
    if (offset + 20 > length) return "IPv4";
    switch (data[offset + 9]) {
      case 1: return "ICMP";
      case 6: return "TCP";
      case 17: return "UDP";
      case 132: return "SCTP";
      default: return "IPv4";
    }
  }
  if (version == 6) {
    if (offset + 40 > length) return "IPv6";
    switch (data[offset + 6]) {
      case 6: return "TCP";
      case 17: return "UDP";
      case 58: return "ICMPv6";
      case 132: return "SCTP";
      default: return "IPv6";
    }
  }
  return "";
}

static std::string protocol_from_ethertype(guint16 ethertype, const guint8 *data,
                                           guint length, guint payloadOffset) {
  switch (ethertype) {
    case 0x0800: return protocol_from_ip_header(data, length, payloadOffset);
    case 0x86DD: return protocol_from_ip_header(data, length, payloadOffset);
    case 0x0806: return "ARP";
    case 0x8035: return "RARP";
    case 0x8100:
    case 0x88A8:
    case 0x9100:
      if (payloadOffset + 4 <= length) {
        guint16 innerType = read_be16(data, payloadOffset + 2, length);
        return protocol_from_ethertype(innerType, data, length, payloadOffset + 4);
      }
      return "VLAN";
    default:
      return "";
  }
}

std::string infer_protocol_from_packet(int encap, Buffer *buffer,
                                       guint capturedLen) {
  if (!buffer || !buffer->data || buffer->allocated < buffer->start) return "";
  guint available = static_cast<guint>(buffer->allocated - buffer->start);
  guint length = std::min(capturedLen, available);
  const guint8 *data = ws_buffer_start_ptr(buffer);
  if (!data || length == 0) return "";

  switch (encap) {
    case WTAP_ENCAP_ETHERNET:
      if (length >= 14) {
        return protocol_from_ethertype(read_be16(data, 12, length), data, length, 14);
      }
      break;
    case WTAP_ENCAP_SLL:
      if (length >= 16) {
        guint16 protocol = read_be16(data, 14, length);
        if (protocol == 0x0003 && length >= 30) {
          return protocol_from_ethertype(read_be16(data, 28, length), data, length, 30);
        }
        return protocol_from_ethertype(protocol, data, length, 16);
      }
      break;
    case WTAP_ENCAP_RAW_IP:
      return protocol_from_ip_header(data, length, 0);
    default:
      return protocol_from_ip_header(data, length, 0);
  }
  return "";
}

bool is_unusable_protocol_label(const std::string &value) {
  std::string lower = lowercase_copy(trim_copy(value));
  if (lower.size() >= 2 && lower.front() == '<' && lower.back() == '>') {
    lower = trim_copy(lower.substr(1, lower.size() - 2));
  }
  return lower.empty() || lower == "unknown" ||
         lower == "missing protocol name";
}

std::string protocol_display_name_from_token(const std::string &token) {
  std::string trimmed = trim_copy(token);
  if (trimmed.empty()) return "";

  int protoId = proto_get_id_by_filter_name(trimmed.c_str());
  if (protoId < 0) {
    protoId = proto_get_id_by_short_name(trimmed.c_str());
  }
  if (protoId >= 0) {
    const char *displayName = proto_get_protocol_name(protoId);
    if (displayName && displayName[0] != '\0') {
      return displayName;
    }
  }

  std::string lower = lowercase_copy(trimmed);
  if (lower == "tcp" || lower == "udp" || lower == "dns" || lower == "http" ||
      lower == "icmp" || lower == "arp" || lower == "tls" || lower == "ssl" ||
      lower == "ip" || lower == "ipv6") {
    std::transform(trimmed.begin(), trimmed.end(), trimmed.begin(), [](unsigned char c) {
      return static_cast<char>(std::toupper(c));
    });
  }
  return trimmed;
}

std::string resolve_protocol_label(packet_info *pinfo,
                                   const std::string &columnProtocol) {
  std::string column = trim_copy(columnProtocol);
  if (!is_unusable_protocol_label(column)) {
    return column;
  }

  if (pinfo && pinfo->current_proto && pinfo->current_proto[0] != '\0') {
    std::string fromCurrent = protocol_display_name_from_token(pinfo->current_proto);
    if (!is_unusable_protocol_label(fromCurrent)) {
      return fromCurrent;
    }
  }

  return "Unknown";
}

/** Project one already-dissected frame into the cacheable packet-list row. */
bool populate_packet_summary(WiresharkSession *session, int frameIdx,
                             DissectedFrame &frame, CachedPacketSummary &summary) {
  if (!session || !frame.edt || frameIdx < 0 ||
      frameIdx >= static_cast<int>(session->frame_offsets.size())) {
    return false;
  }

  summary = CachedPacketSummary();
  if (frame.rec.presence_flags & WTAP_HAS_TS) {
    summary.timestamp = frame.rec.ts.secs + frame.rec.ts.nsecs / 1e9;
  }
  summary.length = frame.rec.rec_header.packet_header.len;

  summary.source = safe_col_text(
      &frame.cinfo,
      session->name_resolution_enabled ? COL_RES_SRC : COL_UNRES_SRC);
  summary.destination = safe_col_text(
      &frame.cinfo,
      session->name_resolution_enabled ? COL_RES_DST : COL_UNRES_DST);
  summary.protocol = safe_col_text(&frame.cinfo, COL_PROTOCOL);
  summary.info = safe_col_text(&frame.cinfo, COL_INFO);

  packet_info *pinfo = &frame.edt->pi;
  summary.source_port = -1;
  summary.destination_port = -1;
  if (pinfo && (pinfo->ptype == PT_TCP || pinfo->ptype == PT_UDP ||
                pinfo->ptype == PT_SCTP || pinfo->ptype == PT_DCCP)) {
    if (pinfo->srcport <= 65535) {
      summary.source_port = static_cast<int>(pinfo->srcport);
    }
    if (pinfo->destport <= 65535) {
      summary.destination_port = static_cast<int>(pinfo->destport);
    }
  }

  char src_buf[256] = {0};
  char dst_buf[256] = {0};
  if (summary.source.empty() && pinfo->net_src.type != AT_NONE) {
    address_to_str_buf(&pinfo->net_src, src_buf, sizeof(src_buf));
    summary.source = src_buf;
  } else if (summary.source.empty() && pinfo->dl_src.type != AT_NONE) {
    address_to_str_buf(&pinfo->dl_src, src_buf, sizeof(src_buf));
    summary.source = src_buf;
  }

  if (summary.destination.empty() && pinfo->net_dst.type != AT_NONE) {
    address_to_str_buf(&pinfo->net_dst, dst_buf, sizeof(dst_buf));
    summary.destination = dst_buf;
  } else if (summary.destination.empty() && pinfo->dl_dst.type != AT_NONE) {
    address_to_str_buf(&pinfo->dl_dst, dst_buf, sizeof(dst_buf));
    summary.destination = dst_buf;
  }

  summary.protocol = resolve_protocol_label(pinfo, summary.protocol);
  if (is_unusable_protocol_label(summary.protocol)) {
    std::string inferredProto = infer_protocol_from_packet(
        frame.rec.rec_header.packet_header.pkt_encap,
        &frame.buf,
        frame.rec.rec_header.packet_header.caplen);
    if (!is_unusable_protocol_label(inferredProto)) {
      summary.protocol = inferredProto;
    }
  }
  summary.valid = true;
  return true;
}

bool build_packet_summary(WiresharkSession *session, int frameIdx,
                          CachedPacketSummary &summary) {
  DissectedFrame frame;
  if (!dissect_frame(session, frameIdx, FALSE, TRUE, nullptr, frame)) {
    return false;
  }
  return populate_packet_summary(session, frameIdx, frame, summary);
}

CachedPacketSummary get_or_build_packet_summary(WiresharkSession *session,
                                                int frameIdx) {
  CachedPacketSummary summary;
  if (load_cached_packet_summary(session, frameIdx, summary)) return summary;

  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    // Another page may have filled this entry while this call waited for the
    // Wireshark executor. Recheck to avoid duplicate seek + dissection.
    if (load_cached_packet_summary(session, frameIdx, summary, false)) return summary;
    if (!build_packet_summary(session, frameIdx, summary)) {
      summary = CachedPacketSummary();
      summary.valid = true;
      summary.protocol = "Unknown";
      summary.info = "Unable to dissect packet safely.";
    }
  }
  store_cached_packet_summary(session, frameIdx, summary);
  return summary;
}

void append_packet_summary_json(json &items, int frameIdx,
                                const CachedPacketSummary &summary) {
  items.push_back({
      {"frameNumber", frameIdx + 1},
      {"time", summary.timestamp},
      {"source", summary.source},
      {"destination", summary.destination},
      {"protocol", summary.protocol},
      {"length", summary.length},
      {"sourcePort", summary.source_port},
      {"destinationPort", summary.destination_port},
      {"info", summary.info},
  });
}

std::string address_text(const address *addr, bool resolveNames) {
  if (!addr || addr->type == AT_NONE) return "";
  if (resolveNames) {
    const gchar *name = address_to_name(addr);
    if (name && name[0] != '\0') return name;
  }
  char buf[256] = {0};
  address_to_str_buf(addr, buf, sizeof(buf));
  return buf;
}

std::string frame_search_text(WiresharkSession *session, int frameIdx,
                              DissectedFrame &frame) {
  std::string text;
  text.reserve(256);
  text.append(std::to_string(frameIdx + 1));
  text.push_back(' ');
  auto append_column = [&text](const char *value) {
    text.append(value ? value : "");
    text.push_back(' ');
  };
  append_column(safe_col_text(&frame.cinfo, COL_REL_TIME));
  append_column(safe_col_text(&frame.cinfo, session->name_resolution_enabled
                                             ? COL_RES_SRC
                                             : COL_UNRES_SRC));
  append_column(safe_col_text(&frame.cinfo, session->name_resolution_enabled
                                             ? COL_RES_DST
                                             : COL_UNRES_DST));
  append_column(safe_col_text(&frame.cinfo, COL_PROTOCOL));
  append_column(safe_col_text(&frame.cinfo, COL_INFO));
  packet_info *pinfo = &frame.edt->pi;
  append_column(address_text(&pinfo->net_src, session->name_resolution_enabled).c_str());
  append_column(address_text(&pinfo->net_dst, session->name_resolution_enabled).c_str());
  append_column(address_text(&pinfo->dl_src, session->name_resolution_enabled).c_str());
  const std::string dl_dst = address_text(&pinfo->dl_dst,
                                          session->name_resolution_enabled);
  text.append(dl_dst);
  return text;
}
