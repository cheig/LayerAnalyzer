// Packet-list row projection and tree/search helper implementation.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/TreeFieldReader.h"
#include "layanalyzer/projection/ProtocolProjection.h"

static std::string protocol_display_name_from_token(const std::string &token) {
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

static std::string last_protocol_token(const std::string &layers) {
  std::string trimmed = trim_copy(layers);
  if (trimmed.empty()) return "";

  size_t start = trimmed.find_last_of(":, >");
  if (start == std::string::npos) return trimmed;
  return trim_copy(trimmed.substr(start + 1));
}

bool is_unusable_protocol_label(const std::string &value) {
  std::string lower = lowercase_copy(trim_copy(value));
  if (lower.size() >= 2 && lower.front() == '<' && lower.back() == '>') {
    lower = trim_copy(lower.substr(1, lower.size() - 2));
  }
  return lower.empty() || lower == "unknown" ||
         lower == "missing protocol name";
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

bool populate_packet_summary(WiresharkSession *session, int frameIdx,
                             DissectedFrame &frame,
                             CachedPacketSummary &summary) {
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

static bool build_packet_summary(WiresharkSession *session, int frameIdx,
                                 CachedPacketSummary &summary) {
  DissectedFrame frame;
  if (!dissect_frame(session, frameIdx, FALSE, TRUE, nullptr, frame)) {
    return false;
  }
  return populate_packet_summary(session, frameIdx, frame, summary);
}

CachedPacketSummary get_or_build_packet_summary(
    WiresharkSession *session, int frameIdx) {
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

bool tree_contains_text(proto_node *node, const std::string &needle) {
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo) {
      std::string label = finfo->rep ? finfo->rep->representation : "";
      std::string abbrev = (finfo->hfinfo && finfo->hfinfo->abbrev) ? finfo->hfinfo->abbrev : "";
      std::string name = (finfo->hfinfo && finfo->hfinfo->name) ? finfo->hfinfo->name : "";
      std::string value = get_filter_value(finfo);
      if (contains_case_insensitive(label, needle) ||
          contains_case_insensitive(abbrev, needle) ||
          contains_case_insensitive(name, needle) ||
          contains_case_insensitive(value, needle)) {
        return true;
      }
    }
    if (tree_contains_text(current, needle)) return true;
  }
  return false;
}

std::vector<guint8> parse_hex_query(const std::string &query) {
  auto hex_value = [](unsigned char value) -> int {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
  };
  std::vector<guint8> bytes;
  bytes.reserve(query.size() / 2);
  int high_nibble = -1;
  for (unsigned char value : query) {
    const int nibble = hex_value(value);
    if (nibble < 0) continue;
    if (high_nibble < 0) {
      high_nibble = nibble;
    } else {
      bytes.push_back(static_cast<guint8>((high_nibble << 4) | nibble));
      high_nibble = -1;
    }
  }
  // An unmatched nibble is not a valid byte query. Returning an empty needle
  // preserves the existing "no match" contract without partial matches.
  if (high_nibble >= 0) bytes.clear();
  return bytes;
}

bool bytes_contain(const guint8 *data, size_t length,
                   const std::vector<guint8> &needle) {
  if (!data || needle.empty() || needle.size() > length) return false;
  for (size_t i = 0; i <= length - needle.size(); ++i) {
    if (memcmp(data + i, needle.data(), needle.size()) == 0) return true;
  }
  return false;
}

std::string severity_from_flags(guint32 flags) {
  switch (flags & PI_SEVERITY_MASK) {
    case PI_ERROR: return "error";
    case PI_WARN: return "warn";
    case PI_NOTE: return "note";
    default: return "none";
  }
}

int severity_rank(const std::string &value) {
  if (value == "error") return 3;
  if (value == "warn") return 2;
  if (value == "note") return 1;
  return 0;
}

bool collect_expert_nodes(proto_node *node, json &items,
                          std::string &highest) {
  bool found = false;
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo) {
      std::string severity = severity_from_flags(finfo->flags);
      if (severity != "none") {
        std::string label = finfo->rep ? finfo->rep->representation : "";
        if (label.empty() && finfo->hfinfo && finfo->hfinfo->name) label = finfo->hfinfo->name;
        json item;
        item["label"] = label;
        item["filter"] = (finfo->hfinfo && finfo->hfinfo->abbrev) ? finfo->hfinfo->abbrev : "";
        item["severity"] = severity;
        item["start"] = finfo->start < 0 ? 0 : finfo->start;
        item["length"] = finfo->length < 0 ? 0 : finfo->length;
        items.push_back(item);
        if (severity_rank(severity) > severity_rank(highest)) highest = severity;
        found = true;
      }
    }
    if (collect_expert_nodes(current, items, highest)) found = true;
  }
  return found;
}

int find_stream_id(proto_node *node, const std::string &fieldName) {
  if (!node) return -1;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev &&
        fieldName == finfo->hfinfo->abbrev) {
      ftenum_t type = fvalue_type_ftenum(&finfo->value);
      if (type == FT_UINT8 || type == FT_UINT16 || type == FT_UINT24 ||
          type == FT_UINT32) {
        return static_cast<int>(fvalue_get_uinteger(&finfo->value));
      }
      if (type == FT_UINT64) {
        return static_cast<int>(fvalue_get_uinteger64(&finfo->value));
      }
      if (finfo->rep) {
        const char *text = finfo->rep->representation;
        const char *colon = strrchr(text, ':');
        if (colon) return atoi(colon + 1);
      }
    }
    int childValue = find_stream_id(current, fieldName);
    if (childValue >= 0) return childValue;
  }
  return -1;
}

bool find_boolean_field(proto_node *node, const std::string &fieldName) {
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev &&
        fieldName == finfo->hfinfo->abbrev) {
      ftenum_t type = fvalue_type_ftenum(&finfo->value);
      if (type == FT_NONE) return true;
      if (type == FT_BOOLEAN) {
        // Wireshark stores FT_BOOLEAN in the 64-bit integer slot; the 32-bit accessor aborts.
        return fvalue_get_uinteger64(&finfo->value) != 0;
      }
      if (type == FT_UINT8 || type == FT_UINT16 || type == FT_UINT24 ||
          type == FT_UINT32) {
        return fvalue_get_uinteger(&finfo->value) != 0;
      }
      if (type == FT_UINT64) return fvalue_get_uinteger64(&finfo->value) != 0;
      return true;
    }
    if (find_boolean_field(current, fieldName)) return true;
  }
  return false;
}

bool append_payload_bytes(proto_node *node, const std::string &fieldName,
                          std::vector<guint8> &bytes) {
  bool found = false;
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev &&
        fieldName == finfo->hfinfo->abbrev && finfo->ds_tvb &&
        finfo->start >= 0 && finfo->length > 0) {
      const guint8 *ptr = tvb_get_ptr(finfo->ds_tvb, finfo->start, finfo->length);
      if (ptr) {
        bytes.insert(bytes.end(), ptr, ptr + finfo->length);
        found = true;
      }
    }
    if (append_payload_bytes(current, fieldName, bytes)) found = true;
  }
  return found;
}
