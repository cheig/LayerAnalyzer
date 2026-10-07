#include "layanalyzer/rtp/RtpSetupInfo.h"

#include <climits>
#include <cstring>

#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/projection/TreeFieldReader.h"
#include "layanalyzer/session/WiresharkSession.h"
#include <wsutil/wmem/wmem_strbuf.h>

namespace layanalyzer::rtp {
namespace {

constexpr size_t kMaxSetupFrames = 64;

bool named(proto_node *node, const char *name) {
  const field_info *field = node ? PITEM_FINFO(node) : nullptr;
  return field && field->hfinfo && field->hfinfo->abbrev &&
         std::strcmp(field->hfinfo->abbrev, name) == 0;
}

void find_protocols(proto_node *root, const char *name,
                    std::vector<proto_node *> &out) {
  if (!root) return;
  for (proto_node *node = root->first_child; node; node = node->next) {
    if (named(node, name)) {
      out.push_back(node);
    } else {
      find_protocols(node, name, out);
    }
  }
}

// All whitelisted fields are FT_STRING in Wireshark 4.0.10. FieldIndex's
// find/collect use display-filter escaping and deduplicate; neither is suitable
// for URI/fmtp values. Copy the string buffer, including any embedded NULs,
// while its DissectedFrame and dissect_mutex are still alive.
std::string raw_string(field_info *field) {
  if (!field || fvalue_type_ftenum(&field->value) != FT_STRING) return {};
  const wmem_strbuf_t *value = fvalue_get_strbuf(&field->value);
  return value && value->str ? std::string(value->str, value->len) : std::string();
}

std::vector<std::string> raw_values(const FieldIndex &index, const char *name) {
  std::vector<std::string> result;
  const auto found = index.values.find(name);
  if (found != index.values.end()) {
    for (field_info *field : found->second) result.push_back(raw_string(field));
  }
  return result;
}

bool single_value(const FieldIndex &index, const char *name, std::string &out) {
  const auto values = raw_values(index, name);
  if (values.size() != 1) return false;
  out = values.front();
  return true;
}

bool unique_value(const FieldIndex &index, const char *name, std::string &out) {
  for (const std::string &value : raw_values(index, name)) {
    if (value.empty()) continue;
    if (!out.empty() && out != value) return false;
    out = value;
  }
  return true;
}

bool decimal(const std::string &text, uint32_t maximum, uint32_t &out) {
  if (text.empty()) return false;
  uint32_t value = 0;
  for (unsigned char c : text) {
    if (c < '0' || c > '9') return false;
    const uint32_t digit = c - '0';
    if (value > maximum / 10 ||
        (value == maximum / 10 && digit > maximum % 10)) return false;
    value = value * 10 + digit;
  }
  out = value;
  return true;
}

std::string sip_user(const std::string &uri) {
  const size_t colon = uri.find(':');
  if (colon == std::string::npos) return {};
  const std::string scheme = lowercase_copy(uri.substr(0, colon));
  if (scheme != "sip" && scheme != "sips") return {};
  const size_t at = uri.find('@', colon + 1);
  if (at == std::string::npos) return {};
  return uri.substr(colon + 1, at - colon - 1);
}

struct SdpFormat {
  int payload_type = -1;
  std::string encoding_name;
  uint32_t clock_rate = 0;
  uint32_t channels = 0;
  bool has_rtpmap = false;
  bool ambiguous = false;
  std::vector<std::string> parameters;
};

SdpFormat &format_for_pt(std::vector<SdpFormat> &formats, int payload_type) {
  // Unknown associations are separate rows, never a shared "unknown PT" bucket.
  if (payload_type >= 0) {
    for (auto &format : formats) {
      if (format.payload_type == payload_type) return format;
    }
  }
  formats.emplace_back();
  formats.back().payload_type = payload_type;
  return formats.back();
}

uint32_t rtpmap_channels(const std::string &attribute, int payload_type,
                        const std::string &encoding, uint32_t clock_rate) {
  // There is no channels field in 4.0.10, and the rtpmap branch does not emit
  // sdp.media_attribute.value. Read only this already-identified rtpmap parent,
  // and cross-check it against the decoded PT/encoding/rate children.
  const size_t colon = attribute.find(':');
  if (colon == std::string::npos || attribute.substr(0, colon) != "rtpmap") return 0;
  std::istringstream input(attribute.substr(colon + 1));
  std::string pt, mapping, extra;
  if (!(input >> pt >> mapping) || (input >> extra)) return 0;
  uint32_t parsed_pt = 0;
  if (!decimal(pt, 127, parsed_pt) || static_cast<int>(parsed_pt) != payload_type)
    return 0;
  const size_t slash = mapping.find('/');
  if (slash == std::string::npos || mapping.substr(0, slash) != encoding) return 0;
  const size_t second_slash = mapping.find('/', slash + 1);
  const std::string rate = mapping.substr(
      slash + 1, second_slash == std::string::npos
                     ? std::string::npos : second_slash - slash - 1);
  uint32_t parsed_rate = 0;
  if (!decimal(rate, INT_MAX, parsed_rate) || parsed_rate == 0 ||
      parsed_rate != clock_rate) return 0;
  if (second_slash == std::string::npos) return 1;
  uint32_t channels = 0;
  if (!decimal(mapping.substr(second_slash + 1), INT_MAX, channels) || channels == 0)
    return 0;
  return channels;
}

void append_formats(const std::vector<SdpFormat> &formats, json &out) {
  for (const auto &format : formats) {
    std::string fmtp;
    for (size_t i = 0; i < format.parameters.size(); ++i) {
      if (i != 0) fmtp += ';';
      fmtp += format.parameters[i];
    }
    out.push_back({{"payloadType", format.ambiguous ? -1 : format.payload_type},
                   {"encodingName", format.ambiguous ? "" : format.encoding_name},
                   {"clockRate", format.ambiguous ? 0 : format.clock_rate},
                   {"channels", format.ambiguous ? 0 : format.channels},
                   {"fmtp", std::move(fmtp)}});
  }
}

void read_sdp(proto_node *sdp, json &out, size_t &warnings) {
  std::vector<SdpFormat> formats;
  // In 4.0.10, m= and a= are siblings under each SDP protocol node. Flush at
  // each m=, and once per SDP body, so reused PTs cannot cross those boundaries.
  for (proto_node *node = sdp->first_child; node; node = node->next) {
    if (named(node, "sdp.media")) {
      append_formats(formats, out);
      formats.clear();
      continue;
    }
    if (!named(node, "sdp.media_attr")) continue;
    FieldIndex attribute(node);
    std::string kind;
    if (!single_value(attribute, "sdp.media_attribute.field", kind) ||
        (kind != "rtpmap" && kind != "fmtp")) continue;

    std::string pt_text;
    uint32_t pt = 0;
    const int payload_type =
        single_value(attribute, "sdp.media.format", pt_text) && decimal(pt_text, 127, pt)
            ? static_cast<int>(pt) : -1;
    if (payload_type < 0) ++warnings;

    if (kind == "fmtp") {
      const auto parameters = raw_values(attribute, "sdp.fmtp.parameter");
      if (parameters.empty()) continue;
      auto &format = format_for_pt(formats, payload_type);
      format.parameters.insert(format.parameters.end(), parameters.begin(), parameters.end());
      continue;
    }

    std::string encoding, rate_text;
    uint32_t rate = 0;
    if (!single_value(attribute, "sdp.mime.type", encoding) || encoding.empty() ||
        !single_value(attribute, "sdp.sample_rate", rate_text) ||
        !decimal(rate_text, INT_MAX, rate) || rate == 0) {
      ++warnings;
      continue;
    }
    const uint32_t channels = rtpmap_channels(
        raw_string(PITEM_FINFO(node)), payload_type, encoding, rate);
    if (channels == 0) ++warnings;
    auto &format = format_for_pt(formats, payload_type);
    if (format.has_rtpmap &&
        (format.encoding_name != encoding || format.clock_rate != rate ||
         format.channels != channels)) {
      if (!format.ambiguous) ++warnings;
      format.ambiguous = true;
    } else {
      format.has_rtpmap = true;
      format.encoding_name = std::move(encoding);
      format.clock_rate = rate;
      format.channels = channels;
    }
  }
  append_formats(formats, out);
}

bool read_frame(proto_node *tree, uint32_t frame_number, bool sdp_only,
                json &out) {
  std::vector<proto_node *> sip_messages;
  find_protocols(tree, "sip", sip_messages);
  // The frame contract describes one SIP message. Combining one message's
  // From with another one's SDP would be false evidence, so reject ambiguity.
  if (sip_messages.size() > 1) return false;
  std::string method, from_uri, to_uri, call_id;
  if (!sip_messages.empty()) {
    FieldIndex sip(sip_messages.front());
    if (!unique_value(sip, "sip.method", method) ||
        !unique_value(sip, "sip.from.addr", from_uri) ||
        !unique_value(sip, "sip.to.addr", to_uri) ||
        !unique_value(sip, "sip.call-id", call_id)) return false;
  }

  out = {{"frame", frame_number}, {"sdp", json::array()}};
  if (!sdp_only) {
    out["sipMethod"] = std::move(method);
    out["fromUser"] = sip_user(from_uri);
    out["fromUri"] = std::move(from_uri);
    out["toUser"] = sip_user(to_uri);
    out["toUri"] = std::move(to_uri);
    out["callId"] = std::move(call_id);
  }
  std::vector<proto_node *> bodies;
  find_protocols(tree, "sdp", bodies);
  size_t warnings = 0;
  for (proto_node *body : bodies) read_sdp(body, out["sdp"], warnings);
  if (warnings != 0) {
    LOGW("RTP setup frame %u: %zu unresolved SDP attributes.", frame_number, warnings);
  }
  return true;
}

bool interrupted(WiresharkSession *session, uint64_t cancel_generation,
                  json &result) {
  if (session->closed.load(std::memory_order_acquire)) {
    result["error"] = "Capture session closed.";
    return true;
  }
  if (long_operation_cancelled(cancel_generation)) {
    result["cancelled"] = true;
    return true;
  }
  return false;
}

}  // namespace

json read_rtp_setup_info(WiresharkSession *session,
                         const std::string &request_text, bool sdp_only) {
  json result = {{"schemaVersion", 1}, {"error", ""},
                 {"cancelled", false}, {"frames", json::array()}};
  if (!session || !session->wth || !session->epan) {
    result["error"] = "No capture is open.";
    return result;
  }
  const uint64_t cancel_generation = current_cancel_generation();
  if (interrupted(session, cancel_generation, result)) return result;
  const json request = json::parse(request_text, nullptr, false);
  if (!request.is_object() || !request.contains("frames") ||
      !request["frames"].is_array()) {
    result["error"] = "Setup request must contain a frames array.";
    return result;
  }
  const json &requested = request["frames"];
  if (requested.size() > kMaxSetupFrames) {
    result["error"] = "Setup request exceeds 64 frames.";
    return result;
  }
  std::vector<uint32_t> frame_numbers;
  for (const auto &value : requested) {
    if (!value.is_number_integer() ||
        (!value.is_number_unsigned() && value.get<int64_t>() <= 0)) {
      result["error"] = "Setup frame numbers must be positive integers.";
      return result;
    }
    const uint64_t frame = value.get<uint64_t>();
    if (frame == 0 || frame > INT_MAX || frame > session->frame_offsets.size()) {
      result["error"] = "Setup frame number is out of range.";
      return result;
    }
    frame_numbers.push_back(static_cast<uint32_t>(frame));
  }

  json frames = json::array();
  for (uint32_t frame_number : frame_numbers) {
    if (interrupted(session, cancel_generation, result)) return result;
    json row;
    {
      std::unique_lock<std::mutex> lock(session->dissect_mutex);
      if (interrupted(session, cancel_generation, result)) return result;
      DissectedFrame frame;
      if (!dissect_frame(session, static_cast<int>(frame_number - 1),
                         TRUE, FALSE, nullptr, frame)) {
        result["error"] = "Unable to dissect setup frame.";
        return result;
      }
      if (!read_frame(frame.edt->tree, frame_number, sdp_only, row)) {
        result["error"] = "Ambiguous SIP setup information.";
        return result;
      }
    }
    // row owns all values. No tree/index pointers survive DissectedFrame or the
    // mutex; JSON serialization is left to the JNI wrapper after this read.
    frames.push_back(std::move(row));
    yield_to_interactive_reads(session);
  }
  if (interrupted(session, cancel_generation, result)) return result;
  result["frames"] = std::move(frames);
  return result;
}

}  // namespace layanalyzer::rtp
