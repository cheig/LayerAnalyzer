// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Communication analysis JNI endpoint (SIP/SDP, RTP/RTCP and core network).
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/ProtocolProjection.h"
#include "layanalyzer/projection/TreeFieldReader.h"

// Authentication values are intentionally never projected. These are the only
// schemes useful to the local analysis facts, so unknown header text is dropped.
static std::string safe_authorization_scheme(const std::string &header_value) {
  const size_t first = header_value.find_first_not_of(" \t");
  if (first == std::string::npos) return "";
  const size_t last = header_value.find_first_of(" \t,", first);
  const std::string candidate = lowercase_copy(header_value.substr(first, last - first));
  if (candidate == "digest") return "Digest";
  if (candidate == "basic") return "Basic";
  if (candidate == "bearer") return "Bearer";
  if (candidate == "aka" || candidate == "akav1-md5" || candidate == "akav2-md5") {
    return candidate == "aka" ? "AKAv1-MD5" : candidate;
  }
  return "";
}

static std::string normalize_sdp_direction(const std::string &value) {
  const std::string normalized = lowercase_copy(value);
  for (const char *candidate : {"sendrecv", "sendonly", "recvonly", "inactive"}) {
    if (normalized.find(candidate) != std::string::npos) return candidate;
  }
  return "";
}

// SDP fmtp values can contain media-specific details. Keep only known parameter
// names that are useful for negotiation analysis and cannot contain a secret.
static std::string safe_sdp_fmtp_parameter_name(const std::string &value) {
  size_t start = value.find_first_not_of(" \t");
  if (start == std::string::npos) return "";
  size_t end = value.find_first_of("=; \t", start);
  std::string name = lowercase_copy(value.substr(start, end - start));
  static const std::vector<std::string> allowed = {
      "profile-level-id", "packetization-mode", "level-asymmetry-allowed",
      "mode-set", "octet-align", "mode-change-capability", "mode-change-neighbor",
      "mode-change-period", "crc", "robust-sorting", "interleaving", "dtx",
      "maxplaybackrate", "minptime", "useinbandfec", "stereo", "sprop-stereo"};
  return std::find(allowed.begin(), allowed.end(), name) != allowed.end() ? name : "";
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_buildCommunicationAnalysis(
    JNIEnv *env, jobject /* this */, jlong sessionPtr) {
  auto session = acquire_session(sessionPtr);
  json root = {{"schemaVersion", 3},
               {"sipMessages", json::array()},
               {"rtpPackets", json::array()},
               {"rtcpPackets", json::array()},
               {"coreMessages", json::array()},
               {"sipTotal", 0},
               {"rtpTotal", 0},
               {"rtcpTotal", 0},
               {"coreTotal", 0},
               {"truncated", false}};
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }

  const std::vector<std::string> sip_method = {"sip.method", "sip.request-line"};
  const std::vector<std::string> sip_status = {"sip.status-code", "sip.status-line"};
  const std::vector<std::string> sip_call_id = {"sip.call-id", "sip.call_id"};
  const std::vector<std::string> sip_cseq_number = {"sip.cseq.seq", "sip.cseq.number"};
  const std::vector<std::string> sip_cseq_method = {"sip.cseq.method"};
  const std::vector<std::string> sip_via_branch = {"sip.via.branch"};
  const std::vector<std::string> sip_from_tag = {"sip.from.tag"};
  const std::vector<std::string> sip_to_tag = {"sip.to.tag"};
  const std::vector<std::string> sip_request_uri = {"sip.request-uri", "sip.request_uri"};
  const std::vector<std::string> sip_content_type = {"sip.content-type", "sip.content_type"};
  const std::vector<std::string> sip_authorization = {
      "sip.authorization", "sip.proxy-authorization", "sip.proxy_authorization"};
  const std::vector<std::string> sip_authorization_scheme = {
      "sip.auth.scheme", "sip.authorization.scheme", "sip.proxy-authorization.scheme",
      "sip.proxy_authorization.scheme"};
  const std::vector<std::string> sdp_connection_address = {
      "sdp.connection_info.address", "sdp.connection.address", "sdp.connection_address"};
  const std::vector<std::string> sdp_media_type = {
      "sdp.media.media", "sdp.media.type"};
  const std::vector<std::string> sdp_media_port = {
      "sdp.media.port", "sdp.media_port"};
  const std::vector<std::string> sdp_media_protocol = {
      "sdp.media.proto", "sdp.media.protocol"};
  const std::vector<std::string> sdp_media_format = {
      "sdp.media.format", "sdp.media_format"};
  const std::vector<std::string> sdp_codec = {
      "sdp.mime.type", "sdp.media.rtpmap.encoding_name", "sdp.rtpmap.encoding_name"};
  const std::vector<std::string> sdp_direction = {
      "sdp.media.direction", "sdp.direction", "sdp.media.attribute.direction"};
  const std::vector<std::string> sdp_rtpmap_payload_type = {
      "sdp.media.rtpmap.payload_type", "sdp.rtpmap.payload_type", "sdp.media.format"};
  const std::vector<std::string> sdp_rtpmap_encoding_name = {
      "sdp.media.rtpmap.encoding_name", "sdp.rtpmap.encoding_name", "sdp.mime.type"};
  const std::vector<std::string> sdp_rtpmap_clock_rate = {
      "sdp.media.rtpmap.clock_rate", "sdp.rtpmap.clock_rate", "sdp.sample_rate"};
  const std::vector<std::string> sdp_rtpmap_channels = {
      "sdp.media.rtpmap.channels", "sdp.rtpmap.channels", "sdp.audio.channels"};
  const std::vector<std::string> sdp_fmtp_parameter = {
      "sdp.fmtp.parameter", "sdp.media.fmtp.parameter"};
  const std::vector<std::string> rtp_sequence = {"rtp.seq", "rtp.sequence-number"};
  const std::vector<std::string> rtp_ssrc = {"rtp.ssrc"};
  const std::vector<std::string> rtp_timestamp = {"rtp.timestamp"};
  const std::vector<std::string> rtp_payload_type = {"rtp.p_type", "rtp.payload_type"};
  const std::vector<std::string> rtcp_packet_type = {"rtcp.pt"};
  const std::vector<std::string> rtcp_sender_ssrc = {"rtcp.senderssrc", "rtcp.ssrc.sender"};
  const std::vector<std::string> rtcp_reported_ssrc = {"rtcp.ssrc.identifier", "rtcp.ssrc.source"};
  const std::vector<std::string> rtcp_fraction_lost = {"rtcp.ssrc.fraction"};
  const std::vector<std::string> rtcp_cumulative_lost = {"rtcp.ssrc.cum_nr"};
  const std::vector<std::string> rtcp_interarrival_jitter = {"rtcp.ssrc.jitter"};
  const std::vector<std::string> diameter_session_id = {
      "diameter.session-id", "diameter.session_id", "diameter.sessionid"};
  const std::vector<std::string> diameter_command_code = {
      "diameter.cmd.code", "diameter.command_code"};
  const std::vector<std::string> diameter_application_id = {
      "diameter.applicationid", "diameter.application-id", "diameter.application_id"};
  const std::vector<std::string> diameter_request = {
      "diameter.flags.request", "diameter.flags.request_bit"};
  const std::vector<std::string> diameter_result_code = {
      "diameter.result-code", "diameter.result.code", "diameter.result_code"};
  const std::vector<std::string> diameter_experimental_result = {
      "diameter.experimental-result-code", "diameter.experimental_result_code",
      "diameter.experimental-result.code"};
  const std::vector<std::string> diameter_origin_realm = {
      "diameter.origin-realm", "diameter.origin_realm", "diameter.originrealm"};
  const std::vector<std::string> diameter_destination_realm = {
      "diameter.destination-realm", "diameter.destination_realm", "diameter.destinationrealm"};
  const std::vector<std::string> pfcp_seid = {"pfcp.seid"};
  const std::vector<std::string> pfcp_sequence = {
      "pfcp.seqno", "pfcp.sequence_number", "pfcp.sequence-number", "pfcp.seq"};
  const std::vector<std::string> pfcp_message_type = {
      "pfcp.message_type", "pfcp.msg.type", "pfcp.msg_type"};
  const std::vector<std::string> pfcp_cause = {"pfcp.cause"};
  const std::vector<std::string> pfcp_node_id = {
      "pfcp.node_id", "pfcp.nodeid", "pfcp.node-id"};
  const std::vector<std::string> gtp_teid = {"gtp.teid"};
  const std::vector<std::string> gtpv2_teid = {"gtpv2.teid"};
  const std::vector<std::string> gtp_sequence = {
      "gtp.seq", "gtp.sequence", "gtp.sequence_number"};
  const std::vector<std::string> gtpv2_sequence = {
      "gtpv2.seq", "gtpv2.sequence", "gtpv2.sequence_number"};
  const std::vector<std::string> gtp_message_type = {
      "gtp.message_type", "gtp.message.type", "gtp.msg.type"};
  const std::vector<std::string> gtpv2_message_type = {
      "gtpv2.message_type", "gtpv2.message.type", "gtpv2.msg.type"};
  const std::vector<std::string> gtp_cause = {"gtp.cause"};
  const std::vector<std::string> gtpv2_cause = {"gtpv2.cause"};
  const std::vector<std::string> gtp_bearer_id = {
      "gtp.bearer_id", "gtp.bearer-id", "gtp.eps_bearer_id"};
  const std::vector<std::string> gtpv2_bearer_id = {
      "gtpv2.bearer_id", "gtpv2.bearer-id", "gtpv2.eps_bearer_id"};
  const std::vector<std::string> s1ap_mme_ue_id = {
      "s1ap.mme_ue_s1ap_id", "s1ap.mme_ue_id"};
  const std::vector<std::string> s1ap_enb_ue_id = {
      "s1ap.enb_ue_s1ap_id", "s1ap.enb_ue_id"};
  const std::vector<std::string> s1ap_procedure_code = {
      "s1ap.procedurecode", "s1ap.procedure_code"};
  const std::vector<std::string> s1ap_outcome = {
      "s1ap.procedureoutcome", "s1ap.procedure_outcome", "s1ap.outcome"};
  const std::vector<std::string> s1ap_cause = {"s1ap.cause"};
  const std::vector<std::string> ngap_amf_ue_id = {
      "ngap.amf_ue_ngap_id", "ngap.amf_ue_id"};
  const std::vector<std::string> ngap_ran_ue_id = {
      "ngap.ran_ue_ngap_id", "ngap.ran_ue_id"};
  const std::vector<std::string> ngap_procedure_code = {
      "ngap.procedurecode", "ngap.procedure_code"};
  const std::vector<std::string> ngap_outcome = {
      "ngap.procedureoutcome", "ngap.procedure_outcome", "ngap.outcome"};
  const std::vector<std::string> ngap_cause = {"ngap.cause"};
  const std::vector<std::string> nas_eps_message_type = {
      "nas_eps.nas_msg_emm_type", "nas_eps.nas_msg_esm_type", "nas_eps.nas_msg_type",
      "nas_eps.emm.message_type", "nas_eps.esm.message_type"};
  const std::vector<std::string> nas_eps_pti = {
      "nas_eps.nas_msg_esm_pti", "nas_eps.esm.pti", "nas_eps.nas_msg_pti"};
  const std::vector<std::string> nas_eps_cause = {
      "nas_eps.emm.cause", "nas_eps.esm.cause", "nas_eps.cause"};
  const std::vector<std::string> nas_eps_state = {
      "nas_eps.emm.state", "nas_eps.esm.state", "nas_eps.state"};
  const std::vector<std::string> nas_5gs_message_type = {
      "nas-5gs.mm.message_type", "nas-5gs.sm.message_type", "nas-5gs.message_type"};
  const std::vector<std::string> nas_5gs_pti = {
      "nas-5gs.mm.pti", "nas-5gs.sm.pti", "nas-5gs.pti"};
  const std::vector<std::string> nas_5gs_cause = {
      "nas-5gs.mm.cause", "nas-5gs.sm.cause", "nas-5gs.cause"};
  const std::vector<std::string> nas_5gs_state = {
      "nas-5gs.mm.state", "nas-5gs.sm.state", "nas-5gs.state"};
  const std::vector<std::string> subscriber_id = {
      "nas_eps.imsi", "nas_eps.guti", "nas-5gs.supi", "nas-5gs.suci", "nas-5gs.guti",
      "gtp.imsi", "gtpv2.imsi", "diameter.user-name", "diameter.user_name"};
  const std::vector<std::string> apn_or_dnn = {
      "gtp.apn", "gtpv2.apn", "nas_eps.esm.apn", "nas-5gs.dnn", "nas-5gs.sm.dnn"};
  const std::vector<std::string> core_message_type = {
      "diameter.cmd.code", "diameter.command_code", "pfcp.message_type", "pfcp.msg.type", "gtp.message_type",
      "gtp.message.type", "gtpv2.message_type", "gtpv2.message.type", "s1ap.procedurecode",
      "ngap.procedurecode", "nas_eps.nas_msg_emm_type", "nas_eps.nas_msg_esm_type",
      "nas-5gs.mm.message_type", "nas-5gs.sm.message_type"};
  const std::vector<std::string> core_outcome = {
      "diameter.result-code", "pfcp.cause", "gtp.cause", "gtpv2.cause",
      "s1ap.cause", "ngap.cause", "nas_eps.emm.cause", "nas_eps.esm.cause",
      "nas-5gs.mm.cause", "nas-5gs.sm.cause"};
  const uint64_t cancel_generation = current_cancel_generation();
  const std::vector<int> visible_frames = snapshot_visible_frames(session);
  for (int frame_idx : visible_frames) {
    if (long_operation_cancelled(cancel_generation)) {
      root["cancelled"] = true;
      break;
    }
    {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    DissectedFrame frame;
    if (!dissect_frame(session, frame_idx, TRUE, TRUE, nullptr, frame)) continue;
    FieldIndex field_index(frame.edt->tree);
    packet_info *pinfo = &frame.edt->pi;
    std::string protocol = uppercase_copy(resolve_protocol_label(
        pinfo, safe_col_text(&frame.cinfo, COL_PROTOCOL)));
    std::string info = safe_col_text(&frame.cinfo, COL_INFO);
    std::string method;
    std::string status;
    std::string call_id;
    std::string cseq_method;
    std::string via_branch;
    std::string from_tag;
    std::string to_tag;
    std::string request_uri;
    std::string content_type;
    std::string authorization_header;
    std::string authorization_scheme;
    std::string sdp_address;
    std::string sdp_type;
    std::string sdp_protocol;
    std::string sdp_direction_value;
    std::vector<std::string> sdp_formats;
    std::vector<std::string> sdp_codecs;
    std::vector<std::string> sdp_rtpmap_payload_types;
    std::vector<std::string> sdp_rtpmap_encoding_names;
    std::vector<std::string> sdp_rtpmap_clock_rates;
    std::vector<std::string> sdp_rtpmap_channels_values;
    std::vector<std::string> sdp_fmtp_values;
    bool has_method = field_index.find( sip_method, method);
    bool has_status = field_index.find( sip_status, status);
    bool has_call_id = field_index.find( sip_call_id, call_id);
    std::string cseq_number_value;
    bool has_cseq_number = field_index.find( sip_cseq_number, cseq_number_value);
    int64_t cseq_number = -1;
    if (has_cseq_number) {
      char *cseq_end = nullptr;
      unsigned long long parsed = strtoull(cseq_number_value.c_str(), &cseq_end, 0);
      if (cseq_end != cseq_number_value.c_str()) cseq_number = static_cast<int64_t>(parsed);
    }
    bool has_cseq_method = field_index.find( sip_cseq_method, cseq_method);
    bool has_via_branch = field_index.find( sip_via_branch, via_branch);
    bool has_from_tag = field_index.find( sip_from_tag, from_tag);
    bool has_to_tag = field_index.find( sip_to_tag, to_tag);
    bool has_request_uri = field_index.find( sip_request_uri, request_uri);
    bool has_content_type = field_index.find( sip_content_type, content_type);
    bool has_authorization = field_index.find( sip_authorization, authorization_header);
    bool has_authorization_scheme = find_field_value(
        frame.edt->tree, sip_authorization_scheme, authorization_scheme);
    if (!has_authorization_scheme && has_authorization) {
      authorization_scheme = safe_authorization_scheme(authorization_header);
      has_authorization_scheme = !authorization_scheme.empty();
    }
    bool has_sdp_address = field_index.find( sdp_connection_address, sdp_address);
    bool has_sdp_type = field_index.find( sdp_media_type, sdp_type);
    bool has_sdp_protocol = field_index.find( sdp_media_protocol, sdp_protocol);
    int sdp_port = field_index.integer( sdp_media_port);
    field_index.collect( sdp_media_format, sdp_formats);
    field_index.collect( sdp_codec, sdp_codecs);
    bool has_sdp_direction = field_index.find( sdp_direction, sdp_direction_value);
    sdp_direction_value = normalize_sdp_direction(sdp_direction_value);
    field_index.collect( sdp_rtpmap_payload_type, sdp_rtpmap_payload_types);
    field_index.collect( sdp_rtpmap_encoding_name, sdp_rtpmap_encoding_names);
    field_index.collect( sdp_rtpmap_clock_rate, sdp_rtpmap_clock_rates);
    field_index.collect( sdp_rtpmap_channels, sdp_rtpmap_channels_values);
    field_index.collect( sdp_fmtp_parameter, sdp_fmtp_values);
    std::vector<std::string> sdp_fmtp_parameter_names;
    for (const std::string &value : sdp_fmtp_values) {
      const std::string name = safe_sdp_fmtp_parameter_name(value);
      if (!name.empty() && std::find(sdp_fmtp_parameter_names.begin(), sdp_fmtp_parameter_names.end(), name) ==
                               sdp_fmtp_parameter_names.end()) {
        sdp_fmtp_parameter_names.push_back(name);
      }
    }
    json sdp_payload_mappings = json::array();
    const size_t sdp_mapping_count = std::max(
        sdp_rtpmap_payload_types.size(),
        std::max(sdp_rtpmap_encoding_names.size(),
                 std::max(sdp_rtpmap_clock_rates.size(), sdp_rtpmap_channels_values.size())));
    for (size_t index = 0; index < sdp_mapping_count; ++index) {
      auto optional_number = [index](const std::vector<std::string> &values) -> json {
        if (index >= values.size()) return nullptr;
        char *end = nullptr;
        unsigned long parsed = strtoul(values[index].c_str(), &end, 0);
        return end == values[index].c_str() ? json(nullptr) : json(parsed);
      };
      sdp_payload_mappings.push_back({
          {"payloadType", optional_number(sdp_rtpmap_payload_types)},
          {"encodingName", index < sdp_rtpmap_encoding_names.size() ?
              json(sdp_rtpmap_encoding_names[index]) : json(nullptr)},
          {"clockRate", optional_number(sdp_rtpmap_clock_rates)},
          {"channels", optional_number(sdp_rtpmap_channels_values)},
          {"fmtpParameters", sdp_fmtp_parameter_names}});
    }
    bool has_sdp = protocol.find("SDP") != std::string::npos || has_sdp_address || has_sdp_type ||
                   has_sdp_protocol || has_sdp_direction || sdp_port >= 0 || !sdp_formats.empty() ||
                   !sdp_codecs.empty() || !sdp_payload_mappings.empty();
    bool sip = protocol.find("SIP") != std::string::npos || has_method || has_status || has_call_id ||
               has_sdp ||
               contains_case_insensitive(info, "INVITE") || contains_case_insensitive(info, "REGISTER") ||
               contains_case_insensitive(info, "SIP/2.0");
    if (sip) {
      root["sipTotal"] = root["sipTotal"].get<int>() + 1;
      if (root["sipMessages"].size() < 5000) {
        double timestamp = 0.0;
        if (frame.rec.presence_flags & WTAP_HAS_TS) {
          timestamp = frame.rec.ts.secs + frame.rec.ts.nsecs / 1e9;
        }
        json item = {{"frameNumber", frame_idx + 1},
                     {"time", timestamp},
                     {"source", address_text(&pinfo->net_src, false)},
                     {"destination", address_text(&pinfo->net_dst, false)},
                     {"sourcePort", pinfo->srcport <= 65535 ? pinfo->srcport : -1},
                     {"destinationPort", pinfo->destport <= 65535 ? pinfo->destport : -1},
                     {"method", method},
                     {"status", status},
                     {"callId", call_id},
                     {"cSeqNumber", cseq_number >= 0 ? json(cseq_number) : json(nullptr)},
                     {"cSeqMethod", has_cseq_method ? json(cseq_method) : json(nullptr)},
                     {"viaBranch", has_via_branch ? json(via_branch) : json(nullptr)},
                     {"fromTag", has_from_tag ? json(from_tag) : json(nullptr)},
                     {"toTag", has_to_tag ? json(to_tag) : json(nullptr)},
                     {"requestUri", has_request_uri ? json(request_uri) : json(nullptr)},
                     {"authorizationPresent", has_authorization},
                     {"authorizationScheme", has_authorization_scheme ? json(authorization_scheme) : json(nullptr)},
                     {"contentType", has_content_type ? json(content_type) : json(nullptr)},
                     {"hasCSeqNumber", has_cseq_number},
                     {"hasCSeqMethod", has_cseq_method},
                     {"hasViaBranch", has_via_branch},
                     {"hasFromTag", has_from_tag},
                     {"hasToTag", has_to_tag},
                     {"hasRequestUri", has_request_uri},
                     {"hasAuthorization", has_authorization},
                     {"hasContentType", has_content_type},
                     {"info", info},
                     {"hasSdp", has_sdp},
                     {"sdpConnectionAddress", sdp_address},
                     {"sdpMediaType", sdp_type},
                     {"sdpMediaPort", sdp_port},
                     {"sdpMediaProtocol", sdp_protocol},
                     {"sdpFormats", sdp_formats},
                     {"sdpCodecs", sdp_codecs},
                     {"sdpDirection", has_sdp_direction && !sdp_direction_value.empty() ?
                         json(sdp_direction_value) : json(nullptr)},
                     {"sdpPayloadMappings", sdp_payload_mappings},
                     {"sdpOfferAnswerRole", has_method ? "offer" : (has_status ? "answer" : "unknown")},
                     {"hasSdpDirection", has_sdp_direction},
                     {"hasSdpPayloadMappings", !sdp_payload_mappings.empty()},
                     {"hasSdpOfferAnswerRole", has_sdp}};
        root["sipMessages"].push_back(item);
      }
    }

    int rtcp_type = field_index.integer( rtcp_packet_type);
    int64_t rtcp_sender = field_index.uint64( rtcp_sender_ssrc);
    int64_t rtcp_reported = field_index.uint64( rtcp_reported_ssrc);
    int rtcp_fraction = field_index.integer( rtcp_fraction_lost);
    int rtcp_cumulative = parse_tree_integer(
        frame.edt->tree, rtcp_cumulative_lost, std::numeric_limits<int>::min());
    int64_t rtcp_jitter = field_index.uint64( rtcp_interarrival_jitter);
    bool rtcp = protocol.find("RTCP") != std::string::npos || rtcp_type >= 0 ||
                rtcp_sender >= 0 || rtcp_reported >= 0;
    if (rtcp) {
      root["rtcpTotal"] = root["rtcpTotal"].get<int>() + 1;
      if (root["rtcpPackets"].size() < 10000) {
        double timestamp = 0.0;
        if (frame.rec.presence_flags & WTAP_HAS_TS) {
          timestamp = frame.rec.ts.secs + frame.rec.ts.nsecs / 1e9;
        }
        root["rtcpPackets"].push_back({{"frameNumber", frame_idx + 1},
                                       {"time", timestamp},
                                       {"source", address_text(&pinfo->net_src, false)},
                                       {"destination", address_text(&pinfo->net_dst, false)},
                                       {"sourcePort", pinfo->srcport <= 65535 ? pinfo->srcport : -1},
                                       {"destinationPort", pinfo->destport <= 65535 ? pinfo->destport : -1},
                                       {"packetType", rtcp_type},
                                       {"senderSsrc", rtcp_sender},
                                       {"reportedSsrc", rtcp_reported},
                                       {"fractionLost", rtcp_fraction},
                                       {"cumulativeLost", rtcp_cumulative},
                                       {"interarrivalJitter", rtcp_jitter}});
      }
    }

    int sequence = field_index.integer( rtp_sequence);
    int64_t ssrc = field_index.uint64( rtp_ssrc);
    int64_t rtp_timestamp_value = field_index.uint64( rtp_timestamp);
    int payload_type = field_index.integer( rtp_payload_type);
    bool rtp = protocol.find("RTP") != std::string::npos || sequence >= 0 || ssrc >= 0;
    if (rtp) {
      root["rtpTotal"] = root["rtpTotal"].get<int>() + 1;
      if (root["rtpPackets"].size() < 10000) {
        double timestamp = 0.0;
        if (frame.rec.presence_flags & WTAP_HAS_TS) {
          timestamp = frame.rec.ts.secs + frame.rec.ts.nsecs / 1e9;
        }
        root["rtpPackets"].push_back({{"frameNumber", frame_idx + 1},
                                      {"time", timestamp},
                                      {"source", address_text(&pinfo->net_src, false)},
                                      {"destination", address_text(&pinfo->net_dst, false)},
                                      {"sourcePort", pinfo->srcport <= 65535 ? pinfo->srcport : -1},
                                      {"destinationPort", pinfo->destport <= 65535 ? pinfo->destport : -1},
                                      {"sequence", sequence},
                                      {"ssrc", ssrc},
                                      {"timestamp", rtp_timestamp_value},
                                      {"payloadType", payload_type}});
      }
    }

    std::string correlation_field;
    std::string correlation_value;
  const std::vector<std::pair<std::string, const std::vector<std::string> *>> correlation_fields = {
      {"diameter.session-id", &diameter_session_id}, {"pfcp.seid", &pfcp_seid},
      {"gtp.teid", &gtp_teid}, {"gtpv2.teid", &gtpv2_teid},
      {"s1ap.mme_ue_s1ap_id", &s1ap_mme_ue_id}, {"s1ap.enb_ue_s1ap_id", &s1ap_enb_ue_id},
      {"ngap.amf_ue_ngap_id", &ngap_amf_ue_id}, {"ngap.ran_ue_ngap_id", &ngap_ran_ue_id},
      {"subscriber.id", &subscriber_id}};
    for (const auto &candidate : correlation_fields) {
      if (field_index.find( *candidate.second, correlation_value)) {
        correlation_field = candidate.first;
        break;
      }
    }
    bool core_protocol = protocol.find("DIAMETER") != std::string::npos ||
                         protocol.find("PFCP") != std::string::npos ||
                         protocol.find("GTP") != std::string::npos ||
                         protocol.find("S1AP") != std::string::npos ||
                         protocol.find("NGAP") != std::string::npos ||
                         protocol.find("NAS") != std::string::npos ||
                         protocol.find("RRC") != std::string::npos ||
                         protocol.find("RADIO") != std::string::npos;
    if (core_protocol || !correlation_value.empty()) {
      root["coreTotal"] = root["coreTotal"].get<int>() + 1;
      if (root["coreMessages"].size() < 10000) {
        json fields = json::object();
        json identifiers = json::object();
        json field_presence = json::array();
        auto read_core_field = [&](const std::string &name,
                                   const std::vector<std::string> &candidates,
                                   bool identifier,
                                   std::string &output) -> bool {
          if (!field_index.find( candidates, output) || output.empty()) return false;
          fields[name] = output;
          field_presence.push_back(name);
          if (identifier) identifiers[name] = output;
          return true;
        };
        auto optional_number = [](const std::string &value) -> json {
          if (value.empty()) return nullptr;
          char *end = nullptr;
          unsigned long long parsed = strtoull(value.c_str(), &end, 0);
          return end == value.c_str() ? json(nullptr) : json(parsed);
        };

        std::string session_id;
        std::string command_code;
        std::string application_id;
        std::string result_code;
        std::string experimental_result;
        std::string origin_realm;
        std::string destination_realm;
        std::string seid;
        std::string pfcp_sequence_value;
        std::string gtp_sequence_value;
        std::string gtpv2_sequence_value;
        std::string pfcp_type;
        std::string gtp_type;
        std::string gtpv2_type;
        std::string pfcp_cause_value;
        std::string gtp_cause_value;
        std::string gtpv2_cause_value;
        std::string mme_ue_id;
        std::string enb_ue_id;
        std::string s1ap_procedure;
        std::string s1ap_outcome_value;
        std::string s1ap_cause_value;
        std::string amf_ue_id;
        std::string ran_ue_id;
        std::string ngap_procedure;
        std::string ngap_outcome_value;
        std::string ngap_cause_value;
        std::string nas_eps_type;
        std::string nas_eps_pti_value;
        std::string nas_eps_cause_value;
        std::string nas_eps_state_value;
        std::string nas_5gs_type;
        std::string nas_5gs_pti_value;
        std::string nas_5gs_cause_value;
        std::string nas_5gs_state_value;
        std::string subscriber_value;
        std::string apn_dnn_value;
        std::string node_id;
        std::string bearer_id;
        std::string teid;

        read_core_field("diameter.sessionId", diameter_session_id, true, session_id);
        read_core_field("diameter.commandCode", diameter_command_code, false, command_code);
        read_core_field("diameter.applicationId", diameter_application_id, false, application_id);
        read_core_field("diameter.resultCode", diameter_result_code, false, result_code);
        read_core_field("diameter.experimentalResult", diameter_experimental_result, false, experimental_result);
        read_core_field("diameter.originRealm", diameter_origin_realm, true, origin_realm);
        read_core_field("diameter.destinationRealm", diameter_destination_realm, true, destination_realm);
        read_core_field("pfcp.seid", pfcp_seid, true, seid);
        read_core_field("pfcp.sequenceNumber", pfcp_sequence, false, pfcp_sequence_value);
        read_core_field("pfcp.messageType", pfcp_message_type, false, pfcp_type);
        read_core_field("pfcp.cause", pfcp_cause, false, pfcp_cause_value);
        read_core_field("pfcp.nodeId", pfcp_node_id, true, node_id);
        read_core_field("gtp.teid", gtp_teid, true, teid);
        if (teid.empty()) read_core_field("gtpv2.teid", gtpv2_teid, true, teid);
        read_core_field("gtp.sequenceNumber", gtp_sequence, false, gtp_sequence_value);
        read_core_field("gtpv2.sequenceNumber", gtpv2_sequence, false, gtpv2_sequence_value);
        read_core_field("gtp.messageType", gtp_message_type, false, gtp_type);
        read_core_field("gtpv2.messageType", gtpv2_message_type, false, gtpv2_type);
        read_core_field("gtp.cause", gtp_cause, false, gtp_cause_value);
        read_core_field("gtpv2.cause", gtpv2_cause, false, gtpv2_cause_value);
        read_core_field("gtp.bearerId", gtp_bearer_id, true, bearer_id);
        if (bearer_id.empty()) read_core_field("gtpv2.bearerId", gtpv2_bearer_id, true, bearer_id);
        read_core_field("s1ap.mmeUeId", s1ap_mme_ue_id, true, mme_ue_id);
        read_core_field("s1ap.enbUeId", s1ap_enb_ue_id, true, enb_ue_id);
        read_core_field("s1ap.procedureCode", s1ap_procedure_code, false, s1ap_procedure);
        read_core_field("s1ap.outcome", s1ap_outcome, false, s1ap_outcome_value);
        read_core_field("s1ap.cause", s1ap_cause, false, s1ap_cause_value);
        read_core_field("ngap.amfUeId", ngap_amf_ue_id, true, amf_ue_id);
        read_core_field("ngap.ranUeId", ngap_ran_ue_id, true, ran_ue_id);
        read_core_field("ngap.procedureCode", ngap_procedure_code, false, ngap_procedure);
        read_core_field("ngap.outcome", ngap_outcome, false, ngap_outcome_value);
        read_core_field("ngap.cause", ngap_cause, false, ngap_cause_value);
        read_core_field("nas.registrationMessageType", nas_eps_message_type, false, nas_eps_type);
        read_core_field("nas.procedureTransactionIdentity", nas_eps_pti, false, nas_eps_pti_value);
        read_core_field("nas.cause", nas_eps_cause, false, nas_eps_cause_value);
        read_core_field("nas.registrationState", nas_eps_state, false, nas_eps_state_value);
        read_core_field("nas5gs.sessionMessageType", nas_5gs_message_type, false, nas_5gs_type);
        read_core_field("nas5gs.procedureTransactionIdentity", nas_5gs_pti, false, nas_5gs_pti_value);
        read_core_field("nas5gs.cause", nas_5gs_cause, false, nas_5gs_cause_value);
        read_core_field("nas5gs.sessionState", nas_5gs_state, false, nas_5gs_state_value);
        read_core_field("subscriber.id", subscriber_id, true, subscriber_value);
        read_core_field("apnOrDnn", apn_or_dnn, true, apn_dnn_value);

        bool request_value = false;
        const bool has_request = field_index.boolean( diameter_request, request_value);
        if (has_request) {
          fields["diameter.request"] = request_value ? "true" : "false";
          field_presence.push_back("diameter.request");
        }

        std::string message_type;
        std::string outcome;
        field_index.find( core_message_type, message_type);
        field_index.find( core_outcome, outcome);
        if (message_type.empty()) {
          message_type = !pfcp_type.empty() ? pfcp_type :
                         !gtpv2_type.empty() ? gtpv2_type :
                         !gtp_type.empty() ? gtp_type :
                         !s1ap_procedure.empty() ? s1ap_procedure :
                         !ngap_procedure.empty() ? ngap_procedure :
                         !nas_eps_type.empty() ? nas_eps_type : nas_5gs_type;
        }
        if (outcome.empty()) {
          outcome = !result_code.empty() ? result_code :
                    !experimental_result.empty() ? experimental_result :
                    !s1ap_outcome_value.empty() ? s1ap_outcome_value :
                    !ngap_outcome_value.empty() ? ngap_outcome_value :
                    !pfcp_cause_value.empty() ? pfcp_cause_value :
                    !gtpv2_cause_value.empty() ? gtpv2_cause_value :
                    !gtp_cause_value.empty() ? gtp_cause_value :
                    !s1ap_cause_value.empty() ? s1ap_cause_value :
                    !ngap_cause_value.empty() ? ngap_cause_value :
                    !nas_eps_cause_value.empty() ? nas_eps_cause_value : nas_5gs_cause_value;
        }
        std::string cause = !pfcp_cause_value.empty() ? pfcp_cause_value :
                            !gtpv2_cause_value.empty() ? gtpv2_cause_value :
                            !gtp_cause_value.empty() ? gtp_cause_value :
                            !s1ap_cause_value.empty() ? s1ap_cause_value :
                            !ngap_cause_value.empty() ? ngap_cause_value :
                            !nas_eps_cause_value.empty() ? nas_eps_cause_value : nas_5gs_cause_value;
        std::string procedure_code = !s1ap_procedure.empty() ? s1ap_procedure : ngap_procedure;
        std::string ue_id;
        std::string ue_id_type;
        if (!mme_ue_id.empty()) { ue_id = mme_ue_id; ue_id_type = "s1ap.mmeUeId"; }
        else if (!enb_ue_id.empty()) { ue_id = enb_ue_id; ue_id_type = "s1ap.enbUeId"; }
        else if (!amf_ue_id.empty()) { ue_id = amf_ue_id; ue_id_type = "ngap.amfUeId"; }
        else if (!ran_ue_id.empty()) { ue_id = ran_ue_id; ue_id_type = "ngap.ranUeId"; }
        else if (!subscriber_value.empty()) { ue_id = subscriber_value; ue_id_type = "subscriber.id"; }
        std::string sequence_value = !pfcp_sequence_value.empty() ? pfcp_sequence_value :
                                     !gtpv2_sequence_value.empty() ? gtpv2_sequence_value : gtp_sequence_value;
        std::string state_value = !nas_eps_state_value.empty() ? nas_eps_state_value : nas_5gs_state_value;
        std::string pti_value = !nas_eps_pti_value.empty() ? nas_eps_pti_value : nas_5gs_pti_value;
        double timestamp = 0.0;
        if (frame.rec.presence_flags & WTAP_HAS_TS) {
          timestamp = frame.rec.ts.secs + frame.rec.ts.nsecs / 1e9;
        }
        json item = {{"frameNumber", frame_idx + 1},
                     {"time", timestamp},
                     {"protocol", protocol},
                     {"source", address_text(&pinfo->net_src, false)},
                     {"destination", address_text(&pinfo->net_dst, false)},
                     {"correlationField", correlation_field},
                     {"correlationValue", correlation_value},
                     {"messageType", message_type},
                     {"outcome", outcome},
                     {"info", info},
                     {"commandCode", optional_number(command_code)},
                     {"applicationId", optional_number(application_id)},
                     {"request", has_request ? json(request_value) : json(nullptr)},
                     {"resultCode", result_code},
                     {"experimentalResult", experimental_result},
                     {"originRealm", origin_realm},
                     {"destinationRealm", destination_realm},
                     {"sessionId", session_id},
                     {"sequenceNumber", optional_number(sequence_value)},
                     {"cause", cause},
                     {"nodeId", node_id},
                     {"teid", teid},
                     {"seid", seid},
                     {"ueId", ue_id},
                     {"ueIdType", ue_id_type},
                     {"procedureCode", procedure_code},
                     {"bearerId", bearer_id},
                     {"procedureTransactionIdentity", optional_number(pti_value)},
                     {"registrationState", nas_eps_state_value},
                     {"sessionState", nas_5gs_state_value.empty() ? state_value : nas_5gs_state_value},
                     {"subscriberId", subscriber_value},
                     {"apnOrDnn", apn_dnn_value},
                     {"fields", fields},
                     {"identifiers", identifiers},
                     {"fieldPresence", field_presence}};
        root["coreMessages"].push_back(item);
      }
    }
    }
    yield_to_interactive_reads(session);
  }
  root["sipTruncated"] = root["sipTotal"].get<int>() > static_cast<int>(root["sipMessages"].size());
  root["rtpTruncated"] = root["rtpTotal"].get<int>() > static_cast<int>(root["rtpPackets"].size());
  root["rtcpTruncated"] = root["rtcpTotal"].get<int>() > static_cast<int>(root["rtcpPackets"].size());
  root["coreTruncated"] = root["coreTotal"].get<int>() > static_cast<int>(root["coreMessages"].size());
  root["truncated"] = root["sipTruncated"].get<bool>() || root["rtpTruncated"].get<bool>() ||
                      root["rtcpTruncated"].get<bool>() || root["coreTruncated"].get<bool>();
  return new_java_string(env, root.dump());
}
