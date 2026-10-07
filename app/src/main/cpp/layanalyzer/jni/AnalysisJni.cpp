// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Analysis JNI endpoints: Expert Info summary and the statistics build path.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/ProtocolProjection.h"
#include "layanalyzer/analysis/StatisticsLegacy.h"

static bool statistics_peer_before(const StatisticsPeer &left,
                                   const StatisticsPeer &right) {
  std::string left_address = lowercase_copy(left.address);
  std::string right_address = lowercase_copy(right.address);
  return std::tie(left_address, left.port) <=
         std::tie(right_address, right.port);
}

void add_statistics_conversation(
    std::map<StatisticsConversationKey, StatisticsConversationValue> &values,
    const std::string &type, StatisticsPeer source, StatisticsPeer destination,
    int length, double timestamp) {
  if (source.address.empty() || destination.address.empty()) return;
  bool forward = statistics_peer_before(source, destination);
  StatisticsConversationKey key{
      type, forward ? source : destination, forward ? destination : source};
  auto &value = values[key];
  if (value.packets == 0) {
    value.start = timestamp;
    value.last = timestamp;
  } else {
    value.start = std::min(value.start, timestamp);
    value.last = std::max(value.last, timestamp);
  }
  value.packets++;
  value.bytes += length;
  if (forward) value.a_to_b++; else value.b_to_a++;
}

void add_statistics_endpoint(
    std::map<StatisticsEndpointKey, StatisticsEndpointValue> &values,
    const std::string &type, const std::string &address, int port, int length,
    bool sent) {
  if (address.empty()) return;
  auto &value = values[{type, address, port}];
  value.packets++;
  value.bytes += length;
  if (sent) value.sent++; else value.received++;
}

void append_statistics_summary(json &array, int frame_number,
                               double timestamp,
                               const std::string &source,
                               const std::string &destination,
                               const std::string &protocol,
                               const std::string &summary) {
  if (array.size() >= 200) return;
  array.push_back({{"frameNumber", frame_number},
                   {"time", timestamp},
                   {"source", source},
                   {"destination", destination},
                   {"protocol", protocol},
                   {"summary", summary.empty() ? protocol : summary}});
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getExpertInfoSummary(JNIEnv *env,
                                                               jobject /* this */,
                                                               jlong sessionPtr) {
  PERF_SCAN_START();
  auto session = acquire_session(sessionPtr);
  json root;
  root["items"] = json::array();
  if (!session || !session->wth || !session->epan) {
    root["warnings"] = 0;
    root["errors"] = 0;
    return new_java_string(env, root.dump());
  }

  uint64_t cancel_generation = current_cancel_generation();
  int warnings = 0;
  int errors = 0;
  int total_items = 0;
  std::vector<int> visible_frames = snapshot_visible_frames(session);
  for (int frameIdx : visible_frames) {
    if (long_operation_cancelled(cancel_generation)) {
      root["cancelled"] = true;
      break;
    }
    json items = json::array();
    std::string highest = "none";
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      if (!dissect_frame(session, frameIdx, TRUE, FALSE, nullptr, frame)) continue;
      if (collect_expert_nodes(frame.edt->tree, items, highest)) {
        if (highest == "error") errors++; else if (highest == "warn") warnings++;
        for (auto &item : items) {
          item["frameNumber"] = frameIdx + 1;
          total_items++;
          if (root["items"].size() < 5000) root["items"].push_back(item);
        }
      }
    }
    yield_to_interactive_reads(session);
  }
  root["warnings"] = warnings;
  root["errors"] = errors;
  root["totalItems"] = total_items;
  root["truncated"] = total_items > static_cast<int>(root["items"].size());
  PERF_SCAN_LOG("getExpertInfoSummary frames=%d ms=%lld items=%d warnings=%d errors=%d%s",
                static_cast<int>(visible_frames.size()), __perf_ms, total_items,
                warnings, errors,
                root.contains("cancelled") ? " cancelled=1" : "");
  return new_java_string(env, root.dump());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_buildStatistics(JNIEnv *env,
                                                           jobject /* this */,
                                                           jlong sessionPtr,
                                                           jdouble bucketSeconds) {
  PERF_SCAN_START();
  auto session = acquire_session(sessionPtr);
  json root = {{"packetCount", 0},
               {"byteCount", 0},
               {"protocolHierarchy", json::array()},
               {"conversations", json::array()},
               {"endpoints", json::array()},
               {"ioGraph", json::array()},
               {"packetLengths", json::object()},
               {"dnsSummaries", json::array()},
               {"httpSummaries", json::array()},
               {"tlsSummaries", json::array()},
               {"tcpSummaries", json::array()},
               {"dnsSummaryTotal", 0},
               {"httpSummaryTotal", 0},
               {"tlsSummaryTotal", 0},
               {"tcpSummaryTotal", 0}};
  root["dnsFailureTotal"] = 0;
  root["tlsAlertTotal"] = 0;
  root["httpErrorTotal"] = 0;
  root["dnsFirstFailureFrame"] = 0;
  root["tlsFirstAlertFrame"] = 0;
  root["httpFirstErrorFrame"] = 0;
  root["dnsQueries"] = 0;
  root["dnsResponses"] = 0;
  root["dnsAverageResponseMs"] = 0.0;
  root["tcpSyn"] = 0;
  root["tcpSynAck"] = 0;
  root["tcpRetransmissions"] = 0;
  root["tcpDuplicateAcks"] = 0;
  root["tcpResets"] = 0;
  root["tcpZeroWindows"] = 0;
  root["tcpRttSamples"] = 0;
  root["tcpAverageRttMs"] = 0.0;
  root["tlsVersions"] = json::object();
  root["tlsSni"] = json::object();
  root["httpStatusCodes"] = json::object();
  root["httpHosts"] = json::object();
  root["dnsTopDomains"] = json::object();
  root["truncatedPacketCount"] = 0;
  root["capturedByteCount"] = 0;
  root["startTime"] = 0.0;
  root["endTime"] = 0.0;
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }

  const double bucket_seconds = std::max(0.001, static_cast<double>(bucketSeconds));
  const uint64_t cancel_generation = current_cancel_generation();
  std::map<std::string, StatisticsProtocolValue> protocols;
  std::map<StatisticsConversationKey, StatisticsConversationValue> conversations;
  std::map<StatisticsEndpointKey, StatisticsEndpointValue> endpoints;
  std::vector<std::pair<double, int>> timeline;
  const int length_limits[] = {63, 127, 255, 511, 1023, 1518,
                               std::numeric_limits<int>::max()};
  const char *length_labels[] = {"0-63", "64-127", "128-255", "256-511",
                                 "512-1023", "1024-1518", "1519+"};
  int length_packets[7] = {0};
  int64_t length_bytes[7] = {0};
  int min_length = std::numeric_limits<int>::max();
  int max_length = 0;
  int packet_count = 0;
  int64_t byte_count = 0;
  int64_t captured_byte_count = 0;
  int truncated_packet_count = 0;
  double first_time = std::numeric_limits<double>::max();
  double last_time = 0.0;
  double dns_response_time_sum = 0.0;
  int dns_response_time_count = 0;
  double tcp_rtt_sum = 0.0;
  int tcp_rtt_count = 0;

  // Keep hot-loop counters in native POD values.  Mutating nlohmann::json
  // (and converting it back with get<int>()) for every packet is expensive;
  // the response object is populated once after the scan.
  int dns_failure_total = 0;
  int dns_first_failure_frame = 0;
  int dns_queries = 0;
  int dns_responses = 0;
  int tls_alert_total = 0;
  int tls_first_alert_frame = 0;
  int http_error_total = 0;
  int http_first_error_frame = 0;
  int tcp_syn = 0;
  int tcp_syn_ack = 0;
  int tcp_retransmissions = 0;
  int tcp_duplicate_acks = 0;
  int tcp_resets = 0;
  int tcp_zero_windows = 0;
  int dns_summary_total = 0;
  int http_summary_total = 0;
  int tls_summary_total = 0;
  int tcp_summary_total = 0;
  std::map<std::string, int> tls_versions;
  std::map<std::string, int> tls_sni_counts;
  std::map<std::string, int> http_status_codes;
  std::map<std::string, int> http_hosts;
  std::map<std::string, int> dns_top_domains;

  const std::vector<std::string> dns_response_flag = {"dns.flags.response"};
  const std::vector<std::string> dns_rcode = {"dns.flags.rcode"};
  const std::vector<std::string> dns_time = {"dns.time"};
  const std::vector<std::string> dns_query_name = {"dns.qry.name"};
  const std::vector<std::string> tcp_window_size = {"tcp.window_size_value"};
  const std::vector<std::string> tcp_ack_rtt = {"tcp.analysis.ack_rtt"};
  const std::vector<std::string> tls_version = {"tls.record.version", "tls.handshake.version"};
  const std::vector<std::string> tls_sni = {"tls.handshake.extensions_server_name"};
  const std::vector<std::string> tls_alert = {"tls.alert_message", "tls.alert_message_desc"};
  const std::vector<std::string> http_status = {"http.response.code"};
  const std::vector<std::string> http_host = {"http.host"};
  auto increment_map = [](std::map<std::string, int> &object,
                          const std::string &key) {
    if (key.empty()) return;
    ++object[key];
  };

  std::vector<int> visible_frames = snapshot_visible_frames(session);
  for (int frame_idx : visible_frames) {
    if (long_operation_cancelled(cancel_generation)) {
      root["cancelled"] = true;
      root["error"] = "Operation cancelled.";
      PERF_SCAN_LOG("buildStatistics frames=%d ms=%lld cancelled=1",
                    static_cast<int>(visible_frames.size()), __perf_ms);
      return new_java_string(env, root.dump());
    }
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      if (!dissect_frame(session, frame_idx, TRUE, TRUE, nullptr, frame)) continue;
    FieldIndex field_index(frame.edt->tree);

    packet_info *pinfo = &frame.edt->pi;
    double timestamp = 0.0;
    if (frame.rec.presence_flags & WTAP_HAS_TS) {
      timestamp = frame.rec.ts.secs + frame.rec.ts.nsecs / 1e9;
    }
    int length = static_cast<int>(frame.rec.rec_header.packet_header.len);
    int captured_length = static_cast<int>(frame.rec.rec_header.packet_header.caplen);
    std::string source = address_text(&pinfo->net_src, false);
    std::string destination = address_text(&pinfo->net_dst, false);
    if (source.empty()) source = address_text(&pinfo->src, false);
    if (destination.empty()) destination = address_text(&pinfo->dst, false);
    std::string mac_source = address_text(&pinfo->dl_src, false);
    std::string mac_destination = address_text(&pinfo->dl_dst, false);
    std::string protocol = resolve_protocol_label(
        pinfo, safe_col_text(&frame.cinfo, COL_PROTOCOL));
    if (is_unusable_protocol_label(protocol)) protocol = "Unknown";
    std::string info = safe_col_text(&frame.cinfo, COL_INFO);
    std::string protocol_upper = uppercase_copy(protocol);

    const int dns_response_value = field_index.integer( dns_response_flag);
    const int dns_rcode_value = field_index.integer( dns_rcode);
    const double dns_time_value = field_index.real( dns_time);
    std::string dns_name_value;
    field_index.find( dns_query_name, dns_name_value);
    const bool dns_frame = protocol_upper == "DNS" || dns_response_value >= 0 || !dns_name_value.empty();
    if (dns_frame) {
      if (dns_response_value > 0) {
        ++dns_responses;
        if (dns_time_value >= 0.0) {
          dns_response_time_sum += dns_time_value;
          dns_response_time_count++;
        }
        if (dns_rcode_value > 0) {
          ++dns_failure_total;
          if (dns_first_failure_frame == 0) dns_first_failure_frame = frame_idx + 1;
        }
      } else {
        ++dns_queries;
      }
      increment_map(dns_top_domains, dns_name_value);
    }

    if (pinfo->ptype == PT_TCP) {
      const bool syn = field_index.boolean( "tcp.flags.syn");
      const bool ack = field_index.boolean( "tcp.flags.ack");
      if (syn && !ack) ++tcp_syn;
      if (syn && ack) ++tcp_syn_ack;
      if (field_index.boolean( "tcp.analysis.retransmission") || field_index.boolean( "tcp.analysis.fast_retransmission")) ++tcp_retransmissions;
      if (field_index.boolean( "tcp.analysis.duplicate_ack")) ++tcp_duplicate_acks;
      if (field_index.boolean( "tcp.flags.reset")) ++tcp_resets;
      const int window = field_index.integer( tcp_window_size, -1);
      if (field_index.boolean( "tcp.analysis.zero_window") || window == 0) ++tcp_zero_windows;
      const double rtt = field_index.real( tcp_ack_rtt);
      if (rtt >= 0.0) {
        tcp_rtt_sum += rtt;
        tcp_rtt_count++;
      }
    }

    if (protocol_upper.find("TLS") != std::string::npos || protocol_upper.find("SSL") != std::string::npos) {
      std::string version;
      std::string sni;
      field_index.find( tls_version, version);
      field_index.find( tls_sni, sni);
      increment_map(tls_versions, version);
      increment_map(tls_sni_counts, sni);
    }

    std::string http_status_value;
    std::string http_host_value;
    field_index.find( http_status, http_status_value);
    field_index.find( http_host, http_host_value);
    if (!http_status_value.empty() || !http_host_value.empty()) {
      increment_map(http_status_codes, http_status_value);
      increment_map(http_hosts, http_host_value);
    }

    packet_count++;
    byte_count += length;
    captured_byte_count += captured_length;
    if (captured_length < length) truncated_packet_count++;
    first_time = std::min(first_time, timestamp);
    last_time = std::max(last_time, timestamp);
    timeline.emplace_back(timestamp, length);
    auto &protocol_value = protocols[protocol_upper];
    protocol_value.packets++;
    protocol_value.bytes += length;
    min_length = std::min(min_length, length);
    max_length = std::max(max_length, length);
    for (int bucket = 0; bucket < 7; ++bucket) {
      if (length <= length_limits[bucket]) {
        length_packets[bucket]++;
        length_bytes[bucket] += length;
        break;
      }
    }

    if (!mac_source.empty() && !mac_destination.empty()) {
      add_statistics_conversation(conversations, "Ethernet",
                                  {mac_source, -1}, {mac_destination, -1},
                                  length, timestamp);
      add_statistics_endpoint(endpoints, "MAC", mac_source, -1, length, true);
      add_statistics_endpoint(endpoints, "MAC", mac_destination, -1, length, false);
    }
    bool ipv6 = pinfo->net_src.type == AT_IPv6 || pinfo->net_dst.type == AT_IPv6;
    bool ip = ipv6 || pinfo->net_src.type == AT_IPv4 ||
              pinfo->net_dst.type == AT_IPv4;
    if (ip && !source.empty() && !destination.empty()) {
      add_statistics_conversation(conversations, ipv6 ? "IPv6" : "IPv4",
                                  {source, -1}, {destination, -1}, length,
                                  timestamp);
      add_statistics_endpoint(endpoints, "IP", source, -1, length, true);
      add_statistics_endpoint(endpoints, "IP", destination, -1, length, false);
    }
    const char *transport = pinfo->ptype == PT_TCP ? "TCP" :
                            pinfo->ptype == PT_UDP ? "UDP" : nullptr;
    if (transport && !source.empty() && !destination.empty()) {
      int source_port = pinfo->srcport <= 65535 ? pinfo->srcport : -1;
      int destination_port = pinfo->destport <= 65535 ? pinfo->destport : -1;
      add_statistics_conversation(conversations, transport,
                                  {source, source_port},
                                  {destination, destination_port}, length,
                                  timestamp);
      add_statistics_endpoint(endpoints, transport, source, source_port,
                              length, true);
      add_statistics_endpoint(endpoints, transport, destination,
                              destination_port, length, false);
    }

    if (protocol_upper == "DNS" || contains_case_insensitive(info, "query")) {
      ++dns_summary_total;
      append_statistics_summary(root["dnsSummaries"], frame_idx + 1, timestamp,
                                source, destination, protocol, info);
      if (dns_response_value < 0 && (contains_case_insensitive(info, "NXDOMAIN") ||
          contains_case_insensitive(info, "SERVFAIL") ||
          contains_case_insensitive(info, "REFUSED") ||
          contains_case_insensitive(info, "No such name"))) {
        ++dns_failure_total;
        if (dns_first_failure_frame == 0) dns_first_failure_frame = frame_idx + 1;
      }
    }
    std::string info_upper = uppercase_copy(info);
    bool http = protocol_upper.rfind("HTTP", 0) == 0 ||
                info_upper.rfind("HTTP/", 0) == 0;
    static const char *http_methods[] = {"GET ", "POST ", "PUT ", "DELETE ",
                                         "PATCH ", "HEAD ", "OPTIONS ",
                                         "CONNECT ", "TRACE "};
    for (const char *method : http_methods) {
      if (info_upper.rfind(method, 0) == 0) http = true;
    }
    if (http) {
      ++http_summary_total;
      append_statistics_summary(root["httpSummaries"], frame_idx + 1, timestamp,
                                source, destination, protocol, info);
      const int http_status_value = field_index.integer( http_status, -1);
      if ((http_status_value >= 400 && http_status_value <= 599) ||
          (http_status_value < 0 && (info_upper.find("HTTP/1.0 4") != std::string::npos ||
          info_upper.find("HTTP/1.0 5") != std::string::npos ||
          info_upper.find("HTTP/1.1 4") != std::string::npos ||
          info_upper.find("HTTP/1.1 5") != std::string::npos ||
          info_upper.find("HTTP/2 4") != std::string::npos ||
          info_upper.find("HTTP/2 5") != std::string::npos))) {
        ++http_error_total;
        if (http_first_error_frame == 0) http_first_error_frame = frame_idx + 1;
      }
    }
    if (protocol_upper.find("TLS") != std::string::npos ||
        protocol_upper.find("SSL") != std::string::npos ||
        contains_case_insensitive(info, "TLS") ||
        contains_case_insensitive(info, "SSL") ||
        contains_case_insensitive(info, "SNI")) {
      ++tls_summary_total;
      append_statistics_summary(root["tlsSummaries"], frame_idx + 1, timestamp,
                                source, destination, protocol, info);
      std::string tls_alert_value;
      if (field_index.find( tls_alert, tls_alert_value) || contains_case_insensitive(info, "Alert")) {
        ++tls_alert_total;
        if (tls_first_alert_frame == 0) tls_first_alert_frame = frame_idx + 1;
      }
    }
    static const char *tcp_signals[] = {"retransmission", "duplicate ack",
                                        "dup ack", "reset", "rst",
                                        "out-of-order", "lost segment"};
    bool tcp_signal = false;
    if (protocol_upper == "TCP") {
      for (const char *signal : tcp_signals) {
        if (contains_case_insensitive(info, signal)) tcp_signal = true;
      }
    }
    if (tcp_signal) {
      ++tcp_summary_total;
      append_statistics_summary(root["tcpSummaries"], frame_idx + 1, timestamp,
                                source, destination, protocol, info);
    }
    }
    yield_to_interactive_reads(session);
  }

  root["packetCount"] = packet_count;
  root["byteCount"] = byte_count;
  root["capturedByteCount"] = captured_byte_count;
  root["truncatedPacketCount"] = truncated_packet_count;
  root["startTime"] = packet_count > 0 ? first_time : 0.0;
  root["endTime"] = packet_count > 0 ? last_time : 0.0;
  root["dnsAverageResponseMs"] = dns_response_time_count > 0 ?
      dns_response_time_sum * 1000.0 / dns_response_time_count : 0.0;
  root["dnsFailureTotal"] = dns_failure_total;
  root["dnsFirstFailureFrame"] = dns_first_failure_frame;
  root["dnsQueries"] = dns_queries;
  root["dnsResponses"] = dns_responses;
  root["dnsSummaryTotal"] = dns_summary_total;
  root["httpErrorTotal"] = http_error_total;
  root["httpFirstErrorFrame"] = http_first_error_frame;
  root["httpSummaryTotal"] = http_summary_total;
  root["tlsAlertTotal"] = tls_alert_total;
  root["tlsFirstAlertFrame"] = tls_first_alert_frame;
  root["tlsSummaryTotal"] = tls_summary_total;
  root["tcpSummaryTotal"] = tcp_summary_total;
  root["tcpSyn"] = tcp_syn;
  root["tcpSynAck"] = tcp_syn_ack;
  root["tcpRetransmissions"] = tcp_retransmissions;
  root["tcpDuplicateAcks"] = tcp_duplicate_acks;
  root["tcpResets"] = tcp_resets;
  root["tcpZeroWindows"] = tcp_zero_windows;
  root["tcpRttSamples"] = tcp_rtt_count;
  root["tcpAverageRttMs"] = tcp_rtt_count > 0 ? tcp_rtt_sum * 1000.0 / tcp_rtt_count : 0.0;
  auto map_to_json = [](const std::map<std::string, int> &values) {
    json object = json::object();
    for (const auto &entry : values) object[entry.first] = entry.second;
    return object;
  };
  root["tlsVersions"] = map_to_json(tls_versions);
  root["tlsSni"] = map_to_json(tls_sni_counts);
  root["httpStatusCodes"] = map_to_json(http_status_codes);
  root["httpHosts"] = map_to_json(http_hosts);
  root["dnsTopDomains"] = map_to_json(dns_top_domains);
  for (const auto &entry : protocols) {
    root["protocolHierarchy"].push_back(
        {{"name", entry.first},
         {"packetCount", entry.second.packets},
         {"byteCount", entry.second.bytes},
         {"packetPercent", packet_count > 0 ?
              entry.second.packets * 100.0 / packet_count : 0.0},
         {"bytePercent", byte_count > 0 ?
              entry.second.bytes * 100.0 / byte_count : 0.0}});
  }
  std::sort(root["protocolHierarchy"].begin(), root["protocolHierarchy"].end(),
            [](const json &a, const json &b) {
              int ap = a["packetCount"].get<int>();
              int bp = b["packetCount"].get<int>();
              return ap != bp ? ap > bp :
                     a["name"].get<std::string>() < b["name"].get<std::string>();
            });

  for (const auto &entry : conversations) {
    const auto &key = entry.first;
    const auto &value = entry.second;
    json item = {{"type", key.type}, {"endpointA", key.a.address},
                 {"endpointB", key.b.address}, {"packets", value.packets},
                 {"bytes", value.bytes}, {"startTime", value.start},
                 {"duration", std::max(0.0, value.last - value.start)},
                 {"aToBPackets", value.a_to_b},
                 {"bToAPackets", value.b_to_a}};
    item["portA"] = key.a.port >= 0 ? json(key.a.port) : json(nullptr);
    item["portB"] = key.b.port >= 0 ? json(key.b.port) : json(nullptr);
    root["conversations"].push_back(item);
  }
  for (const auto &entry : endpoints) {
    const auto &key = entry.first;
    const auto &value = entry.second;
    json item = {{"type", key.type}, {"address", key.address},
                 {"packets", value.packets}, {"bytes", value.bytes},
                 {"sentPackets", value.sent},
                 {"receivedPackets", value.received}};
    item["port"] = key.port >= 0 ? json(key.port) : json(nullptr);
    root["endpoints"].push_back(item);
  }

  std::map<int, std::pair<int, int64_t>> io_buckets;
  if (packet_count > 0) {
    for (const auto &point : timeline) {
      int index = static_cast<int>(std::floor(
          std::max(0.0, point.first - first_time) / bucket_seconds));
      auto &bucket = io_buckets[index];
      bucket.first++;
      bucket.second += point.second;
    }
  }
  for (const auto &entry : io_buckets) {
    double start = first_time + entry.first * bucket_seconds;
    root["ioGraph"].push_back({{"startTime", start},
                                {"endTime", start + bucket_seconds},
                                {"packets", entry.second.first},
                                {"bytes", entry.second.second}});
  }

  json length_buckets = json::array();
  for (int i = 0; i < 7; ++i) {
    length_buckets.push_back({{"label", length_labels[i]},
                              {"packets", length_packets[i]},
                              {"bytes", length_bytes[i]}});
  }
  root["packetLengths"] = {
      {"min", packet_count > 0 ? min_length : 0},
      {"max", max_length},
      {"average", packet_count > 0 ?
          static_cast<double>(byte_count) / packet_count : 0.0},
      {"totalBytes", byte_count}, {"buckets", length_buckets}};
  PERF_SCAN_LOG("buildStatistics frames=%d ms=%lld packets=%d conversations=%d endpoints=%d",
                static_cast<int>(visible_frames.size()), __perf_ms, packet_count,
                static_cast<int>(conversations.size()),
                static_cast<int>(endpoints.size()));
  return new_java_string(env, root.dump());
}
