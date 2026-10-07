// =============================================================================
// [PERF-export] G4 对拍导出（T0 基线任务交付物 d）
// Debug 构建专用：对当前会话依次导出过滤 / 四种搜索 / 统计 / Expert /
// Follow Stream / HTTP 对象 / 可见帧 pcap，供改动前后 diff -r 对拍。
// 逻辑逐段复刻对应 JNI 函数，保证"对拍对象"与真实功能路径一致。
// =============================================================================
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/ProtocolProjection.h"
#include "layanalyzer/projection/TreeFieldReader.h"
#include "layanalyzer/analysis/StatisticsLegacy.h"
#include "layanalyzer/stream/HttpObjectCallbacks.h"

#ifndef NDEBUG
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_exportPerfResults(JNIEnv *env,
                                                            jobject /* this */,
                                                            jlong sessionPtr,
                                                            jstring jOutputDir) {
  auto session = acquire_session(sessionPtr);
  json result = {{"success", false}, {"error", ""}, {"files", json::array()}};
  if (!session || !session->wth || !session->epan) {
    result["error"] = "No capture is open.";
    return new_java_string(env, result.dump());
  }
  const char *dirChars = env->GetStringUTFChars(jOutputDir, nullptr);
  std::string output_dir = dirChars ? dirChars : "";
  env->ReleaseStringUTFChars(jOutputDir, dirChars);
  if (output_dir.empty()) {
    result["error"] = "An output directory is required.";
    return new_java_string(env, result.dump());
  }
  if (output_dir.back() != '/') output_dir.push_back('/');
  mkdir(output_dir.c_str(), 0775);  // 已存在则忽略

  auto write_text = [&result, &output_dir](const std::string &name,
                                           const std::string &text) {
    std::string path = output_dir + name;
    FILE *f = fopen(path.c_str(), "wb");
    if (!f) {
      result["error"] = "Unable to write " + path;
      return false;
    }
    bool ok = fwrite(text.data(), 1, text.size(), f) == text.size();
    if (fclose(f) != 0) ok = false;
    if (!ok) result["error"] = "Failed writing " + path;
    return ok;
  };

  const int total_frames = static_cast<int>(session->frame_offsets.size());

  // ---- 1) 过滤器对拍：applyDisplayFilter("tcp") 的命中数 + 帧号列表 ----
  // 复刻 applyDisplayFilter 的编译 + 逐帧匹配路径（仅去掉取消检查）。
  const std::string filter_text = "tcp";
  dfilter_t *df = nullptr;
  gchar *df_err = nullptr;
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    if (!dfilter_compile(filter_text.c_str(), &df, &df_err)) {
      std::string err = df_err ? df_err : "invalid filter";
      g_free(df_err);
      result["error"] = "compile-filter: " + err;
      return new_java_string(env, result.dump());
    }
  }
  std::vector<int> filter_matches;
  for (int i = 0; i < total_frames; ++i) {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    DissectedFrame frame;
    if (dissect_frame(session, i, TRUE, FALSE, df, frame) &&
        (!df || dfilter_apply_edt(df, frame.edt))) {
      filter_matches.push_back(i);
    }
  }
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    dfilter_free(df);
  }
  {
    std::ostringstream out;
    out << "filter=" << filter_text << "\n";
    out << "matches=" << filter_matches.size() << "\n";
    for (int idx : filter_matches) out << (idx + 1) << "\n";
    if (!write_text("filter_tcp.txt", out.str())) {
      return new_java_string(env, result.dump());
    }
    result["files"].push_back("filter_tcp.txt");
  }

  // 提交过滤状态，让后续 search/expert/statistics/follow 在过滤后的可见集上
  // 运行（与 UI 中"先过滤再操作"的路径一致）。
  {
    std::unique_lock<std::shared_mutex> state_lock(session->state_mutex);
    session->active_filter = filter_text;
    session->filter_error.clear();
    session->filtered_frames = filter_matches;
  }

  // ---- 2) 搜索对拍：number / hex / field / text 四种模式 ----
  // 逐段复刻 searchPackets 各分支（去掉取消与代际检查）。
  struct SearchCase {
    const char *mode;
    const char *query;
  };
  const SearchCase search_cases[] = {
      {"number", "10"},
      {"hex", "0800"},
      {"field", "tcp.srcport"},
      {"text", "example"},
  };
  for (const auto &search_case : search_cases) {
    std::string mode = search_case.mode;
    std::string query = search_case.query;
    std::vector<int> visible_frames = snapshot_visible_frames(session);
    std::vector<int> hits;
    if (mode == "number") {
      int frameNumber = atoi(query.c_str());
      if (frameNumber > 0 && frameNumber <= total_frames &&
          std::find(visible_frames.begin(), visible_frames.end(),
                    frameNumber - 1) != visible_frames.end()) {
        hits.push_back(frameNumber);
      }
    } else {
      std::vector<guint8> hexNeedle =
          mode == "hex" ? parse_hex_query(query) : std::vector<guint8>();
      for (int frameIdx : visible_frames) {
        bool createTree = mode == "field";
        bool matched = false;
        {
          std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
          DissectedFrame frame;
          if (!dissect_frame(session, frameIdx, createTree, TRUE, nullptr,
                             frame)) {
            continue;
          }
          if (mode == "hex") {
            matched = bytes_contain(ws_buffer_start_ptr(&frame.buf),
                                    packet_data_length(&frame.rec, &frame.buf),
                                    hexNeedle);
          } else if (mode == "field") {
            matched = tree_contains_text(frame.edt->tree, query);
          } else {
            matched = contains_case_insensitive(
                frame_search_text(session, frameIdx, frame), query);
          }
        }
        if (matched) hits.push_back(frameIdx + 1);
      }
    }
    std::ostringstream out;
    out << "mode=" << mode << "\n";
    out << "query=" << query << "\n";
    out << "matches=" << hits.size() << "\n";
    for (int n : hits) out << n << "\n";
    std::string name = "search_" + mode + ".txt";
    if (!write_text(name, out.str())) {
      return new_java_string(env, result.dump());
    }
    result["files"].push_back(name);
  }

  // ---- 3) Expert Info 对拍：复刻 getExpertInfoSummary ----
  {
    json root;
    root["items"] = json::array();
    int warnings = 0;
    int errors = 0;
    int total_items = 0;
    std::vector<int> visible_frames = snapshot_visible_frames(session);
    for (int frameIdx : visible_frames) {
      json items = json::array();
      std::string highest = "none";
      {
        std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
        DissectedFrame frame;
        if (!dissect_frame(session, frameIdx, TRUE, FALSE, nullptr, frame))
          continue;
        if (collect_expert_nodes(frame.edt->tree, items, highest)) {
          if (highest == "error") errors++; else if (highest == "warn") warnings++;
          for (auto &item : items) {
            item["frameNumber"] = frameIdx + 1;
            total_items++;
            if (root["items"].size() < 5000) root["items"].push_back(item);
          }
        }
      }
    }
    root["warnings"] = warnings;
    root["errors"] = errors;
    root["totalItems"] = total_items;
    root["truncated"] = total_items > static_cast<int>(root["items"].size());
    if (!write_text("expert.json", root.dump(2))) {
      return new_java_string(env, result.dump());
    }
    result["files"].push_back("expert.json");
  }

  // ---- 4) 统计对拍：复刻 buildStatistics（bucket=1.0），完整 JSON ----
  {
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

    const double bucket_seconds = 1.0;
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
    auto increment_json_map = [](json &object, const std::string &key) {
      if (key.empty()) return;
      object[key] = object.contains(key) ? object[key].get<int>() + 1 : 1;
    };

    std::vector<int> visible_frames = snapshot_visible_frames(session);
    for (int frame_idx : visible_frames) {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      if (!dissect_frame(session, frame_idx, TRUE, TRUE, nullptr, frame)) continue;

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

      const int dns_response_value = parse_tree_integer(frame.edt->tree, dns_response_flag);
      const int dns_rcode_value = parse_tree_integer(frame.edt->tree, dns_rcode);
      const double dns_time_value = parse_tree_double(frame.edt->tree, dns_time);
      std::string dns_name_value;
      find_field_value(frame.edt->tree, dns_query_name, dns_name_value);
      const bool dns_frame = protocol_upper == "DNS" || dns_response_value >= 0 || !dns_name_value.empty();
      if (dns_frame) {
        if (dns_response_value > 0) {
          root["dnsResponses"] = root["dnsResponses"].get<int>() + 1;
          if (dns_time_value >= 0.0) {
            dns_response_time_sum += dns_time_value;
            dns_response_time_count++;
          }
          if (dns_rcode_value > 0) {
            root["dnsFailureTotal"] = root["dnsFailureTotal"].get<int>() + 1;
            if (root["dnsFirstFailureFrame"].get<int>() == 0) root["dnsFirstFailureFrame"] = frame_idx + 1;
          }
        } else {
          root["dnsQueries"] = root["dnsQueries"].get<int>() + 1;
        }
        increment_json_map(root["dnsTopDomains"], dns_name_value);
      }

      if (pinfo->ptype == PT_TCP) {
        const bool syn = find_boolean_field(frame.edt->tree, "tcp.flags.syn");
        const bool ack = find_boolean_field(frame.edt->tree, "tcp.flags.ack");
        if (syn && !ack) root["tcpSyn"] = root["tcpSyn"].get<int>() + 1;
        if (syn && ack) root["tcpSynAck"] = root["tcpSynAck"].get<int>() + 1;
        if (find_boolean_field(frame.edt->tree, "tcp.analysis.retransmission") || find_boolean_field(frame.edt->tree, "tcp.analysis.fast_retransmission")) root["tcpRetransmissions"] = root["tcpRetransmissions"].get<int>() + 1;
        if (find_boolean_field(frame.edt->tree, "tcp.analysis.duplicate_ack")) root["tcpDuplicateAcks"] = root["tcpDuplicateAcks"].get<int>() + 1;
        if (find_boolean_field(frame.edt->tree, "tcp.flags.reset")) root["tcpResets"] = root["tcpResets"].get<int>() + 1;
        const int window = parse_tree_integer(frame.edt->tree, tcp_window_size, -1);
        if (find_boolean_field(frame.edt->tree, "tcp.analysis.zero_window") || window == 0) root["tcpZeroWindows"] = root["tcpZeroWindows"].get<int>() + 1;
        const double rtt = parse_tree_double(frame.edt->tree, tcp_ack_rtt);
        if (rtt >= 0.0) {
          tcp_rtt_sum += rtt;
          tcp_rtt_count++;
        }
      }

      if (protocol_upper.find("TLS") != std::string::npos || protocol_upper.find("SSL") != std::string::npos) {
        std::string version;
        std::string sni;
        find_field_value(frame.edt->tree, tls_version, version);
        find_field_value(frame.edt->tree, tls_sni, sni);
        increment_json_map(root["tlsVersions"], version);
        increment_json_map(root["tlsSni"], sni);
      }

      std::string http_status_value;
      std::string http_host_value;
      find_field_value(frame.edt->tree, http_status, http_status_value);
      find_field_value(frame.edt->tree, http_host, http_host_value);
      if (!http_status_value.empty() || !http_host_value.empty()) {
        increment_json_map(root["httpStatusCodes"], http_status_value);
        increment_json_map(root["httpHosts"], http_host_value);
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
        root["dnsSummaryTotal"] = root["dnsSummaryTotal"].get<int>() + 1;
        append_statistics_summary(root["dnsSummaries"], frame_idx + 1, timestamp,
                                  source, destination, protocol, info);
        if (dns_response_value < 0 && (contains_case_insensitive(info, "NXDOMAIN") ||
            contains_case_insensitive(info, "SERVFAIL") ||
            contains_case_insensitive(info, "REFUSED") ||
            contains_case_insensitive(info, "No such name"))) {
          root["dnsFailureTotal"] = root["dnsFailureTotal"].get<int>() + 1;
          if (root["dnsFirstFailureFrame"].get<int>() == 0) root["dnsFirstFailureFrame"] = frame_idx + 1;
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
        root["httpSummaryTotal"] = root["httpSummaryTotal"].get<int>() + 1;
        append_statistics_summary(root["httpSummaries"], frame_idx + 1, timestamp,
                                  source, destination, protocol, info);
        const int http_status_int = parse_tree_integer(frame.edt->tree, http_status, -1);
        if ((http_status_int >= 400 && http_status_int <= 599) ||
            (http_status_int < 0 && (info_upper.find("HTTP/1.0 4") != std::string::npos ||
            info_upper.find("HTTP/1.0 5") != std::string::npos ||
            info_upper.find("HTTP/1.1 4") != std::string::npos ||
            info_upper.find("HTTP/1.1 5") != std::string::npos ||
            info_upper.find("HTTP/2 4") != std::string::npos ||
            info_upper.find("HTTP/2 5") != std::string::npos))) {
          root["httpErrorTotal"] = root["httpErrorTotal"].get<int>() + 1;
          if (root["httpFirstErrorFrame"].get<int>() == 0) root["httpFirstErrorFrame"] = frame_idx + 1;
        }
      }
      if (protocol_upper.find("TLS") != std::string::npos ||
          protocol_upper.find("SSL") != std::string::npos ||
          contains_case_insensitive(info, "TLS") ||
          contains_case_insensitive(info, "SSL") ||
          contains_case_insensitive(info, "SNI")) {
        root["tlsSummaryTotal"] = root["tlsSummaryTotal"].get<int>() + 1;
        append_statistics_summary(root["tlsSummaries"], frame_idx + 1, timestamp,
                                  source, destination, protocol, info);
        std::string tls_alert_value;
        if (find_field_value(frame.edt->tree, tls_alert, tls_alert_value) || contains_case_insensitive(info, "Alert")) {
          root["tlsAlertTotal"] = root["tlsAlertTotal"].get<int>() + 1;
          if (root["tlsFirstAlertFrame"].get<int>() == 0) root["tlsFirstAlertFrame"] = frame_idx + 1;
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
        root["tcpSummaryTotal"] = root["tcpSummaryTotal"].get<int>() + 1;
        append_statistics_summary(root["tcpSummaries"], frame_idx + 1, timestamp,
                                  source, destination, protocol, info);
      }
    }

    root["packetCount"] = packet_count;
    root["byteCount"] = byte_count;
    root["capturedByteCount"] = captured_byte_count;
    root["truncatedPacketCount"] = truncated_packet_count;
    root["startTime"] = packet_count > 0 ? first_time : 0.0;
    root["endTime"] = packet_count > 0 ? last_time : 0.0;
    root["dnsAverageResponseMs"] = dns_response_time_count > 0 ?
        dns_response_time_sum * 1000.0 / dns_response_time_count : 0.0;
    root["tcpRttSamples"] = tcp_rtt_count;
    root["tcpAverageRttMs"] = tcp_rtt_count > 0 ? tcp_rtt_sum * 1000.0 / tcp_rtt_count : 0.0;
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
    if (!write_text("statistics.json", root.dump(2))) {
      return new_java_string(env, result.dump());
    }
    result["files"].push_back("statistics.json");
  }
  // ---- 5) Follow Stream 对拍：tcp / udp 各取第一条流，复刻 followStream ----
  for (const char *proto : {"tcp", "udp"}) {
    const std::string stream_field = std::string(proto) + ".stream";
    const std::string payload_field = std::string(proto) + ".payload";
    json root;
    root["protocol"] = proto;
    root["records"] = json::array();
    std::string client;
    std::vector<int> visible_frames = snapshot_visible_frames(session);
    int stream_id = -1;
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      for (int frame_idx : visible_frames) {
        DissectedFrame frame;
        if (!dissect_frame(session, frame_idx, TRUE, FALSE, nullptr, frame))
          continue;
        int found = find_stream_id(frame.edt->tree, stream_field);
        if (found >= 0) {
          stream_id = found;
          break;
        }
      }
      if (stream_id < 0) {
        root["error"] = "No stream is available.";
      } else {
        root["streamId"] = stream_id;
        bool direction_known = false;
        if (std::string(proto) == "tcp") {
          for (int frame_idx : visible_frames) {
            DissectedFrame frame;
            if (!dissect_frame(session, frame_idx, TRUE, FALSE, nullptr,
                               frame) ||
                find_stream_id(frame.edt->tree, stream_field) != stream_id)
              continue;
            if (find_boolean_field(frame.edt->tree, "tcp.flags.syn") &&
                !find_boolean_field(frame.edt->tree, "tcp.flags.ack")) {
              packet_info *pinfo = &frame.edt->pi;
              client = address_text(&pinfo->src,
                                    session->name_resolution_enabled) +
                       ":" + std::to_string(pinfo->srcport);
              direction_known = true;
              break;
            }
          }
        }
        root["directionKnown"] = direction_known;
        for (int i : visible_frames) {
          DissectedFrame frame;
          if (!dissect_frame(session, i, TRUE, FALSE, nullptr, frame)) continue;
          if (find_stream_id(frame.edt->tree, stream_field) != stream_id)
            continue;
          packet_info *pinfo = &frame.edt->pi;
          std::string source =
              address_text(&pinfo->src, session->name_resolution_enabled) +
              ":" + std::to_string(pinfo->srcport);
          std::string dest =
              address_text(&pinfo->dst, session->name_resolution_enabled) +
              ":" + std::to_string(pinfo->destport);
          std::vector<guint8> bytes;
          bool hasPayload =
              append_payload_bytes(frame.edt->tree, payload_field, bytes);
          if (!hasPayload) {
            const guint8 *data = ws_buffer_start_ptr(&frame.buf);
            size_t length = packet_data_length(&frame.rec, &frame.buf);
            if (data && length > 0) bytes.assign(data, data + length);
          }
          json record;
          record["frameNumber"] = i + 1;
          record["direction"] =
              direction_known ? (source == client ? "client" : "server")
                              : "unknown";
          record["source"] = source;
          record["destination"] = dest;
          record["length"] = static_cast<int>(bytes.size());
          record["payload"] = hasPayload;
          record["ascii"] = bytes_to_ascii(bytes);
          record["text"] = bytes_to_utf8_text(bytes);
          record["hex"] = bytes_to_hex(bytes);
          root["records"].push_back(record);
        }
      }
    }
    std::string name = std::string("follow_stream_") + proto + ".json";
    if (!write_text(name, root.dump(2))) {
      return new_java_string(env, result.dump());
    }
    result["files"].push_back(name);
  }

  // ---- 6) HTTP 对象对拍：复刻 getHttpObjects ----
  {
    json root = {{"objects", json::array()}, {"error", ""}};
    std::unique_lock<std::mutex> object_lock(session->http_objects_mutex);
    clear_http_objects(session);
    register_eo_t *http_export = get_eo_by_name("http");
    if (!http_export) {
      root["error"] = "HTTP object export is not available in this build.";
    } else {
      export_object_gui_reset_cb export_reset = get_eo_reset_func(http_export);
      if (export_reset) export_reset();

      export_object_list_t object_list;
      object_list.add_entry = http_object_list_add_entry;
      object_list.get_entry = http_object_list_get_entry;
      object_list.gui_data = session;

      GString *tap_error = register_tap_listener(
          get_eo_tap_listener_name(http_export), &object_list, nullptr, 0,
          nullptr, get_eo_packet_func(http_export), nullptr, nullptr);
      if (tap_error) {
        root["error"] = tap_error->str ? tap_error->str : "tap error";
        g_string_free(tap_error, TRUE);
      } else {
        std::vector<int> visible_frames = snapshot_visible_frames(session);
        for (int frame_idx : visible_frames) {
          std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
          DissectedFrame frame;
          dissect_frame(session, frame_idx, TRUE, FALSE, nullptr, frame);
        }
        remove_tap_listener(&object_list);

        for (int index = 0;
             index < static_cast<int>(session->http_objects.size()); ++index) {
          export_object_entry_t *entry = session->http_objects[index];
          if (!entry) continue;
          std::string filename = entry->filename ? entry->filename : "";
          if (filename.empty()) {
            filename = "http-object-" + std::to_string(entry->pkt_num) + "-" +
                       std::to_string(index + 1);
          }
          root["objects"].push_back({
              {"id", index},
              {"frameNumber", entry->pkt_num},
              {"hostname", entry->hostname ? entry->hostname : ""},
              {"contentType", entry->content_type ? entry->content_type : ""},
              {"filename", filename},
              {"size", entry->payload_len},
          });
        }
      }
      clear_http_objects(session);
    }
    if (!write_text("http_objects.json", root.dump(2))) {
      return new_java_string(env, result.dump());
    }
    result["files"].push_back("http_objects.json");
  }

  // ---- 7) 可见帧 pcap 导出：复刻 exportVisibleCapture ----
  {
    std::vector<int> visible_frames = snapshot_visible_frames(session);
    if (visible_frames.empty()) {
      result["error"] = "export: no visible frames";
      return new_java_string(env, result.dump());
    }
    int first_index = visible_frames.front();
    int err = 0;
    gchar *err_info = nullptr;
    int first_encap = WTAP_ENCAP_UNKNOWN;
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      FrameRead first;
      if (!wtap_seek_read(session->wth, session->frame_offsets[first_index],
                          &first.rec, &first.buf, &err, &err_info)) {
        result["error"] = err_info ? err_info : "Unable to read first packet.";
        g_free(err_info);
        return new_java_string(env, result.dump());
      }
      prepare_packet_record(session->wth, &first.rec);
      first_encap = first.rec.rec_header.packet_header.pkt_encap;
    }
    int link_type = link_type_for_encapsulation(first_encap);
    if (link_type < 0) {
      result["error"] = "export: unsupported encapsulation";
      return new_java_string(env, result.dump());
    }
    uint32_t snapshot_length = wtap_snapshot_length(session->wth);
    if (snapshot_length == 0) snapshot_length = 65535;
    std::string pcap_path = output_dir + "visible.pcap";
    FILE *output = fopen(pcap_path.c_str(), "wb");
    if (!output) {
      result["error"] = "Unable to write " + pcap_path;
      return new_java_string(env, result.dump());
    }
    bool ok = write_le32(output, 0xa1b2c3d4u) && write_le16(output, 2) &&
              write_le16(output, 4) && write_le32(output, 0) &&
              write_le32(output, 0) && write_le32(output, snapshot_length) &&
              write_le32(output, static_cast<uint32_t>(link_type));
    int exported = 0;
    for (int frame_index : visible_frames) {
      if (!ok) break;
      std::vector<guint8> packet_bytes;
      guint captured_length = 0;
      guint original_length = 0;
      int64_t seconds = 0;
      int32_t micros = 0;
      err = 0;
      err_info = nullptr;
      {
        std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
        FrameRead frame;
        if (!wtap_seek_read(session->wth, session->frame_offsets[frame_index],
                            &frame.rec, &frame.buf, &err, &err_info)) {
          result["error"] = err_info ? err_info : "Unable to read a packet.";
          g_free(err_info);
          ok = false;
        } else {
          prepare_packet_record(session->wth, &frame.rec);
          captured_length = packet_data_length(&frame.rec, &frame.buf);
          original_length = frame.rec.rec_header.packet_header.len;
          const guint8 *data = ws_buffer_start_ptr(&frame.buf);
          if (data && captured_length > 0) {
            packet_bytes.assign(data, data + captured_length);
          }
          if (frame.rec.presence_flags & WTAP_HAS_TS) {
            seconds = std::max<int64_t>(0, frame.rec.ts.secs);
            micros = std::max<int32_t>(0, frame.rec.ts.nsecs / 1000);
          }
        }
      }
      if (!ok) break;
      ok = write_le32(output, static_cast<uint32_t>(seconds)) &&
           write_le32(output, static_cast<uint32_t>(micros)) &&
           write_le32(output, captured_length) &&
           write_le32(output, original_length) &&
           (captured_length == 0 ||
            fwrite(packet_bytes.data(), 1, captured_length, output) ==
                captured_length);
      if (ok) exported++;
    }
    if (fflush(output) != 0 || ferror(output)) ok = false;
    if (fclose(output) != 0) ok = false;
    if (!ok) {
      if (result["error"].get<std::string>().empty()) {
        result["error"] = "export: write failed";
      }
      return new_java_string(env, result.dump());
    }
    result["files"].push_back("visible.pcap");
    result["visibleFrames"] = exported;
  }

  result["success"] = true;
  result["totalFrames"] = total_frames;
  result["visibleFramesTotal"] =
      static_cast<int>(snapshot_visible_frames(session).size());
  LOGI("[PERF-export] exported %d files to %s",
       static_cast<int>(result["files"].size()), output_dir.c_str());
  return new_java_string(env, result.dump());
}
#endif  // !NDEBUG
