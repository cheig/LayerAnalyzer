// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Statistics accumulator helpers shared by the statistics service and the
// debug perf export.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/projection/FieldReader.h"
#include "layanalyzer/analysis/StatisticsTypes.h"

bool statistics_peer_before(const StatisticsPeer &left,
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

void append_statistics_summary(json &array, int frame_number, double timestamp,
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
