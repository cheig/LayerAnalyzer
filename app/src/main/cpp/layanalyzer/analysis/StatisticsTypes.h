#pragma once

// Statistics accumulator types shared by the statistics service and the
// debug perf export (until the export is fully service-composed).

#include "layanalyzer/internal/Common.h"

struct StatisticsPeer {
  std::string address;
  int port = -1;
};

struct StatisticsConversationKey {
  std::string type;
  StatisticsPeer a;
  StatisticsPeer b;

  bool operator<(const StatisticsConversationKey &other) const {
    return std::tie(type, a.address, a.port, b.address, b.port) <
           std::tie(other.type, other.a.address, other.a.port,
                    other.b.address, other.b.port);
  }
};

struct StatisticsConversationValue {
  int packets = 0;
  int64_t bytes = 0;
  double start = 0.0;
  double last = 0.0;
  int a_to_b = 0;
  int b_to_a = 0;
};

struct StatisticsEndpointKey {
  std::string type;
  std::string address;
  int port = -1;

  bool operator<(const StatisticsEndpointKey &other) const {
    return std::tie(type, address, port) <
           std::tie(other.type, other.address, other.port);
  }
};

struct StatisticsEndpointValue {
  int packets = 0;
  int64_t bytes = 0;
  int sent = 0;
  int received = 0;
};

struct StatisticsProtocolValue {
  int packets = 0;
  int64_t bytes = 0;
};

bool statistics_peer_before(const StatisticsPeer &left,
                            const StatisticsPeer &right);
void add_statistics_conversation(
    std::map<StatisticsConversationKey, StatisticsConversationValue> &values,
    const std::string &type, StatisticsPeer source, StatisticsPeer destination,
    int length, double timestamp);
void add_statistics_endpoint(
    std::map<StatisticsEndpointKey, StatisticsEndpointValue> &values,
    const std::string &type, const std::string &address, int port, int length,
    bool sent);
void append_statistics_summary(json &array, int frame_number, double timestamp,
                               const std::string &source,
                               const std::string &destination,
                               const std::string &protocol,
                               const std::string &summary);
