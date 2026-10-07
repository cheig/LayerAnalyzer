// Projection helpers that turn a dissected frame into value-typed data for
// the packet list, search, analysis and stream modules. These helpers were
// file-local statics in the former single translation unit.
#pragma once
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/TreeFieldReader.h"

bool is_unusable_protocol_label(const std::string &value);
std::string resolve_protocol_label(packet_info *pinfo,
                                   const std::string &columnProtocol);

/** Project one already-dissected frame into the cacheable packet-list row. */
bool populate_packet_summary(WiresharkSession *session, int frameIdx,
                             DissectedFrame &frame,
                             CachedPacketSummary &summary);
CachedPacketSummary get_or_build_packet_summary(WiresharkSession *session,
                                                int frameIdx);
void append_packet_summary_json(json &items, int frameIdx,
                                const CachedPacketSummary &summary);

std::string address_text(const address *addr, bool resolveNames);
std::string frame_search_text(WiresharkSession *session, int frameIdx,
                              DissectedFrame &frame);

bool tree_contains_text(proto_node *node, const std::string &needle);
std::vector<guint8> parse_hex_query(const std::string &query);
bool bytes_contain(const guint8 *data, size_t length,
                   const std::vector<guint8> &needle);

std::string severity_from_flags(guint32 flags);
int severity_rank(const std::string &value);
bool collect_expert_nodes(proto_node *node, json &items,
                          std::string &highest);

int find_stream_id(proto_node *node, const std::string &fieldName);
bool find_boolean_field(proto_node *node, const std::string &fieldName);
bool append_payload_bytes(proto_node *node, const std::string &fieldName,
                          std::vector<guint8> &bytes);
