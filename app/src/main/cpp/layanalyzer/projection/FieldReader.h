#pragma once

// Shared projection helpers: cached packet-list summaries and the per-frame
// field index used by statistics, communication analysis and stream follow.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/session/CaptureSession.h"

// Lowercase/trim helpers shared across query and analysis services.
std::string lowercase_copy(const std::string &value);
std::string uppercase_copy(const std::string &value);
std::string trim_copy(const std::string &value);

// Case-insensitive substring check; allocates no copies on the hot path.
bool contains_case_insensitive(const std::string &text,
                               const std::string &needle);

bool is_unusable_protocol_label(const std::string &value);
std::string protocol_display_name_from_token(const std::string &token);
std::string resolve_protocol_label(packet_info *pinfo,
                                   const std::string &columnProtocol);

// Builds the cacheable packet-list row for an already-dissected frame.
bool populate_packet_summary(WiresharkSession *session, int frameIdx,
                             DissectedFrame &frame, CachedPacketSummary &summary);

// Dissects + projects a single frame, checking the summary cache first.
CachedPacketSummary get_or_build_packet_summary(WiresharkSession *session,
                                                int frameIdx);

// JSON row shape shared by paging and scoped queries.
void append_packet_summary_json(json &items, int frameIdx,
                                const CachedPacketSummary &summary);

std::string address_text(const address *addr, bool resolveNames);
std::string frame_search_text(WiresharkSession *session, int frameIdx,
                              DissectedFrame &frame);

std::string get_filter_value(field_info *finfo);

// Build a per-packet field index once.  Communication analysis used to call
// find_field_value()/collect_field_values() dozens of times for the same tree;
// each call recursively walked every proto_node and lower-cased every
// abbreviation again.  The index owns no Wireshark memory and is valid only
// for the current DissectedFrame scope.
struct FieldIndex {
  std::unordered_map<std::string, std::vector<field_info *>> values;

  explicit FieldIndex(proto_node *root) { visit(root); }

  bool find(const std::vector<std::string> &names, std::string &value) const;
  void collect(const std::vector<std::string> &names,
               std::vector<std::string> &out, size_t limit = 64) const;
  int integer(const std::vector<std::string> &names, int fallback = -1) const;
  int64_t uint64(const std::vector<std::string> &names,
                 int64_t fallback = -1) const;
  double real(const std::vector<std::string> &names,
              double fallback = -1.0) const;
  bool boolean(const std::vector<std::string> &names, bool &value) const;
  bool boolean(const char *name) const;

 private:
  void visit(proto_node *node);
};

// Recursive-tree field readers kept for callers without a FieldIndex.
bool find_field_value(proto_node *node,
                      const std::vector<std::string> &field_names,
                      std::string &value);
int parse_tree_integer(proto_node *node,
                       const std::vector<std::string> &field_names,
                       int fallback = -1);
double parse_tree_double(proto_node *node,
                         const std::vector<std::string> &field_names,
                         double fallback = -1.0);

// Text/hex/tree search helpers.
bool tree_contains_text(proto_node *node, const std::string &needle);
std::vector<guint8> parse_hex_query(const std::string &query);
bool bytes_contain(const guint8 *data, size_t length,
                   const std::vector<guint8> &needle);

// Expert-info severity mapping shared by detail and expert services.
std::string severity_from_flags(guint32 flags);
int severity_rank(const std::string &value);

// Stream-follow helpers.
int find_stream_id(proto_node *node, const std::string &fieldName);
bool find_boolean_field(proto_node *node, const std::string &fieldName);
bool append_payload_bytes(proto_node *node, const std::string &fieldName,
                          std::vector<guint8> &bytes);

// RAW-IP/Ethernet protocol inference for rows whose columns carry no usable
// protocol label.
std::string infer_protocol_from_packet(int encap, Buffer *buffer,
                                       guint capturedLen);
