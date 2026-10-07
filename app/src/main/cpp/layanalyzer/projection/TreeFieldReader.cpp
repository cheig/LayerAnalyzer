// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Protocol-tree field reader implementation shared by every consumer of
// Wireshark protocol trees.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/projection/TreeFieldReader.h"

std::string get_node_text(field_info *finfo) {
  if (!finfo)
    return "";
  if (finfo->rep) {
    return std::string(finfo->rep->representation);
  }
  if (!finfo->hfinfo) {
    return "";
  }
  gchar label[ITEM_LABEL_LENGTH] = {0};
  proto_item_fill_label(finfo, label);
  return label[0] != '\0' ? std::string(label) : "";
}

std::string get_filter_value(field_info *finfo) {
  if (!finfo || !finfo->hfinfo) {
    return "";
  }
  // Tree serialization runs after epan_dissect_run() has left its packet
  // scope. Allocate independently, copy the representation, then free it as
  // done by Wireshark's own wslua_field implementation.
  char *repr = fvalue_to_string_repr(
      nullptr, &finfo->value, FTREPR_DFILTER,
      FIELD_DISPLAY(finfo->hfinfo->display));
  if (!repr) return "";
  std::string value(repr);
  wmem_free(nullptr, repr);
  return value;
}

bool find_field_value(proto_node *node,
                      const std::vector<std::string> &field_names,
                      std::string &value) {
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev) {
      std::string abbrev = lowercase_copy(finfo->hfinfo->abbrev);
      if (std::find(field_names.begin(), field_names.end(), abbrev) != field_names.end()) {
        value = get_filter_value(finfo);
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
          value = value.substr(1, value.size() - 2);
        }
        return true;
      }
    }
    if (find_field_value(current, field_names, value)) return true;
  }
  return false;
}

void collect_field_values(proto_node *node,
                          const std::vector<std::string> &field_names,
                          std::vector<std::string> &values,
                          size_t limit) {
  if (!node || values.size() >= limit) return;
  for (proto_node *current = node->first_child; current && values.size() < limit;
       current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev) {
      std::string abbrev = lowercase_copy(finfo->hfinfo->abbrev);
      if (std::find(field_names.begin(), field_names.end(), abbrev) != field_names.end()) {
        std::string value = get_filter_value(finfo);
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
          value = value.substr(1, value.size() - 2);
        }
        if (!value.empty() && std::find(values.begin(), values.end(), value) == values.end()) {
          values.push_back(value);
        }
      }
    }
    collect_field_values(current, field_names, values, limit);
  }
}

int parse_tree_integer(proto_node *node,
                       const std::vector<std::string> &field_names,
                       int fallback) {
  std::string value;
  if (!find_field_value(node, field_names, value)) return fallback;
  char *end = nullptr;
  unsigned long parsed = strtoul(value.c_str(), &end, 0);
  if (end == value.c_str()) return fallback;
  return static_cast<int>(parsed);
}

int64_t parse_tree_uint64(proto_node *node,
                          const std::vector<std::string> &field_names,
                          int64_t fallback) {
  std::string value;
  if (!find_field_value(node, field_names, value)) return fallback;
  char *end = nullptr;
  unsigned long long parsed = strtoull(value.c_str(), &end, 0);
  if (end == value.c_str()) return fallback;
  return static_cast<int64_t>(parsed);
}

bool parse_tree_boolean(proto_node *node,
                        const std::vector<std::string> &field_names,
                        bool &value) {
  std::string raw;
  if (!find_field_value(node, field_names, raw)) return false;
  const std::string normalized = lowercase_copy(trim_copy(raw));
  value = normalized != "0" && normalized != "false" &&
          normalized != "unset" && normalized != "not set" &&
          normalized != "not present" &&
          normalized.find("not set") == std::string::npos &&
          normalized.find("not present") == std::string::npos &&
          normalized.find("false") == std::string::npos;
  return true;
}

double parse_tree_double(proto_node *node,
                         const std::vector<std::string> &field_names,
                         double fallback) {
  std::string value;
  if (!find_field_value(node, field_names, value)) return fallback;
  char *end = nullptr;
  double parsed = strtod(value.c_str(), &end);
  return end == value.c_str() ? fallback : parsed;
}
