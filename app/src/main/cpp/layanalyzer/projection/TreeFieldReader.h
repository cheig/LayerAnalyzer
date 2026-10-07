// Protocol-tree field readers shared by the detail, list, analysis and
// communication modules. These helpers were file-local statics in the former
// single translation unit.
#pragma once
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/TextUtils.h"

std::string get_node_text(field_info *finfo);
std::string get_filter_value(field_info *finfo);

bool find_field_value(proto_node *node,
                      const std::vector<std::string> &field_names,
                      std::string &value);
void collect_field_values(proto_node *node,
                          const std::vector<std::string> &field_names,
                          std::vector<std::string> &values,
                          size_t limit = 64);
int parse_tree_integer(proto_node *node,
                       const std::vector<std::string> &field_names,
                       int fallback = -1);
int64_t parse_tree_uint64(proto_node *node,
                          const std::vector<std::string> &field_names,
                          int64_t fallback = -1);
bool parse_tree_boolean(proto_node *node,
                        const std::vector<std::string> &field_names,
                        bool &value);
double parse_tree_double(proto_node *node,
                         const std::vector<std::string> &field_names,
                         double fallback = -1.0);

// Build a per-packet field index once.  Communication analysis used to call
// find_field_value()/collect_field_values() dozens of times for the same tree;
// each call recursively walked every proto_node and lower-cased every
// abbreviation again.  The index owns no Wireshark memory and is valid only
// for the current DissectedFrame scope.
struct FieldIndex {
  std::unordered_map<std::string, std::vector<field_info *>> values;

  explicit FieldIndex(proto_node *root) { visit(root); }

  bool find(const std::vector<std::string> &names, std::string &value) const {
    for (const std::string &name : names) {
      auto found = values.find(lowercase_copy(name));
      if (found == values.end()) continue;
      for (field_info *field : found->second) {
        std::string candidate = get_filter_value(field);
        if (candidate.size() >= 2 && candidate.front() == '"' &&
            candidate.back() == '"') {
          candidate = candidate.substr(1, candidate.size() - 2);
        }
        if (!candidate.empty()) {
          value = std::move(candidate);
          return true;
        }
      }
    }
    return false;
  }

  void collect(const std::vector<std::string> &names,
               std::vector<std::string> &out, size_t limit = 64) const {
    if (out.size() >= limit) return;
    for (const std::string &name : names) {
      auto found = values.find(lowercase_copy(name));
      if (found == values.end()) continue;
      for (field_info *field : found->second) {
        std::string candidate = get_filter_value(field);
        if (candidate.size() >= 2 && candidate.front() == '"' &&
            candidate.back() == '"') {
          candidate = candidate.substr(1, candidate.size() - 2);
        }
        if (!candidate.empty() &&
            std::find(out.begin(), out.end(), candidate) == out.end()) {
          out.push_back(std::move(candidate));
          if (out.size() >= limit) return;
        }
      }
    }
  }

  int integer(const std::vector<std::string> &names, int fallback = -1) const {
    std::string value;
    if (!find(names, value)) return fallback;
    char *end = nullptr;
    const unsigned long parsed = strtoul(value.c_str(), &end, 0);
    return end == value.c_str() ? fallback : static_cast<int>(parsed);
  }

  int64_t uint64(const std::vector<std::string> &names,
                 int64_t fallback = -1) const {
    std::string value;
    if (!find(names, value)) return fallback;
    char *end = nullptr;
    const unsigned long long parsed = strtoull(value.c_str(), &end, 0);
    return end == value.c_str() ? fallback : static_cast<int64_t>(parsed);
  }

  double real(const std::vector<std::string> &names,
              double fallback = -1.0) const {
    std::string value;
    if (!find(names, value)) return fallback;
    char *end = nullptr;
    const double parsed = strtod(value.c_str(), &end);
    return end == value.c_str() ? fallback : parsed;
  }

  bool boolean(const std::vector<std::string> &names, bool &value) const {
    for (const std::string &name : names) {
      auto found = values.find(lowercase_copy(name));
      if (found == values.end()) continue;
      for (field_info *field : found->second) {
        const ftenum_t type = fvalue_type_ftenum(&field->value);
        if (type == FT_NONE) {
          value = true;
          return true;
        }
        if (type == FT_BOOLEAN) {
          value = fvalue_get_uinteger64(&field->value) != 0;
          return true;
        }
        if (type == FT_UINT8 || type == FT_UINT16 || type == FT_UINT24 ||
            type == FT_UINT32) {
          value = fvalue_get_uinteger(&field->value) != 0;
          return true;
        }
        if (type == FT_UINT64) {
          value = fvalue_get_uinteger64(&field->value) != 0;
          return true;
        }
        value = true;
        return true;
      }
    }
    return false;
  }

  bool boolean(const char *name) const {
    bool value = false;
    if (!name) return false;
    return boolean(std::vector<std::string>{name}, value) && value;
  }

 private:
  void visit(proto_node *node) {
    if (!node) return;
    for (proto_node *current = node->first_child; current;
         current = current->next) {
      field_info *field = PITEM_FINFO(current);
      if (field && field->hfinfo && field->hfinfo->abbrev) {
        values[lowercase_copy(field->hfinfo->abbrev)].push_back(field);
      }
      visit(current);
    }
  }
};
