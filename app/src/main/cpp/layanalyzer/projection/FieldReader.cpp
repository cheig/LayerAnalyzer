// Projection: per-frame field access.  FieldIndex walks a protocol tree once;
// the recursive find_field_value/parse_tree_* readers remain for callers that
// do not have an index.  get_filter_value() is the single fvalue -> string
// projection used everywhere.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/projection/FieldReader.h"

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

bool FieldIndex::find(const std::vector<std::string> &names,
                      std::string &value) const {
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

void FieldIndex::collect(const std::vector<std::string> &names,
                         std::vector<std::string> &out, size_t limit) const {
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

int FieldIndex::integer(const std::vector<std::string> &names,
                        int fallback) const {
  std::string value;
  if (!find(names, value)) return fallback;
  char *end = nullptr;
  const unsigned long parsed = strtoul(value.c_str(), &end, 0);
  return end == value.c_str() ? fallback : static_cast<int>(parsed);
}

int64_t FieldIndex::uint64(const std::vector<std::string> &names,
                           int64_t fallback) const {
  std::string value;
  if (!find(names, value)) return fallback;
  char *end = nullptr;
  const unsigned long long parsed = strtoull(value.c_str(), &end, 0);
  return end == value.c_str() ? fallback : static_cast<int64_t>(parsed);
}

double FieldIndex::real(const std::vector<std::string> &names,
                        double fallback) const {
  std::string value;
  if (!find(names, value)) return fallback;
  char *end = nullptr;
  const double parsed = strtod(value.c_str(), &end);
  return end == value.c_str() ? fallback : parsed;
}

bool FieldIndex::boolean(const std::vector<std::string> &names,
                         bool &value) const {
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

bool FieldIndex::boolean(const char *name) const {
  bool value = false;
  if (!name) return false;
  return boolean(std::vector<std::string>{name}, value) && value;
}

void FieldIndex::visit(proto_node *node) {
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

double parse_tree_double(proto_node *node,
                         const std::vector<std::string> &field_names,
                         double fallback) {
  std::string value;
  if (!find_field_value(node, field_names, value)) return fallback;
  char *end = nullptr;
  double parsed = strtod(value.c_str(), &end);
  return end == value.c_str() ? fallback : parsed;
}

bool tree_contains_text(proto_node *node, const std::string &needle) {
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo) {
      std::string label = finfo->rep ? finfo->rep->representation : "";
      std::string abbrev = (finfo->hfinfo && finfo->hfinfo->abbrev) ? finfo->hfinfo->abbrev : "";
      std::string name = (finfo->hfinfo && finfo->hfinfo->name) ? finfo->hfinfo->name : "";
      std::string value = get_filter_value(finfo);
      if (contains_case_insensitive(label, needle) ||
          contains_case_insensitive(abbrev, needle) ||
          contains_case_insensitive(name, needle) ||
          contains_case_insensitive(value, needle)) {
        return true;
      }
    }
    if (tree_contains_text(current, needle)) return true;
  }
  return false;
}

std::vector<guint8> parse_hex_query(const std::string &query) {
  auto hex_value = [](unsigned char value) -> int {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
  };
  std::vector<guint8> bytes;
  bytes.reserve(query.size() / 2);
  int high_nibble = -1;
  for (unsigned char value : query) {
    const int nibble = hex_value(value);
    if (nibble < 0) continue;
    if (high_nibble < 0) {
      high_nibble = nibble;
    } else {
      bytes.push_back(static_cast<guint8>((high_nibble << 4) | nibble));
      high_nibble = -1;
    }
  }
  // An unmatched nibble is not a valid byte query. Returning an empty needle
  // preserves the existing "no match" contract without partial matches.
  if (high_nibble >= 0) bytes.clear();
  return bytes;
}

bool bytes_contain(const guint8 *data, size_t length,
                   const std::vector<guint8> &needle) {
  if (!data || needle.empty() || needle.size() > length) return false;
  for (size_t i = 0; i <= length - needle.size(); ++i) {
    if (memcmp(data + i, needle.data(), needle.size()) == 0) return true;
  }
  return false;
}

std::string severity_from_flags(guint32 flags) {
  switch (flags & PI_SEVERITY_MASK) {
    case PI_ERROR: return "error";
    case PI_WARN: return "warn";
    case PI_NOTE: return "note";
    default: return "none";
  }
}

int severity_rank(const std::string &value) {
  if (value == "error") return 3;
  if (value == "warn") return 2;
  if (value == "note") return 1;
  return 0;
}

int find_stream_id(proto_node *node, const std::string &fieldName) {
  if (!node) return -1;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev &&
        fieldName == finfo->hfinfo->abbrev) {
      ftenum_t type = fvalue_type_ftenum(&finfo->value);
      if (type == FT_UINT8 || type == FT_UINT16 || type == FT_UINT24 ||
          type == FT_UINT32) {
        return static_cast<int>(fvalue_get_uinteger(&finfo->value));
      }
      if (type == FT_UINT64) {
        return static_cast<int>(fvalue_get_uinteger64(&finfo->value));
      }
      if (finfo->rep) {
        const char *text = finfo->rep->representation;
        const char *colon = strrchr(text, ':');
        if (colon) return atoi(colon + 1);
      }
    }
    int childValue = find_stream_id(current, fieldName);
    if (childValue >= 0) return childValue;
  }
  return -1;
}

bool find_boolean_field(proto_node *node, const std::string &fieldName) {
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev &&
        fieldName == finfo->hfinfo->abbrev) {
      ftenum_t type = fvalue_type_ftenum(&finfo->value);
      if (type == FT_NONE) return true;
      if (type == FT_BOOLEAN) {
        // Wireshark stores FT_BOOLEAN in the 64-bit integer slot; the 32-bit accessor aborts.
        return fvalue_get_uinteger64(&finfo->value) != 0;
      }
      if (type == FT_UINT8 || type == FT_UINT16 || type == FT_UINT24 ||
          type == FT_UINT32) {
        return fvalue_get_uinteger(&finfo->value) != 0;
      }
      if (type == FT_UINT64) return fvalue_get_uinteger64(&finfo->value) != 0;
      return true;
    }
    if (find_boolean_field(current, fieldName)) return true;
  }
  return false;
}

bool append_payload_bytes(proto_node *node, const std::string &fieldName,
                          std::vector<guint8> &bytes) {
  bool found = false;
  if (!node) return false;
  for (proto_node *current = node->first_child; current; current = current->next) {
    field_info *finfo = PITEM_FINFO(current);
    if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev &&
        fieldName == finfo->hfinfo->abbrev && finfo->ds_tvb &&
        finfo->start >= 0 && finfo->length > 0) {
      const guint8 *ptr = tvb_get_ptr(finfo->ds_tvb, finfo->start, finfo->length);
      if (ptr) {
        bytes.insert(bytes.end(), ptr, ptr + finfo->length);
        found = true;
      }
    }
    if (append_payload_bytes(current, fieldName, bytes)) found = true;
  }
  return found;
}
