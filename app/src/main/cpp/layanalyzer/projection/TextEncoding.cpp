// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Charset-aware conversion of captured bytes into UTF-8 for display (P2-1).
// See TextEncoding.h for why this lives on the projection side.
#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/projection/TextEncoding.h"

// Wireshark's own converters. They are WS_DLL_PUBLIC, already linked into the
// engine, and they implement the Unicode 5.22 U+FFFD substitution rule, so the
// replacement behaviour matches Wireshark's own displays instead of glib's
// g_utf8_make_valid(). Passing a null wmem scope makes them use g_malloc /
// g_free, which is what fvalue_to_string_repr() already does in this codebase.
#include <epan/charsets.h>

namespace layanalyzer::projection {
namespace {

// Fail-closed guard: a protocol label is never a megabyte, so anything larger
// is treated as binary rather than decoded.
constexpr std::size_t kMaxConvertBytes = 1u << 20;

constexpr const char kUndecodable[] = "\xEF\xBF\xBD";  // U+FFFD

std::size_t count_undecodable(const std::string &utf8) {
  std::size_t count = 0;
  for (std::size_t pos = utf8.find(kUndecodable); pos != std::string::npos;
       pos = utf8.find(kUndecodable, pos + sizeof(kUndecodable) - 1)) {
    ++count;
  }
  return count;
}

/** Decodes with one charset; empty when the charset is unusable here. */
std::string decode_with(TextCharset charset, const guint8 *bytes,
                        std::size_t length) {
  if (!bytes || length == 0 || length > static_cast<std::size_t>(G_MAXINT)) {
    return std::string();
  }
  const gint size = static_cast<gint>(length);
  guint8 *converted = nullptr;
  switch (charset) {
    case TextCharset::kUtf8:
      converted = get_utf_8_string(nullptr, bytes, size);
      break;
    case TextCharset::kGb18030:
      converted = get_gb18030_string(nullptr, bytes, size);
      break;
    case TextCharset::kEucKr:
      converted = get_euc_kr_string(nullptr, bytes, size);
      break;
    case TextCharset::kIso8859_1:
      converted = get_8859_1_string(nullptr, bytes, size);
      break;
    case TextCharset::kUtf16Le:
      converted = get_utf_16_string(nullptr, bytes, size, ENC_LITTLE_ENDIAN);
      break;
    case TextCharset::kUtf16Be:
      converted = get_utf_16_string(nullptr, bytes, size, ENC_BIG_ENDIAN);
      break;
    case TextCharset::kAuto:
    default:
      return std::string();
  }
  if (!converted) return std::string();
  // The converters return a NUL-terminated buffer; embedded NULs therefore
  // truncate, which is the same behaviour the preview strings had before.
  std::string result(reinterpret_cast<const char *>(converted));
  wmem_free(nullptr, converted);
  return result;
}

/** Last resort: keep the bytes that are valid, replace the rest (P0-1). */
std::string sanitize(const char *data, std::size_t length) {
  if (!data || length == 0) return std::string();
  if (length > static_cast<std::size_t>(G_MAXINT)) return std::string();
  guint8 *converted = get_utf_8_string(
      nullptr, reinterpret_cast<const guint8 *>(data),
      static_cast<gint>(length));
  if (!converted) return std::string();
  std::string result(reinterpret_cast<const char *>(converted));
  wmem_free(nullptr, converted);
  return result;
}

/**
 * Payload that is not text at all: TCP headers, compressed bodies. Judged by
 * the share of C0 control bytes, which text encodings almost never carry.
 */
bool looks_binary(const guint8 *bytes, std::size_t length) {
  if (!bytes || length == 0) return false;
  std::size_t controls = 0;
  for (std::size_t index = 0; index < length; ++index) {
    const guint8 value = bytes[index];
    if (value == '\t' || value == '\n' || value == '\r') continue;
    if (value < 0x20) ++controls;
  }
  return controls * 10 >= length;
}

/** Replaces each U+FFFD with '.', the preview marker used for binary payloads. */
std::string dots_for_replacements(const std::string &utf8) {
  std::string out;
  out.reserve(utf8.size());
  for (std::size_t index = 0; index < utf8.size(); ++index) {
    if (utf8.compare(index, sizeof(kUndecodable) - 1, kUndecodable) == 0) {
      out.push_back('.');
      index += sizeof(kUndecodable) - 2;
      continue;
    }
    out.push_back(utf8[index]);
  }
  return out;
}

std::string convert(const char *data, std::size_t length,
                    const CharsetProvider &hint) {
  if (!data || length == 0) return std::string();
  if (length > kMaxConvertBytes) return sanitize(data, length);
  const auto *bytes = reinterpret_cast<const guint8 *>(data);

  // 1) A UTF-16 BOM is unambiguous. UTF-32LE (FF FE 00 00) is deliberately
  //    excluded and falls through: it is not a web text encoding.
  if (length >= 2) {
    const bool utf32_le =
        length >= 4 && bytes[0] == 0xFF && bytes[1] == 0xFE &&
        bytes[2] == 0x00 && bytes[3] == 0x00;
    if (!utf32_le && bytes[0] == 0xFF && bytes[1] == 0xFE) {
      const std::string decoded =
          decode_with(TextCharset::kUtf16Le, bytes, length);
      if (!decoded.empty()) return decoded;
    } else if (bytes[0] == 0xFE && bytes[1] == 0xFF) {
      const std::string decoded =
          decode_with(TextCharset::kUtf16Be, bytes, length);
      if (!decoded.empty()) return decoded;
    }
  }

  // 2) The declared charset, when the packet carries one. Only trusted if it
  //    decodes cleanly -- a stale or wrong charset= must not make things worse.
  const TextCharset declared = hint ? hint() : TextCharset::kAuto;
  if (declared != TextCharset::kAuto && declared != TextCharset::kUtf8) {
    const std::string decoded = decode_with(declared, bytes, length);
    if (!decoded.empty() && count_undecodable(decoded) == 0) return decoded;
  }

  // 3) Binary payloads (TCP headers, compressed bodies) must not be guessed
  //    into CJK: GB18030 accepts nearly any byte pair, so a header would decode
  //    "cleanly" into nonsense. '.' is the established marker for "not text".
  if (looks_binary(bytes, length)) {
    return dots_for_replacements(sanitize(data, length));
  }

  // 4) Heuristic. GB18030 is the GBK/GB2312 superset and by far the most
  //    common non-UTF-8 encoding in Chinese captures, so it wins ties; EUC-KR
  //    is the only other multi-byte encoding the engine can decode. Keep
  //    whichever leaves fewer undecodable sequences than raw replacement.
  std::string fallback = sanitize(data, length);
  std::size_t best_bad = count_undecodable(fallback);
  std::string best;
  static constexpr TextCharset kCandidates[] = {TextCharset::kGb18030,
                                               TextCharset::kEucKr};
  for (const TextCharset candidate : kCandidates) {
    if (best_bad == 0) break;
    std::string decoded = decode_with(candidate, bytes, length);
    if (decoded.empty()) continue;
    const std::size_t bad = count_undecodable(decoded);
    if (bad < best_bad) {
      best_bad = bad;
      best = std::move(decoded);
    }
  }
  if (!best.empty()) return best;

  // 5) Nothing decoded better than replacement: Big5, Shift-JIS and friends.
  return fallback;
}

}  // namespace

TextCharset charset_from_label(const std::string &label) {
  std::string name = lowercase_copy(trim_copy(label));
  if (name.size() >= 2) {
    const char first = name.front();
    const char last = name.back();
    if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
      name = trim_copy(name.substr(1, name.size() - 2));
    }
  }
  if (name.empty()) return TextCharset::kAuto;

  if (name == "utf-8" || name == "utf8" || name == "us-ascii" ||
      name == "ascii") {
    return TextCharset::kUtf8;
  }
  if (name == "gbk" || name == "gb2312" || name == "gb-2312" ||
      name == "gb_2312-80" || name == "gb18030" || name == "cp936" ||
      name == "ms936" || name == "x-gbk" || name == "euc-cn" ||
      name == "csgb2312") {
    return TextCharset::kGb18030;
  }
  if (name == "euc-kr" || name == "euckr" || name == "ks_c_5601-1987" ||
      name == "cp949" || name == "uhc") {
    return TextCharset::kEucKr;
  }
  if (name == "iso-8859-1" || name == "iso8859-1" || name == "iso_8859-1" ||
      name == "latin1" || name == "latin-1") {
    return TextCharset::kIso8859_1;
  }
  if (name == "utf-16" || name == "utf16" || name == "utf-16le" ||
      name == "ucs-2" || name == "ucs2") {
    return TextCharset::kUtf16Le;
  }
  if (name == "utf-16be") return TextCharset::kUtf16Be;

  // Big5, Shift-JIS, ...: the engine ships no table for these, so they keep the
  // U+FFFD behaviour instead of a wrong decode.
  return TextCharset::kAuto;
}

TextCharset charset_from_content_type(const std::string &content_type) {
  if (content_type.empty()) return TextCharset::kAuto;
  const std::string lower = lowercase_copy(content_type);
  const auto is_space = [](char c) { return c == ' ' || c == '\t'; };

  for (std::size_t pos = lower.find("charset"); pos != std::string::npos;
       pos = lower.find("charset", pos + 7)) {
    std::size_t cursor = pos + 7;
    while (cursor < lower.size() && is_space(lower[cursor])) ++cursor;
    if (cursor >= lower.size() || lower[cursor] != '=') continue;
    ++cursor;
    while (cursor < lower.size() && is_space(lower[cursor])) ++cursor;
    std::size_t end = cursor;
    while (end < lower.size() && lower[end] != ';' && lower[end] != ' ' &&
           lower[end] != '\t' && lower[end] != '\r' && lower[end] != '\n' &&
           lower[end] != '"' && lower[end] != '\'') {
      ++end;
    }
    const TextCharset parsed =
        charset_from_label(lower.substr(cursor, end - cursor));
    if (parsed != TextCharset::kAuto) return parsed;
  }
  return TextCharset::kAuto;
}

std::string to_display_utf8(std::string text, const CharsetProvider &hint) {
  if (text.empty()) return text;
  if (g_utf8_validate(text.data(), static_cast<gssize>(text.size()), nullptr)) {
    return text;
  }
  return convert(text.data(), text.size(), hint);
}

std::string to_display_utf8(std::string text, TextCharset hint) {
  if (text.empty()) return text;
  if (g_utf8_validate(text.data(), static_cast<gssize>(text.size()), nullptr)) {
    return text;
  }
  if (hint == TextCharset::kAuto) {
    return convert(text.data(), text.size(), CharsetProvider());
  }
  return convert(text.data(), text.size(),
                 CharsetProvider([hint] { return hint; }));
}

std::string to_display_utf8(const char *data, std::size_t length,
                            TextCharset hint) {
  if (!data || length == 0) return std::string();
  return to_display_utf8(std::string(data, length), hint);
}

std::string to_display_utf8(const char *data, std::size_t length,
                            const CharsetProvider &hint) {
  if (!data || length == 0) return std::string();
  return to_display_utf8(std::string(data, length), hint);
}

namespace {

/**
 * Printable-ASCII shape of already-decoded text: multi-byte sequences, U+FFFD
 * runs and C-style escapes ("\r\n", "\xNN", "\NNN") dropped.
 *
 * @param positions optional; receives the offset in @p text of every byte kept
 */
std::string label_skeleton(const std::string &text,
                           std::vector<std::size_t> *positions) {
  std::string out;
  out.reserve(text.size());
  for (std::size_t index = 0; index < text.size(); ++index) {
    const unsigned char value = static_cast<unsigned char>(text[index]);
    if (value >= 0x80) continue;  // multi-byte sequence or U+FFFD run
    if (value == '\\' && index + 1 < text.size()) {
      const char escape = text[index + 1];
      index += 1;
      if (escape == 'x' || escape == 'X') {
        std::size_t digits = 0;
        while (digits < 2 && index + 1 < text.size() &&
               std::isxdigit(static_cast<unsigned char>(text[index + 1]))) {
          ++index;
          ++digits;
        }
      } else if (escape >= '0' && escape <= '7') {
        std::size_t digits = 1;
        while (digits < 3 && index + 1 < text.size() && text[index + 1] >= '0' &&
               text[index + 1] <= '7') {
          ++index;
          ++digits;
        }
      }
      continue;
    }
    if (value >= 0x20 && value <= 0x7E) {
      out.push_back(static_cast<char>(value));
      if (positions) positions->push_back(index);
    }
  }
  return out;
}

/** Printable-ASCII shape of raw bytes: control bytes and high bytes dropped. */
std::string bytes_skeleton(const char *bytes, std::size_t length) {
  std::string out;
  out.reserve(length);
  for (std::size_t index = 0; index < length; ++index) {
    const unsigned char value = static_cast<unsigned char>(bytes[index]);
    if (value >= 0x20 && value <= 0x7E) out.push_back(static_cast<char>(value));
  }
  return out;
}

}  // namespace

std::string recover_text_from_source(std::string label, const char *bytes,
                                     std::size_t length,
                                     const CharsetProvider &hint) {
  if (!bytes || length == 0 || label.empty()) return label;
  if (label.find(kUndecodable) == std::string::npos) return label;

  const std::string from_bytes = bytes_skeleton(bytes, length);
  // Short shapes ("q=", "OK") match too easily to prove anything.
  if (from_bytes.size() < 4) return label;

  std::vector<std::size_t> positions;
  const std::string from_label = label_skeleton(label, &positions);
  if (from_label.size() < from_bytes.size()) return label;

  // Either the label is exactly the rendering of these bytes, or it is
  // "<prefix><rendering>" the way "Request URI: /x?q=…" is. Anything else is a
  // formatted label and is left untouched.
  std::size_t cut = 0;
  if (from_label != from_bytes) {
    const std::size_t offset = from_label.size() - from_bytes.size();
    if (from_label.compare(offset, from_bytes.size(), from_bytes) != 0) {
      return label;
    }
    cut = positions[offset];
    // The prefix itself must be clean text, otherwise the label mixes more
    // than one source and dropping everything after `cut` would be unsafe.
    const std::size_t first_replacement = label.find(kUndecodable);
    if (first_replacement != std::string::npos && first_replacement < cut) {
      return label;
    }
  }

  std::string decoded = to_display_utf8(std::string(bytes, length), hint);
  if (decoded.empty()) return label;
  // No improvement means no recovery.
  if (count_undecodable(decoded) >= count_undecodable(label)) return label;
  return label.substr(0, cut) + decoded;
}

}  // namespace layanalyzer::projection
