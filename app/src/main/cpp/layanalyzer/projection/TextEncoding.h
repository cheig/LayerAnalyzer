// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Charset-aware conversion of captured bytes into UTF-8 for display (P2-1).
//
// Packet payloads, HTTP header values and reassembled stream text are raw
// bytes. A large part of the Chinese web still answers in GBK, so a protocol
// label built from those bytes is not valid UTF-8. Two behaviours are wrong
// here and this module exists to avoid both:
//
//   * nlohmann::json::dump() throws type_error.316 on such a label. That is
//     what P0-1 fixed, by replacing the offending bytes with U+FFFD at the JNI
//     boundary -- correct, but the text is then lost ("口口口").
//   * Guessing at the JNI boundary would decode *content*, not just labels,
//     and would corrupt binary bodies on their way out.
//
// So the conversion happens on the projection side, explicitly, only for
// strings that are display text (protocol-tree labels, list columns, follow
// stream text previews). Raw bytes stay untouched everywhere else: the hex
// view, the pcap export and PacketDataSource bytes are never transcoded.
#pragma once

#include <cstddef>
#include <cstring>
#include <functional>
#include <string>

namespace layanalyzer::projection {

/** Encodings this module can convert; GB18030 covers GBK and GB2312. */
enum class TextCharset {
  kAuto = 0, /**< No declaration: sniff, see to_display_utf8(). */
  kUtf8,
  kGb18030,
  kEucKr,
  kIso8859_1,
  kUtf16Le,
  kUtf16Be,
};

/**
 * Lazily resolved charset for one packet.
 *
 * Resolving a declared charset means walking the protocol tree, which is only
 * worth it for the rare strings that are not UTF-8 already. A provider lets
 * the caller defer that lookup instead of paying for it on every label.
 */
using CharsetProvider = std::function<TextCharset()>;

/** Maps a charset token ("gbk", "utf-8", ...) to a decoder; kAuto if unknown. */
TextCharset charset_from_label(const std::string &label);

/** Extracts charset= from a full Content-Type value; kAuto if absent/unknown. */
TextCharset charset_from_content_type(const std::string &content_type);

/**
 * Converts captured text into valid UTF-8 for display.
 *
 * Valid UTF-8 is returned unchanged (the fast path; the provider is not
 * called). Otherwise, in order:
 *   1. a UTF-16 BOM, which is unambiguous;
 *   2. the declared charset, if the caller supplied one;
 *   3. a heuristic over GB18030 and EUC-KR, keeping whichever leaves fewer
 *      undecodable sequences;
 *   4. per-byte U+FFFD replacement, i.e. the P0-1 behaviour, for anything no
 *      candidate can decode (Big5, Shift-JIS, binary).
 *
 * Never fails and never throws: the result is always a valid UTF-8 string.
 */
std::string to_display_utf8(std::string text,
                            const CharsetProvider &hint);
std::string to_display_utf8(std::string text,
                            TextCharset hint = TextCharset::kAuto);
std::string to_display_utf8(const char *data, std::size_t length,
                            TextCharset hint = TextCharset::kAuto);
std::string to_display_utf8(const char *data, std::size_t length,
                            const CharsetProvider &hint);

/**
 * Null-safe wrapper for Wireshark column text (safe_col_text()).
 *
 * Columns such as COL_INFO carry payload bytes too ("GET /搜索 HTTP/1.1"), so
 * they need the same treatment as protocol-tree labels.
 */
inline std::string column_to_display_utf8(const char *text) {
  if (!text) return std::string();
  return to_display_utf8(text, std::strlen(text));
}

/**
 * Recovers a display label from the raw field bytes when Wireshark has already
 * destroyed them.
 *
 * Several dissectors do not keep the captured bytes in a protocol-tree label:
 * HTTP builds its request/response line and the COL_INFO text with
 * ENC_NA|ENC_ASCII, so every GBK byte is turned into U+FFFD before the label
 * ever reaches this engine ("GET /x?q=\uFFFD\uFFFD\uFFFD HTTP/1.1"). The bytes
 * still exist in the field's data source, so the text can be rebuilt from
 * there -- but only when the label really is a rendering of exactly those
 * bytes. That is what the comparison below establishes: both sides are reduced
 * to their printable-ASCII skeleton (multi-byte sequences, U+FFFD runs and
 * C-style escapes such as "\r\n" / "\xNN" dropped) and must match exactly.
 * A formatted label with a prefix the bytes do not contain therefore never
 * gets replaced.
 *
 * @param label  the dissector label, possibly already sanitised
 * @param bytes  the field's bytes from its data source, may be null
 * @param length length of @p bytes
 * @param hint   declared charset provider, see to_display_utf8()
 * @return the decoded text, or @p label unchanged when recovery does not apply
 */
std::string recover_text_from_source(std::string label, const char *bytes,
                                     std::size_t length,
                                     const CharsetProvider &hint);

}  // namespace layanalyzer::projection
