#include "layanalyzer/rtp/core/RtpStreamKey.h"

#include <cstdio>
#include <functional>

namespace layanalyzer::rtp {

bool RtpStreamKey::operator==(const RtpStreamKey &other) const {
  // 对应 rtpstream_id_equal(...) 的五元组比较（原版始终带
  // RTPSTREAM_ID_EQUAL_SSRC 语义，这里把 SSRC 也纳入相等判定）。
  return src == other.src && dst == other.dst && src_port == other.src_port &&
         dst_port == other.dst_port && ssrc == other.ssrc;
}

size_t RtpStreamKeyHash::operator()(const RtpStreamKey &key) const noexcept {
  // 与 rtpstream_id_to_hash 同构：先异或端口/SSRC，再混入两个地址。
  // 不用 Wireshark 的 add_address_to_hash —— 我们只需要自洽的 std::hash 组合。
  const uint32_t ports = static_cast<uint32_t>(key.src_port) |
                         (static_cast<uint32_t>(key.dst_port) << 16);
  size_t hash = 0;
  hash ^= static_cast<size_t>(ports);
  hash ^= static_cast<size_t>(key.ssrc);
  hash ^= std::hash<std::string>{}(key.src);
  hash ^= std::hash<std::string>{}(key.dst);
  return hash;
}

bool RtpStreamKeyHash::operator()(const RtpStreamKey &left,
                                  const RtpStreamKey &right) const noexcept {
  if (left.src != right.src) return left.src < right.src;
  if (left.dst != right.dst) return left.dst < right.dst;
  if (left.src_port != right.src_port) return left.src_port < right.src_port;
  if (left.dst_port != right.dst_port) return left.dst_port < right.dst_port;
  return left.ssrc < right.ssrc;
}

std::string rtp_stream_key_to_string(const RtpStreamKey &key) {
  char ssrc_text[16];
  std::snprintf(ssrc_text, sizeof(ssrc_text), "0x%08x", key.ssrc);

  std::string text;
  text.reserve(key.src.size() + key.dst.size() + 32);
  text += key.src;
  text += ':';
  text += std::to_string(key.src_port);
  text += '-';
  text += key.dst;
  text += ':';
  text += std::to_string(key.dst_port);
  text += '/';
  text += ssrc_text;
  return text;
}

}  // namespace layanalyzer::rtp
