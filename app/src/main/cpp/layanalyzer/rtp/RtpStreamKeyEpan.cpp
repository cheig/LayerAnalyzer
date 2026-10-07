// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "layanalyzer/rtp/RtpStreamKeyEpan.h"

#include "layanalyzer/projection/ProtocolProjection.h"

namespace layanalyzer::rtp {

RtpStreamKey make_rtp_stream_key(const packet_info *pinfo, uint32_t ssrc) {
  RtpStreamKey key;
  key.ssrc = ssrc;
  if (!pinfo) return key;

  // address_text 返回 std::string（内部用 address_to_str_buf），不开启名称解析。
  key.src = address_text(&pinfo->src, false);
  key.dst = address_text(&pinfo->dst, false);
  key.src_port = pinfo->srcport;
  key.dst_port = pinfo->destport;
  return key;
}

}  // namespace layanalyzer::rtp
