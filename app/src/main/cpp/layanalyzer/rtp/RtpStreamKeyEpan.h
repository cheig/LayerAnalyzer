// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// 从 epan 的 packet_info 构造 RtpStreamKey（RTP1-NAT-01）。
//
// 对应 Wireshark 4.0.10 ui/rtp_stream_id.c 的 rtpstream_id_copy_pinfo：
// 取 pinfo->src/srcport、pinfo->dst/destport（**不是** net_src/net_dst）。
// 依赖 epan，放在 layanalyzer/rtp/ 根目录，不进 host 单测。
#pragma once

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/rtp/core/RtpStreamKey.h"

namespace layanalyzer::rtp {

/** SSRC 由调用方传入（tap 回调里的 rtp_info->info_sync_src）。 */
RtpStreamKey make_rtp_stream_key(const packet_info *pinfo, uint32_t ssrc);

}  // namespace layanalyzer::rtp
