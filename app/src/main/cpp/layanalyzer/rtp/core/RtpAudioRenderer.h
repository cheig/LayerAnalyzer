// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Pure RTP audio timing and silence renderer.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

enum class RtpTimingMode { JitterBuffer, RtpTimestamp, Uninterrupted };

struct RtpRenderPacket {
  uint32_t frame_number = 0;
  double arrival_rel_sec = 0.0;
  uint64_t ext_ts = 0;
  uint8_t pt = 0;
  bool marker = false;
  std::vector<int16_t> samples;
  unsigned channels = 1;
  unsigned sample_rate = 0;
  unsigned timestamp_rate = 0;
  uint32_t ext_seq = 0;
};

struct RtpRenderGap {
  uint32_t at_ms = 0;
  uint32_t dur_ms = 0;
  std::string reason;
  uint32_t frame = 0;
  bool clipped = false;
};

struct RtpRenderEvent {
  uint32_t at_ms = 0;
  std::string type;
  std::string value;
  uint32_t frame = 0;
};

struct RtpRenderMapEntry {
  uint32_t at_ms = 0;
  uint32_t frame = 0;
};

struct RtpRenderOptions {
  RtpTimingMode timing = RtpTimingMode::JitterBuffer;
  int jitter_buffer_ms = 50;
  unsigned out_sample_rate = 0;
  double global_start_rel_sec = 0.0;
};

struct RtpRenderResult {
  std::vector<int16_t> samples;
  unsigned sample_rate = 0;
  std::vector<RtpRenderGap> gaps;
  std::vector<RtpRenderEvent> events;
  std::vector<RtpRenderMapEntry> map;
  uint64_t dropped_late = 0;
  uint32_t prepend_samples = 0;
  std::string error;
};

struct RtpMixRequest {
  std::string left_stream_id;
  std::string right_stream_id;
  bool align_abs_arrival = true;
  unsigned out_sample_rate = 0;
};

struct RtpMixedAudio {
  std::vector<int16_t> interleaved;
  unsigned sample_rate = 0;
  int left_offset_ms = 0;
  int right_offset_ms = 0;
  bool resampled = false;
  std::string error;
};

// Packets must be supplied in arrival order.
RtpRenderResult render_rtp_audio(const std::vector<RtpRenderPacket> &packets,
                                 const RtpRenderOptions &options);

// Aligns two already-rendered mono streams by their first-packet absolute
// times and returns interleaved L/R PCM. Lower-rate inputs are linearly
// interpolated to the output rate.
RtpMixedAudio mix_stereo(
    const std::vector<int16_t> &left, unsigned left_rate,
    double left_start_abs_sec, const std::vector<int16_t> &right,
    unsigned right_rate, double right_start_abs_sec,
    const RtpMixRequest &request);

}  // namespace layanalyzer::rtp
