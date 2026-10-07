// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "layanalyzer/rtp/core/RtpAudioRenderer.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace layanalyzer::rtp {
namespace {

constexpr int64_t kMaxSilenceBeforeClipSec = 60;
constexpr int64_t kClippedSilenceSec = 1;

uint32_t saturating_milliseconds(double seconds) {
  if (!(seconds > 0.0)) {
    return 0;
  }

  const double milliseconds = seconds * 1000.0;
  if (milliseconds >=
      static_cast<double>(std::numeric_limits<uint32_t>::max())) {
    return std::numeric_limits<uint32_t>::max();
  }
  return static_cast<uint32_t>(milliseconds);
}

uint32_t samples_to_milliseconds(size_t samples, unsigned sample_rate) {
  if (sample_rate == 0) {
    return 0;
  }
  const uint64_t milliseconds =
      static_cast<uint64_t>(samples) * 1000u / sample_rate;
  return milliseconds > std::numeric_limits<uint32_t>::max()
             ? std::numeric_limits<uint32_t>::max()
             : static_cast<uint32_t>(milliseconds);
}

bool checked_offset_samples(double offset_sec, unsigned sample_rate,
                            int64_t &samples) {
  if (!(offset_sec > 0.0)) {
    samples = 0;
    return true;
  }

  const long double scaled =
      static_cast<long double>(offset_sec) * sample_rate;
  if (scaled >
      static_cast<long double>(std::numeric_limits<int64_t>::max())) {
    return false;
  }
  samples = static_cast<int64_t>(std::llround(scaled));
  return true;
}

int offset_milliseconds(double offset_sec) {
  if (!(offset_sec > 0.0)) {
    return 0;
  }
  const long double scaled =
      static_cast<long double>(offset_sec) * 1000.0L;
  if (scaled >
      static_cast<long double>(std::numeric_limits<int>::max())) {
    return std::numeric_limits<int>::max();
  }
  return static_cast<int>(std::llround(scaled));
}

std::vector<int16_t> resample_linear(const std::vector<int16_t> &input,
                                     unsigned input_rate,
                                     unsigned output_rate) {
  if (input.empty() || input_rate == output_rate) {
    return input;
  }

  const long double output_size =
      static_cast<long double>(input.size()) * output_rate / input_rate;
  if (output_size >
      static_cast<long double>(std::numeric_limits<size_t>::max())) {
    return {};
  }

  const size_t output_count =
      std::max<size_t>(1, static_cast<size_t>(std::llround(output_size)));
  std::vector<int16_t> output(output_count);
  const long double step =
      static_cast<long double>(input_rate) / output_rate;

  for (size_t index = 0; index < output_count; ++index) {
    const long double position = index * step;
    const size_t lower = static_cast<size_t>(std::floor(position));
    if (lower >= input.size() - 1u) {
      output[index] = input.back();
      continue;
    }

    const long double fraction = position - lower;
    const long double sample =
        static_cast<long double>(input[lower]) * (1.0L - fraction) +
        static_cast<long double>(input[lower + 1u]) * fraction;
    output[index] =
        static_cast<int16_t>(std::llround(std::clamp(
            sample, static_cast<long double>(std::numeric_limits<int16_t>::min()),
            static_cast<long double>(std::numeric_limits<int16_t>::max()))));
  }
  return output;
}

void append_silence(RtpRenderResult &result, int64_t silence_samples,
                    uint32_t at_ms, uint32_t frame, unsigned sample_rate) {
  if (silence_samples <= 0 || sample_rate == 0) {
    return;
  }

  bool clipped = false;
  const int64_t max_unclipped =
      static_cast<int64_t>(sample_rate) * kMaxSilenceBeforeClipSec;
  if (silence_samples > max_unclipped) {
    silence_samples =
        static_cast<int64_t>(sample_rate) * kClippedSilenceSec;
    clipped = true;
  }

  result.samples.insert(result.samples.end(),
                        static_cast<size_t>(silence_samples), 0);
  result.gaps.push_back(
      {at_ms, samples_to_milliseconds(static_cast<size_t>(silence_samples),
                                      sample_rate),
       "silence", frame, clipped});
}

}  // namespace

RtpRenderResult render_rtp_audio(const std::vector<RtpRenderPacket> &packets,
                                 const RtpRenderOptions &options) {
  RtpRenderResult result;
  if (packets.empty()) {
    return result;
  }

  const double start_rel_time = packets.front().arrival_rel_sec;
  double stop_rel_time = start_rel_time;
  unsigned sample_rate = 0;
  unsigned audio_out_rate = 0;
  uint32_t last_sequence = 0;
  uint32_t last_sequence_w = 0;
  double rtp_time_prev = 0.0;
  double arrive_time_prev = 0.0;
  double pack_period = 0.0;
  double start_time = 0.0;
  double start_rtp_time = 0.0;
  uint64_t start_timestamp = 0;
  size_t decoded_bytes_prev = 0;

  for (size_t cur_packet = 0; cur_packet < packets.size(); ++cur_packet) {
    const RtpRenderPacket &packet = packets[cur_packet];
    const double arrive_offset = packet.arrival_rel_sec - start_rel_time;
    stop_rel_time = start_rel_time + arrive_offset;
    const uint32_t stop_at_ms =
        saturating_milliseconds(stop_rel_time - start_rel_time);

    if (cur_packet == 0) {
      start_timestamp = packet.ext_ts;
      start_rtp_time = 0.0;
      rtp_time_prev = 0.0;
      last_sequence = packet.ext_seq - 1u;
    }

    const size_t decoded_bytes = packet.samples.size() * sizeof(int16_t);
    if (decoded_bytes == 0 || packet.sample_rate == 0 ||
        packet.timestamp_rate == 0) {
      last_sequence = packet.ext_seq;
      continue;
    }

    if (audio_out_rate == 0) {
      if (options.out_sample_rate != 0 &&
          options.out_sample_rate != packet.sample_rate) {
        result.error = "resamplingUnsupported";
        return result;
      }

      sample_rate = packet.sample_rate;
      audio_out_rate = sample_rate;
      result.sample_rate = audio_out_rate;

      double prepend_samples =
          (start_rel_time - options.global_start_rel_sec) * sample_rate;
      prepend_samples = prepend_samples * audio_out_rate / sample_rate;
      if (prepend_samples > 0.0) {
        const double max_prepend =
            static_cast<double>(std::numeric_limits<uint32_t>::max());
        result.prepend_samples =
            prepend_samples >= max_prepend
                ? std::numeric_limits<uint32_t>::max()
                : static_cast<uint32_t>(prepend_samples);
      }
    } else if (packet.sample_rate != sample_rate) {
      result.error = "sampleRateChanged";
      return result;
    }

    const double rtp_time =
        static_cast<double>(packet.ext_ts - start_timestamp) /
            packet.timestamp_rate -
        start_rtp_time;
    const double arrive_time =
        options.timing == RtpTimingMode::RtpTimestamp
            ? rtp_time
            : arrive_offset - start_time;
    const double diff = std::fabs(arrive_time - rtp_time);

    if (packet.ext_seq != last_sequence + 1u) {
      result.events.push_back({stop_at_ms, "outOfOrder",
                               std::to_string(packet.ext_seq),
                               packet.frame_number});
    }
    last_sequence = packet.ext_seq;

    if (diff * 1000.0 > options.jitter_buffer_ms &&
        options.timing != RtpTimingMode::Uninterrupted) {
      result.gaps.push_back(
          {stop_at_ms, 0, "late", packet.frame_number, false});
      ++result.dropped_late;

      if ((rtp_time - rtp_time_prev) > pack_period * 2.0) {
        int64_t silence_samples =
            static_cast<int64_t>((arrive_time - arrive_time_prev) *
                                     sample_rate -
                                 static_cast<double>(decoded_bytes_prev / 2));
        silence_samples =
            silence_samples * static_cast<int64_t>(audio_out_rate) /
            static_cast<int64_t>(sample_rate);
        append_silence(result, silence_samples, stop_at_ms, packet.frame_number,
                       audio_out_rate);

        decoded_bytes_prev = 0;
        start_timestamp = packet.ext_ts;
        start_rtp_time = 0.0;
        start_time = arrive_offset;
        rtp_time_prev = 0.0;
      }

      // The M2 card deliberately treats a jitter-buffer drop as non-writing.
      continue;
    }

    int64_t silence_samples = 0;
    if (options.timing != RtpTimingMode::Uninterrupted) {
      silence_samples =
          static_cast<int64_t>((rtp_time - rtp_time_prev) * sample_rate -
                               static_cast<double>(decoded_bytes_prev / 2));
      silence_samples =
          silence_samples * static_cast<int64_t>(audio_out_rate) /
          static_cast<int64_t>(sample_rate);
    }

    if (silence_samples != 0) {
      result.events.push_back({stop_at_ms, "wrongTimestamp",
                               std::to_string(silence_samples),
                               packet.frame_number});
    }
    if (silence_samples > 0) {
      append_silence(result, silence_samples, stop_at_ms, packet.frame_number,
                     audio_out_rate);
    }

    rtp_time_prev = rtp_time;
    pack_period = static_cast<double>(decoded_bytes) / sizeof(int16_t) /
                  static_cast<double>(sample_rate);
    decoded_bytes_prev = decoded_bytes;
    arrive_time_prev = arrive_time;

    if (last_sequence_w < last_sequence) {
      const uint32_t sample_at_ms =
          samples_to_milliseconds(result.samples.size(), audio_out_rate);
      result.samples.insert(result.samples.end(), packet.samples.begin(),
                            packet.samples.end());
      result.map.push_back({sample_at_ms, packet.frame_number});
      last_sequence_w = last_sequence;
    }
  }

  return result;
}

RtpMixedAudio mix_stereo(
    const std::vector<int16_t> &left, unsigned left_rate,
    double left_start_abs_sec, const std::vector<int16_t> &right,
    unsigned right_rate, double right_start_abs_sec,
    const RtpMixRequest &request) {
  RtpMixedAudio result;
  if (left.empty() && right.empty()) {
    return result;
  }
  if (!request.align_abs_arrival) {
    result.error = "alignmentUnsupported";
    return result;
  }
  if ((!left.empty() && left_rate == 0) ||
      (!right.empty() && right_rate == 0)) {
    result.error = "sampleRateRequired";
    return result;
  }

  const unsigned highest_input_rate =
      std::max(left.empty() ? 0u : left_rate,
               right.empty() ? 0u : right_rate);
  const unsigned output_rate =
      request.out_sample_rate == 0 ? highest_input_rate
                                   : request.out_sample_rate;
  if (output_rate == 0 || output_rate < highest_input_rate) {
    result.error = "outputSampleRateUnsupported";
    return result;
  }
  result.sample_rate = output_rate;

  double time_zero = 0.0;
  if (!left.empty() && !right.empty()) {
    time_zero = std::min(left_start_abs_sec, right_start_abs_sec);
  } else if (!left.empty()) {
    time_zero = left_start_abs_sec;
  } else {
    time_zero = right_start_abs_sec;
  }

  const double left_offset_sec =
      left.empty() ? 0.0
                   : std::max(0.0, left_start_abs_sec - time_zero);
  const double right_offset_sec =
      right.empty() ? 0.0
                    : std::max(0.0, right_start_abs_sec - time_zero);
  int64_t left_offset_samples = 0;
  int64_t right_offset_samples = 0;
  if (!checked_offset_samples(left_offset_sec, output_rate,
                              left_offset_samples) ||
      !checked_offset_samples(right_offset_sec, output_rate,
                              right_offset_samples)) {
    result.error = "mixTooLarge";
    return result;
  }

  result.left_offset_ms = offset_milliseconds(left_offset_sec);
  result.right_offset_ms = offset_milliseconds(right_offset_sec);

  const std::vector<int16_t> resampled_left =
      left.empty() ? std::vector<int16_t>()
                   : resample_linear(left, left_rate, output_rate);
  const std::vector<int16_t> resampled_right =
      right.empty() ? std::vector<int16_t>()
                    : resample_linear(right, right_rate, output_rate);
  result.resampled =
      (!left.empty() && left_rate != output_rate) ||
      (!right.empty() && right_rate != output_rate);

  const uint64_t left_samples =
      static_cast<uint64_t>(left_offset_samples) + resampled_left.size();
  const uint64_t right_samples =
      static_cast<uint64_t>(right_offset_samples) + resampled_right.size();
  const uint64_t total_samples = std::max(left_samples, right_samples);
  if (total_samples >
      std::numeric_limits<size_t>::max() / 2u) {
    result.error = "mixTooLarge";
    return result;
  }

  result.interleaved.assign(static_cast<size_t>(total_samples) * 2u, 0);
  for (size_t index = 0; index < resampled_left.size(); ++index) {
    result.interleaved[(static_cast<size_t>(left_offset_samples) + index) *
                       2u] = resampled_left[index];
  }
  for (size_t index = 0; index < resampled_right.size(); ++index) {
    result.interleaved[(static_cast<size_t>(right_offset_samples) + index) *
                           2u +
                       1u] = resampled_right[index];
  }
  return result;
}

}  // namespace layanalyzer::rtp
