// RTP2-NAT-04: RTP timing, silence, resync, and sequence-dedup host tests.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "layanalyzer/rtp/core/RtpAudioRenderer.h"

using layanalyzer::rtp::RtpRenderOptions;
using layanalyzer::rtp::RtpRenderPacket;
using layanalyzer::rtp::RtpRenderResult;
using layanalyzer::rtp::RtpTimingMode;
using layanalyzer::rtp::render_rtp_audio;

namespace {

constexpr unsigned kSampleRate = 8000;
constexpr unsigned kTimestampRate = 8000;
constexpr size_t kPacketSamples = 160;

RtpRenderPacket packet(uint32_t sequence, uint64_t timestamp, double arrival,
                       int16_t sample_value = 1,
                       size_t sample_count = kPacketSamples,
                       unsigned sample_rate = kSampleRate,
                       unsigned timestamp_rate = kTimestampRate) {
  RtpRenderPacket value;
  value.frame_number = sequence + 100;
  value.arrival_rel_sec = arrival;
  value.ext_seq = sequence;
  value.ext_ts = timestamp;
  value.samples.assign(sample_count, sample_value);
  value.channels = 1;
  value.sample_rate = sample_rate;
  value.timestamp_rate = timestamp_rate;
  return value;
}

size_t zero_sample_count(const RtpRenderResult &result) {
  size_t total = 0;
  for (int16_t sample : result.samples) {
    if (sample == 0) {
      ++total;
    }
  }
  return total;
}

}  // namespace

TEST_CASE("RtpAudioRenderer writes continuous 20 ms packets") {
  // 20 packets * 160 samples = 3200 samples. Each packet starts 20 ms after
  // the previous one, and packet 1 starts at 0 ms.
  std::vector<RtpRenderPacket> packets;
  for (uint32_t i = 0; i < 20; ++i) {
    packets.push_back(
        packet(i + 1, 1000u + static_cast<uint64_t>(i) * 160u,
               static_cast<double>(i) * 0.020, static_cast<int16_t>(i + 1)));
  }

  const RtpRenderResult result = render_rtp_audio(packets, {});

  CHECK(result.error.empty());
  CHECK_EQ(result.sample_rate, 8000u);
  CHECK_EQ(result.samples.size(), static_cast<size_t>(3200));
  CHECK(result.gaps.empty());
  CHECK(result.events.empty());
  REQUIRE_EQ(result.map.size(), static_cast<size_t>(20));
  CHECK_EQ(result.map[0].at_ms, 0u);
  CHECK_EQ(result.map[1].at_ms, 20u);
  CHECK_EQ(result.dropped_late, 0u);
}

TEST_CASE("RtpAudioRenderer inserts silence for 30 ms RTP packet periods") {
  // The 30 ms RTP cadence carries 20 ms of PCM. There are 19 inter-packet
  // gaps. Binary floating point and the required integer truncation make five
  // gaps 79 samples and the other fourteen 80 samples:
  // 5 * 79 + 14 * 80 = 1515 silence samples. There is no trailing gap, so the
  // total is 3200 + 1515 = 4715.
  std::vector<RtpRenderPacket> packets;
  for (uint32_t i = 0; i < 20; ++i) {
    packets.push_back(
        packet(i + 1, 1000u + static_cast<uint64_t>(i) * 240u,
               static_cast<double>(i) * 0.030, static_cast<int16_t>(i + 1)));
  }

  const RtpRenderResult result = render_rtp_audio(packets, {});

  CHECK(result.error.empty());
  CHECK_EQ(result.samples.size(), static_cast<size_t>(4715));
  CHECK_EQ(zero_sample_count(result), static_cast<size_t>(1515));
  REQUIRE_EQ(result.gaps.size(), static_cast<size_t>(19));
  CHECK(result.gaps.front().reason == "silence");
  CHECK_EQ(result.gaps.front().dur_ms, 10u);
  REQUIRE_EQ(result.events.size(), static_cast<size_t>(19));
  CHECK(result.events.front().type == "wrongTimestamp");
  CHECK_EQ(result.map[1].at_ms, 30u);
}

TEST_CASE("RtpAudioRenderer drops a packet later than the jitter buffer") {
  // Packet 2 is expected at 20 ms but arrives at 100 ms. The 80 ms difference
  // exceeds the 50 ms buffer, so only packet 1 contributes 160 samples.
  const std::vector<RtpRenderPacket> packets = {
      packet(1, 1000, 0.000, 11),
      packet(2, 1160, 0.100, 22),
  };

  const RtpRenderResult result = render_rtp_audio(packets, {});

  CHECK_EQ(result.samples.size(), static_cast<size_t>(160));
  REQUIRE_EQ(result.gaps.size(), static_cast<size_t>(1));
  CHECK(result.gaps[0].reason == "late");
  CHECK_EQ(result.gaps[0].at_ms, 100u);
  CHECK_EQ(result.gaps[0].dur_ms, 0u);
  CHECK_EQ(result.dropped_late, 1u);
  REQUIRE_EQ(result.map.size(), static_cast<size_t>(1));
  CHECK_EQ(result.map[0].frame, 101u);
}

TEST_CASE("RtpAudioRenderer records a missing sequence and fills its gap") {
  // Sequence 3 is absent. Its 40 ms timestamp span becomes 160 samples of
  // silence, so audio packets 1, 2, and 4 plus silence total 640 samples.
  const std::vector<RtpRenderPacket> packets = {
      packet(1, 1000, 0.00, 11),
      packet(2, 1160, 0.02, 22),
      packet(4, 1480, 0.06, 44),
  };

  const RtpRenderResult result = render_rtp_audio(packets, {});

  // The 40 ms timestamp delta truncates to 159 silence samples because the
  // double subtraction is just below 160. Total: 3 * 160 + 159 = 639.
  CHECK_EQ(result.samples.size(), static_cast<size_t>(639));
  CHECK_EQ(zero_sample_count(result), static_cast<size_t>(159));
  REQUIRE_EQ(result.gaps.size(), static_cast<size_t>(1));
  CHECK(result.gaps[0].reason == "silence");
  CHECK_EQ(result.gaps[0].at_ms, 60u);
  REQUIRE_EQ(result.events.size(), static_cast<size_t>(2));
  CHECK(result.events[0].type == "outOfOrder");
  CHECK(result.events[0].value == "4");
  CHECK(result.events[1].type == "wrongTimestamp");
  REQUIRE_EQ(result.map.size(), static_cast<size_t>(3));
  CHECK_EQ(result.map[2].frame, 104u);
}

TEST_CASE("RtpAudioRenderer writes a duplicate sequence only once") {
  // The duplicate arrives 100 ms late. The first copy writes 160 samples;
  // the second is dropped by the jitter buffer and cannot overwrite it.
  const std::vector<RtpRenderPacket> packets = {
      packet(7, 1000, 0.000, 11),
      packet(7, 1000, 0.100, 99),
  };

  const RtpRenderResult result = render_rtp_audio(packets, {});

  CHECK_EQ(result.samples.size(), static_cast<size_t>(160));
  CHECK_EQ(result.samples.front(), 11);
  CHECK_EQ(result.dropped_late, 1u);
  REQUIRE_EQ(result.events.size(), static_cast<size_t>(1));
  CHECK(result.events[0].type == "outOfOrder");
  REQUIRE_EQ(result.map.size(), static_cast<size_t>(1));
}

TEST_CASE("RtpAudioRenderer uses RTP timestamps in RtpTimestamp mode") {
  // Packet 2 arrives one second later but its timestamp is only 40 ms after
  // packet 1. RTP-timestamp mode places it at 40 ms and inserts 160 samples
  // of silence between the two 20 ms payloads.
  RtpRenderOptions options;
  options.timing = RtpTimingMode::RtpTimestamp;
  const std::vector<RtpRenderPacket> packets = {
      packet(1, 1000, 0.0, 11),
      packet(2, 1320, 1.0, 22),
  };

  const RtpRenderResult result = render_rtp_audio(packets, options);

  CHECK_EQ(result.samples.size(), static_cast<size_t>(480));
  CHECK_EQ(zero_sample_count(result), static_cast<size_t>(160));
  REQUIRE_EQ(result.map.size(), static_cast<size_t>(2));
  CHECK_EQ(result.map[1].at_ms, 40u);
  CHECK_EQ(result.dropped_late, 0u);
}

TEST_CASE("RtpAudioRenderer concatenates packets in Uninterrupted mode") {
  // Uninterrupted mode ignores both arrival time and timestamp jumps:
  // 3 packets * 160 samples = 480 samples, with no inserted gaps.
  RtpRenderOptions options;
  options.timing = RtpTimingMode::Uninterrupted;
  const std::vector<RtpRenderPacket> packets = {
      packet(1, 1000, 0.0, 11),
      packet(2, 9000, 0.1, 22),
      packet(3, 10000, 0.2, 33),
  };

  const RtpRenderResult result = render_rtp_audio(packets, options);

  CHECK_EQ(result.samples.size(), static_cast<size_t>(480));
  CHECK(result.gaps.empty());
  REQUIRE_EQ(result.map.size(), static_cast<size_t>(3));
  CHECK_EQ(result.map[0].at_ms, 0u);
  CHECK_EQ(result.map[1].at_ms, 20u);
  CHECK_EQ(result.map[2].at_ms, 40u);
}

TEST_CASE("RtpAudioRenderer clips a timestamp jump longer than 60 seconds") {
  // A 100 s timestamp and arrival jump would add 799840 samples. The M2
  // safety rule clips that single silence run to 1 s (8000 samples), yielding
  // 160 + 8000 + 160 = 8320 output samples and a clipped 1000 ms gap.
  const std::vector<RtpRenderPacket> packets = {
      packet(1, 1000, 0.0, 11),
      packet(2, 801000, 100.0, 22),
  };

  const RtpRenderResult result = render_rtp_audio(packets, {});

  CHECK_EQ(result.samples.size(), static_cast<size_t>(8320));
  REQUIRE_EQ(result.gaps.size(), static_cast<size_t>(1));
  CHECK(result.gaps[0].reason == "silence");
  CHECK_EQ(result.gaps[0].at_ms, 100000u);
  CHECK_EQ(result.gaps[0].dur_ms, 1000u);
  CHECK(result.gaps[0].clipped);
}

TEST_CASE("RtpAudioRenderer truncates silence samples before scaling") {
  // timestamp_rate=44100 and sample_rate=8000:
  // 883/44100 * 8000 - 160 = 0.1814, which truncates to 0.
  // 890/44100 * 8000 - 160 = 1.4512, which truncates to 1.
  const RtpRenderPacket first =
      packet(1, 0, 0.0, 11, 160, 8000, 44100);
  const RtpRenderPacket truncated_to_zero =
      packet(2, 883, 883.0 / 44100.0, 22, 160, 8000, 44100);
  const RtpRenderPacket truncated_to_one =
      packet(2, 890, 890.0 / 44100.0, 33, 160, 8000, 44100);

  const RtpRenderResult zero_result =
      render_rtp_audio({first, truncated_to_zero}, {});
  CHECK_EQ(zero_result.samples.size(), static_cast<size_t>(320));
  CHECK(zero_result.gaps.empty());
  CHECK(zero_result.events.empty());

  const RtpRenderResult one_result =
      render_rtp_audio({first, truncated_to_one}, {});
  CHECK_EQ(one_result.samples.size(), static_cast<size_t>(321));
  REQUIRE_EQ(one_result.gaps.size(), static_cast<size_t>(1));
  CHECK(one_result.gaps[0].reason == "silence");
  REQUIRE_EQ(one_result.events.size(), static_cast<size_t>(1));
  CHECK(one_result.events[0].type == "wrongTimestamp");
  CHECK(one_result.events[0].value == "1");
}

TEST_CASE("RtpAudioRenderer resync depends on measured packet period") {
  // Packet 1 establishes a 20 ms pack_period. A 30 ms timestamp jump is
  // below 2 * pack_period, so a late packet is dropped without resync.
  const RtpRenderPacket first = packet(1, 1000, 0.0, 11);
  const RtpRenderPacket thirty_ms = packet(2, 1240, 0.1, 22);
  const RtpRenderResult no_resync =
      render_rtp_audio({first, thirty_ms}, {});
  REQUIRE_EQ(no_resync.gaps.size(), static_cast<size_t>(1));
  CHECK(no_resync.gaps[0].reason == "late");

  // A 50 ms jump exceeds 2 * pack_period. Packet 2 arrives 120 ms late, so
  // resync inserts (0.12 - 0) * 8000 - 160 = 800 silence samples.
  const RtpRenderPacket fifty_ms = packet(2, 1400, 0.12, 22);
  const RtpRenderResult resync =
      render_rtp_audio({first, fifty_ms}, {});
  REQUIRE_EQ(resync.gaps.size(), static_cast<size_t>(2));
  CHECK(resync.gaps[0].reason == "late");
  CHECK(resync.gaps[1].reason == "silence");
  CHECK_EQ(resync.gaps[1].dur_ms, 100u);
  CHECK_EQ(resync.samples.size(), static_cast<size_t>(960));
}

TEST_CASE("RtpAudioRenderer applies setFrameReadStage prepend trimming") {
  // The stream starts at 125 ms while global time starts at 0. The internal
  // prepend is 125 ms * 8000 = 1000 samples, but export drops that leading
  // frame, so result.samples contains only the packet's 160 samples and the
  // packet map starts at 0 ms.
  RtpRenderOptions options;
  options.global_start_rel_sec = 0.0;
  const std::vector<RtpRenderPacket> packets = {
      packet(1, 1000, 0.125, 11),
  };

  const RtpRenderResult result = render_rtp_audio(packets, options);

  CHECK_EQ(result.prepend_samples, 1000u);
  CHECK_EQ(result.samples.size(), static_cast<size_t>(160));
  REQUIRE_EQ(result.map.size(), static_cast<size_t>(1));
  CHECK_EQ(result.map[0].at_ms, 0u);
}
