// RTP3-NAT-03: RFC 4733 telephone-event DTMF parser tests.
#include "doctest.h"

#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/RtpDecodeRequest.h"
#include "layanalyzer/rtp/core/DtmfParser.h"

using layanalyzer::rtp::DtmfEvent;
using layanalyzer::rtp::DtmfPacket;
using layanalyzer::rtp::parse_dtmf_events;
using layanalyzer::rtp::parse_rtp_decode_request;
using layanalyzer::rtp::RtpDecodeRequest;

namespace {

DtmfPacket make_packet(uint8_t pt, uint64_t timestamp, uint8_t event,
                       bool end, uint8_t volume, uint16_t duration,
                       uint32_t at_ms, uint32_t frame) {
  DtmfPacket packet;
  packet.pt = pt;
  packet.payload = {
      event,
      static_cast<uint8_t>((end ? 0x80u : 0u) | (volume & 0x3fu)),
      static_cast<uint8_t>((duration >> 8u) & 0xffu),
      static_cast<uint8_t>(duration & 0xffu),
  };
  packet.at_ms = at_ms;
  packet.frame = frame;
  packet.rtp_timestamp = timestamp;
  return packet;
}

}  // namespace

TEST_CASE("DtmfParser decodes a normal event using the last duration") {
  const std::vector<DtmfPacket> packets = {
      make_packet(101, 1000, 5, false, 10, 320, 5000, 900),
      make_packet(101, 1000, 5, true, 10, 1280, 5040, 902),
  };

  const std::vector<DtmfEvent> events =
      parse_dtmf_events(packets, 101, 8000);

  REQUIRE(events.size() == 1u);
  CHECK_EQ(events[0].digit, "5");
  CHECK_EQ(events[0].at_ms, 5000u);
  CHECK_EQ(events[0].dur_ms, 160u);
  CHECK_EQ(events[0].volume, 10u);
  CHECK_EQ(events[0].frame, 900u);
}

TEST_CASE("DtmfParser emits one event for repeated end packets") {
  const std::vector<DtmfPacket> packets = {
      make_packet(96, 2000, 7, false, 8, 640, 100, 10),
      make_packet(96, 2000, 7, true, 8, 1280, 120, 11),
      make_packet(96, 2000, 7, true, 8, 1280, 140, 12),
      make_packet(96, 2000, 7, true, 8, 1280, 160, 13),
  };

  const std::vector<DtmfEvent> events =
      parse_dtmf_events(packets, 96, 8000);

  REQUIRE(events.size() == 1u);
  CHECK_EQ(events[0].digit, "7");
  CHECK_EQ(events[0].dur_ms, 160u);
  CHECK_EQ(events[0].frame, 10u);
}

TEST_CASE("DtmfParser emits an event without an end packet") {
  const std::vector<DtmfPacket> packets = {
      make_packet(101, 3000, 3, false, 6, 320, 1000, 20),
      make_packet(101, 3000, 3, false, 6, 960, 1040, 21),
  };

  const std::vector<DtmfEvent> events =
      parse_dtmf_events(packets, 101, 8000);

  REQUIRE(events.size() == 1u);
  CHECK_EQ(events[0].digit, "3");
  CHECK_EQ(events[0].dur_ms, 120u);
}

TEST_CASE("DtmfParser separates events with different timestamps") {
  const std::vector<DtmfPacket> packets = {
      make_packet(101, 4000, 1, true, 4, 160, 100, 30),
      make_packet(101, 4160, 2, true, 4, 320, 120, 31),
  };

  const std::vector<DtmfEvent> events =
      parse_dtmf_events(packets, 101, 8000);

  REQUIRE(events.size() == 2u);
  CHECK_EQ(events[0].digit, "1");
  CHECK_EQ(events[0].at_ms, 100u);
  CHECK_EQ(events[0].frame, 30u);
  CHECK_EQ(events[1].digit, "2");
  CHECK_EQ(events[1].at_ms, 120u);
  CHECK_EQ(events[1].dur_ms, 40u);
  CHECK_EQ(events[1].frame, 31u);
}

TEST_CASE("DtmfParser skips short payloads and non-matching PTs") {
  DtmfPacket short_payload;
  short_payload.pt = 101;
  short_payload.payload = {5, 0, 0};
  short_payload.at_ms = 10;
  short_payload.frame = 1;
  short_payload.rtp_timestamp = 5000;

  const std::vector<DtmfPacket> packets = {
      short_payload,
      make_packet(0, 5001, 9, true, 3, 160, 20, 2),
  };

  CHECK(parse_dtmf_events(packets, 101, 8000).empty());
}

TEST_CASE("DtmfParser maps DTMF and unknown event ids") {
  const std::vector<uint8_t> event_ids = {
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  };
  const std::vector<std::string> expected = {
      "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
      "*", "#", "A", "B", "C", "D", "event:16",
  };

  for (size_t index = 0; index < event_ids.size(); ++index) {
    const std::vector<DtmfPacket> packets = {make_packet(
        101, 6000u + index, event_ids[index], true, 5, 160, 100, 40)};
    const std::vector<DtmfEvent> events =
        parse_dtmf_events(packets, 101, 8000);
    REQUIRE(events.size() == 1u);
    CHECK_EQ(events[0].digit, expected[index]);
  }
}

TEST_CASE("DtmfParser keeps one event across another PT with same timestamp") {
  const std::vector<DtmfPacket> packets = {
      make_packet(101, 7000, 8, false, 12, 640, 200, 50),
      make_packet(0, 7000, 0, true, 0, 160, 210, 51),
      make_packet(101, 7000, 8, true, 12, 1280, 220, 52),
  };

  const std::vector<DtmfEvent> events =
      parse_dtmf_events(packets, 101, 8000);

  REQUIRE(events.size() == 1u);
  CHECK_EQ(events[0].digit, "8");
  CHECK_EQ(events[0].dur_ms, 160u);
  CHECK_EQ(events[0].frame, 50u);
}

TEST_CASE("DtmfParser request parses the dtmf boolean") {
  RtpDecodeRequest request;
  std::string error;

  REQUIRE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"jitter","dtmf":true})",
      request, error));
  CHECK(request.dtmf);

  error.clear();
  REQUIRE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"jitter"})",
      request, error));
  CHECK_FALSE(request.dtmf);
}

TEST_CASE("DtmfParser request rejects malformed dtmf fields") {
  RtpDecodeRequest request;
  std::string error;

  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"jitter","dtmf":"true"})",
      request, error));
  CHECK_FALSE(error.empty());

  error.clear();
  CHECK_FALSE(parse_rtp_decode_request(
      R"({"scanGeneration":1,"streams":["s0"],"timing":"jitter","dtmf":true,"dtmf":false})",
      request, error));
  CHECK_FALSE(error.empty());
}
