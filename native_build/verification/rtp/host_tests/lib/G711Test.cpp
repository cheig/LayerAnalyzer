// RTP2-NAT-02: G.711 expansion table tests.
//
// The expected tables are copied value-for-value from Wireshark 4.0.10:
// plugins/codecs/G711/G711decode.c.
#include "doctest.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

using layanalyzer::rtp::is_decoder_available;
using layanalyzer::rtp::make_audio_decoder;
using layanalyzer::rtp::RtpAudioDecoder;

namespace {

constexpr std::array<int16_t, 256> kExpectedUlaw = {
    -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956,
    -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764,
    -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412,
    -11900, -11388, -10876, -10364, -9852,  -9340,  -8828,  -8316,
    -7932,  -7676,  -7420,  -7164,  -6908,  -6652,  -6396,  -6140,
    -5884,  -5628,  -5372,  -5116,  -4860,  -4604,  -4348,  -4092,
    -3900,  -3772,  -3644,  -3516,  -3388,  -3260,  -3132,  -3004,
    -2876,  -2748,  -2620,  -2492,  -2364,  -2236,  -2108,  -1980,
    -1884,  -1820,  -1756,  -1692,  -1628,  -1564,  -1500,  -1436,
    -1372,  -1308,  -1244,  -1180,  -1116,  -1052,  -988,   -924,
    -876,   -844,   -812,   -780,   -748,   -716,   -684,   -652,
    -620,   -588,   -556,   -524,   -492,   -460,   -428,   -396,
    -372,   -356,   -340,   -324,   -308,   -292,   -276,   -260,
    -244,   -228,   -212,   -196,   -180,   -164,   -148,   -132,
    -120,   -112,   -104,   -96,    -88,    -80,    -72,    -64,
    -56,    -48,    -40,    -32,    -24,    -16,    -8,     0,
    32124,  31100,  30076,  29052,  28028,  27004,  25980,  24956,
    23932,  22908,  21884,  20860,  19836,  18812,  17788,  16764,
    15996,  15484,  14972,  14460,  13948,  13436,  12924,  12412,
    11900,  11388,  10876,  10364,  9852,   9340,   8828,   8316,
    7932,   7676,   7420,   7164,   6908,   6652,   6396,   6140,
    5884,   5628,   5372,   5116,   4860,   4604,   4348,   4092,
    3900,   3772,   3644,   3516,   3388,   3260,   3132,   3004,
    2876,   2748,   2620,   2492,   2364,   2236,   2108,   1980,
    1884,   1820,   1756,   1692,   1628,   1564,   1500,   1436,
    1372,   1308,   1244,   1180,   1116,   1052,   988,    924,
    876,    844,    812,    780,    748,    716,    684,    652,
    620,    588,    556,    524,    492,    460,    428,    396,
    372,    356,    340,    324,    308,    292,    276,    260,
    244,    228,    212,    196,    180,    164,    148,    132,
    120,    112,    104,    96,     88,     80,     72,     64,
    56,     48,     40,     32,     24,     16,     8,      0,
};

constexpr std::array<int16_t, 256> kExpectedAlaw = {
    -5504,  -5248,  -6016,  -5760,  -4480,  -4224,  -4992,  -4736,
    -7552,  -7296,  -8064,  -7808,  -6528,  -6272,  -7040,  -6784,
    -2752,  -2624,  -3008,  -2880,  -2240,  -2112,  -2496,  -2368,
    -3776,  -3648,  -4032,  -3904,  -3264,  -3136,  -3520,  -3392,
    -22016, -20992, -24064, -23040, -17920, -16896, -19968, -18944,
    -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136,
    -11008, -10496, -12032, -11520, -8960,  -8448,  -9984,  -9472,
    -15104, -14592, -16128, -15616, -13056, -12544, -14080, -13568,
    -344,   -328,   -376,   -360,   -280,   -264,   -312,   -296,
    -472,   -456,   -504,   -488,   -408,   -392,   -440,   -424,
    -88,    -72,    -120,   -104,   -24,    -8,     -56,    -40,
    -216,   -200,   -248,   -232,   -152,   -136,   -184,   -168,
    -1376,  -1312,  -1504,  -1440,  -1120,  -1056,  -1248,  -1184,
    -1888,  -1824,  -2016,  -1952,  -1632,  -1568,  -1760,  -1696,
    -688,   -656,   -752,   -720,   -560,   -528,   -624,   -592,
    -944,   -912,   -1008,  -976,   -816,   -784,   -880,   -848,
    5504,   5248,   6016,   5760,   4480,   4224,   4992,   4736,
    7552,   7296,   8064,   7808,   6528,   6272,   7040,   6784,
    2752,   2624,   3008,   2880,   2240,   2112,   2496,   2368,
    3776,   3648,   4032,   3904,   3264,   3136,   3520,   3392,
    22016,  20992,  24064,  23040,  17920,  16896,  19968,  18944,
    30208,  29184,  32256,  31232,  26112,  25088,  28160,  27136,
    11008,  10496,  12032,  11520,  8960,   8448,   9984,   9472,
    15104,  14592,  16128,  15616,  13056,  12544,  14080,  13568,
    344,    328,    376,    360,    280,    264,    312,    296,
    472,    456,    504,    488,    408,    392,    440,    424,
    88,     72,     120,    104,    24,     8,      56,     40,
    216,    200,    248,    232,    152,    136,    184,    168,
    1376,   1312,   1504,   1440,   1120,   1056,   1248,   1184,
    1888,   1824,   2016,   1952,   1632,   1568,   1760,   1696,
    688,    656,    752,    720,    560,    528,    624,    592,
    944,    912,    1008,   976,    816,    784,    880,    848,
};

std::vector<uint8_t> allCodewords() {
  std::vector<uint8_t> payload(256);
  for (size_t i = 0; i < payload.size(); ++i) {
    payload[i] = static_cast<uint8_t>(i);
  }
  return payload;
}

}  // namespace

TEST_CASE("G711 A-law expansion matches Wireshark 4.0.10 table") {
  const std::unique_ptr<RtpAudioDecoder> decoder =
      make_audio_decoder("g711A");
  REQUIRE(decoder);
  CHECK_EQ(decoder->channels(), 1u);
  CHECK_EQ(decoder->sample_rate(), 8000u);
  CHECK_EQ(decoder->timestamp_rate(), 8000u);

  const std::vector<uint8_t> payload = allCodewords();
  std::vector<int16_t> out;
  REQUIRE(decoder->decode(payload.data(), payload.size(), out));
  REQUIRE_EQ(out.size(), kExpectedAlaw.size());
  for (size_t i = 0; i < out.size(); ++i) {
    CHECK_EQ(out[i], kExpectedAlaw[i]);
  }
}

TEST_CASE("G711 mu-law expansion matches Wireshark 4.0.10 table") {
  const std::unique_ptr<RtpAudioDecoder> decoder =
      make_audio_decoder("g711U");
  REQUIRE(decoder);
  CHECK_EQ(decoder->channels(), 1u);
  CHECK_EQ(decoder->sample_rate(), 8000u);
  CHECK_EQ(decoder->timestamp_rate(), 8000u);

  const std::vector<uint8_t> payload = allCodewords();
  std::vector<int16_t> out;
  REQUIRE(decoder->decode(payload.data(), payload.size(), out));
  REQUIRE_EQ(out.size(), kExpectedUlaw.size());
  for (size_t i = 0; i < out.size(); ++i) {
    CHECK_EQ(out[i], kExpectedUlaw[i]);
  }

  // Wireshark 4.0.10's table maps both sign zeros to zero.
  CHECK_EQ(out[0x7F], 0);
  CHECK_EQ(out[0xFF], 0);
}

TEST_CASE("G711 factory rejects unavailable codecs and malformed names") {
  CHECK(is_decoder_available("g711A"));
  CHECK(is_decoder_available("g711U"));
  CHECK(is_decoder_available("L16"));
  // AMR/AMR-WB are decoded through MediaCodec (RTP4-KT-02), never through
  // RtpDecoderFactory, so AMR is the honest example of a codec this factory
  // must reject -- this case used to name g722, which RTP4-NAT-01 implemented.
  CHECK_FALSE(is_decoder_available("AMR"));
  CHECK_FALSE(make_audio_decoder("AMR"));
  CHECK_FALSE(make_audio_decoder("G711A"));
  CHECK_FALSE(make_audio_decoder("g711A", 2));
}

TEST_CASE("G711:L16 decoder factory integration") {
  CHECK(is_decoder_available("g711A"));
  CHECK(is_decoder_available("g711U"));
  CHECK(is_decoder_available("L16"));
  CHECK_EQ(make_audio_decoder("L16")->channels(), 1u);
  CHECK_EQ(make_audio_decoder("L16", 2)->channels(), 2u);
}
