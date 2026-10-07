#include "layanalyzer/rtp/core/RtpMediaDecoder.h"

#include "layanalyzer/rtp/codecs/RtpDecoderFactory.h"

namespace layanalyzer::rtp {

RtpMediaDecoder::RtpMediaDecoder(const std::string &canonical_codec)
    : canonical_codec_(canonical_codec),
      decoder_(make_audio_decoder(canonical_codec, 1)),
      available_(decoder_ != nullptr) {}

bool RtpMediaDecoder::available() const { return available_; }

bool RtpMediaDecoder::ensureDecoderForPayloadType(uint32_t payload_type) {
  if (!available_) {
    return false;
  }

  if (canonical_codec_ != "L16") {
    return decoder_ != nullptr;
  }

  const unsigned channels = payload_type == 10 ? 2 : 1;
  if (!decoder_ || decoder_->channels() != channels) {
    decoder_ = make_audio_decoder(canonical_codec_, channels);
    available_ = decoder_ != nullptr;
  }
  return decoder_ != nullptr;
}

RtpMediaDecoderResult RtpMediaDecoder::decodePacket(
    uint32_t payload_type, const uint8_t *payload, size_t length,
    std::vector<int16_t> &out) {
  out.clear();

  if (!available_) {
    return {false, "unsupported"};
  }
  if (!ensureDecoderForPayloadType(payload_type)) {
    return {false, "unsupported"};
  }
  if (payload == nullptr || length == 0) {
    return {false, "decodeFailed"};
  }

  if (!decoder_->decode(payload, length, out)) {
    out.clear();
    return {false, "decodeFailed"};
  }

  const unsigned channels = decoder_->channels();
  if (channels == 0) {
    out.clear();
    return {false, "decodeFailed"};
  }

  last_packet_samples_ =
      static_cast<uint32_t>(out.size() / static_cast<size_t>(channels));
  return {true, ""};
}

unsigned RtpMediaDecoder::channels() const {
  return decoder_ ? decoder_->channels() : 0;
}

unsigned RtpMediaDecoder::sample_rate() const {
  return decoder_ ? decoder_->sample_rate() : 0;
}

unsigned RtpMediaDecoder::timestamp_rate() const {
  return decoder_ ? decoder_->timestamp_rate() : 0;
}

uint32_t RtpMediaDecoder::lastPacketSamples() const {
  return last_packet_samples_;
}

}  // namespace layanalyzer::rtp
