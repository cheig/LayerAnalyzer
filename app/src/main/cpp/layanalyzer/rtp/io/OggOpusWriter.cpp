// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#include "layanalyzer/rtp/io/OggOpusWriter.h"

#include <limits>
#include <vector>

namespace layanalyzer::rtp {
namespace {

// "OggS" (RFC 3533 section 6). The fixed part of a page header is 27 octets:
// magic (4) + version (1) + header type (1) + granule (8) + serial (4) +
// sequence (4) + CRC (4) + segment count (1). The segment table follows it and
// the page body follows the table.
constexpr size_t kOggPageHeaderSize = 27;
constexpr uint8_t kOggVersion = 0;
// Header type flags: bit 0 is "continuation of a packet from the previous
// page", which this writer never sets (one packet per page, never split across
// pages), bit 1 is beginning-of-stream, bit 2 is end-of-stream.
constexpr uint8_t kHeaderBos = 0x02;
constexpr uint8_t kHeaderEos = 0x04;

// Bitstream serial number. The card calls for a fixed, random-looking value
// that does not change within one run; a constant satisfies that and, unlike a
// random value, keeps the output reproducible for the byte-for-byte golden
// test (OggOpusWriterTest.cpp). 0x4C41594C is "LAYL" in ASCII.
constexpr uint32_t kOggOpusSerial = 0x4C41594Cu;

// A page carries at most 255 lacing values, so a page body is at most
// 255 * 255 = 65025 octets. With the terminating lacing value the real limit
// for one packet is 65024 (see writePage()); anything longer is rejected
// rather than truncated into a stream a reader would misparse.
constexpr size_t kMaxPageSegments = 255;

constexpr char kOpusHeadMagic[8] = {'O', 'p', 'u', 's', 'H', 'e', 'a', 'd'};
constexpr char kOpusTagsMagic[8] = {'O', 'p', 'u', 's', 'T', 'a', 'g', 's'};
constexpr uint8_t kOpusHeadVersion = 1;
constexpr size_t kOpusHeadSize = 19;
constexpr uint64_t kOpusSampleRate = 48000;

// Ogg's CRC-32 (RFC 3533 section 6): polynomial 0x04C11DB7, initial value 0,
// no input or output reflection and no final XOR -- MSB-first, the opposite of
// the reflected CRC-32 everyone is used to.
//
// This is NOT zlib's CRC-32 and NOT CRC-32/POSIX: both of those reflect the
// input and the output and CRC-32/POSIX additionally xors the result with
// 0xFFFFFFFF. Substituting either produces a wrong value in the CRC field of
// every page, which is exactly the field a player checks first. zlib's crc32()
// is also not available here -- this file is standard library only.
uint32_t ogg_crc32(const uint8_t *data, size_t length) {
  uint32_t crc = 0;
  for (size_t i = 0; i < length; ++i) {
    crc ^= static_cast<uint32_t>(data[i]) << 24;
    for (int bit = 0; bit < 8; ++bit) {
      if ((crc & 0x80000000u) != 0) {
        crc = (crc << 1) ^ 0x04C11DB7u;
      } else {
        crc <<= 1;
      }
    }
  }
  return crc;
}

void push_le16(std::vector<uint8_t> &out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xffu));
  out.push_back(static_cast<uint8_t>((value >> 8u) & 0xffu));
}

void push_le32(std::vector<uint8_t> &out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xffu));
  out.push_back(static_cast<uint8_t>((value >> 8u) & 0xffu));
  out.push_back(static_cast<uint8_t>((value >> 16u) & 0xffu));
  out.push_back(static_cast<uint8_t>((value >> 24u) & 0xffu));
}

void push_le64(std::vector<uint8_t> &out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xffu));
  }
}

void store_le32(uint8_t *dst, uint32_t value) {
  dst[0] = static_cast<uint8_t>(value & 0xffu);
  dst[1] = static_cast<uint8_t>((value >> 8u) & 0xffu);
  dst[2] = static_cast<uint8_t>((value >> 16u) & 0xffu);
  dst[3] = static_cast<uint8_t>((value >> 24u) & 0xffu);
}

bool write_bytes(std::FILE *file, const void *data, size_t length) {
  return length == 0 || std::fwrite(data, 1, length, file) == length;
}

void close_file(std::FILE *&file) {
  if (file) {
    std::fclose(file);
    file = nullptr;
  }
}

// The OpusTags comment header (RFC 7845 section 5.2): magic, the vendor string
// length, the vendor string itself with no NUL terminator, then the number of
// user comments (zero here) and their bodies.
std::vector<uint8_t> make_opus_tags(const OggOpusOptions &options) {
  std::vector<uint8_t> tags;
  tags.reserve(8 + 4 + options.vendor.size() + 4);
  tags.insert(tags.end(), kOpusTagsMagic, kOpusTagsMagic + 8);
  push_le32(tags, static_cast<uint32_t>(options.vendor.size()));
  tags.insert(tags.end(), options.vendor.begin(), options.vendor.end());
  push_le32(tags, 0);
  return tags;
}

}  // namespace

// The 19-octet OpusHead identification header (RFC 7845 section 5.1): magic,
// version, channel count, pre-skip, original sample rate, output gain, channel
// mapping family. Public (see the header) because RTP4-NAT-06 hands the same
// bytes to the platform Opus decoder as `csd-0`.
std::vector<uint8_t> build_opus_head(const OggOpusOptions &options) {
  std::vector<uint8_t> head;
  head.reserve(kOpusHeadSize);
  head.insert(head.end(), kOpusHeadMagic, kOpusHeadMagic + 8);
  head.push_back(kOpusHeadVersion);
  head.push_back(options.channels);
  push_le16(head, static_cast<uint16_t>(options.pre_skip));
  push_le32(head, static_cast<uint32_t>(options.input_sample_rate));
  // Output gain is signed Q7.8 dB; zero means no change. Written as the two
  // octets of a signed 16-bit zero, i.e. also 0x0000.
  push_le16(head, 0);
  // Channel mapping family 0: mono or stereo, stream count 1, coupled count
  // (stereo only) 1, no channel mapping table.
  head.push_back(0);
  return head;
}

OggOpusWriter::~OggOpusWriter() {
  // Closes what is still open and writes nothing: the destructor cannot report
  // an error, so finalize() is the only place the EOS page is written.
  close_file(file_);
}

bool OggOpusWriter::refuse(const std::string &message, std::string &error) {
  error_ = message;
  error = error_;
  return false;
}

bool OggOpusWriter::fail(const std::string &message, std::string &error) {
  error_ = message;
  error = error_;
  failed_ = true;
  close_file(file_);
  return false;
}

bool OggOpusWriter::open(const std::string &path, const OggOpusOptions &options,
                         std::string &error) {
  error_.clear();
  error.clear();
  // Every check below runs before std::fopen and goes through refuse(), which
  // leaves the stream alone: a refused open must not close a writer that is
  // already open. Opening a writer that has been finalized is allowed and
  // starts a fresh stream, the same way WavWriter::open() does.
  if (file_) {
    return refuse("Ogg Opus writer is already open.", error);
  }
  if (path.empty()) {
    return refuse("Ogg Opus path is empty.", error);
  }
  if (options.input_sample_rate != kOpusSampleRate) {
    return refuse("Ogg Opus requires a 48000 Hz input sample rate.", error);
  }
  if (options.channels == 0) {
    return refuse("Ogg Opus channel count must be at least 1.", error);
  }
  // OpusHead carries pre-skip as a 16-bit field (RFC 7845 section 5.1).
  // Truncating a larger value would shift the whole stream by however much the
  // top bits held, so refuse instead of wrapping.
  if (options.pre_skip > std::numeric_limits<uint16_t>::max()) {
    return refuse("Ogg Opus pre-skip does not fit the OpusHead field.", error);
  }
  // OpusTags carries the vendor length as a 32-bit field (RFC 7845 section
  // 5.2); a longer string could not be described by the header.
  if (options.vendor.size() > std::numeric_limits<uint32_t>::max()) {
    return refuse("Ogg Opus vendor string is too long.", error);
  }

  file_ = std::fopen(path.c_str(), "wb");
  if (!file_) {
    return refuse("Unable to open Ogg Opus file.", error);
  }

  path_ = path;
  page_sequence_ = 0;
  last_granule_ = 0;
  failed_ = false;
  finalized_ = false;

  const std::vector<uint8_t> head = build_opus_head(options);
  const std::vector<uint8_t> tags = make_opus_tags(options);
  // Page 0 must carry the identification header and must be marked BOS; both
  // its granule and the OpusTags page's granule are 0 (RFC 7845 section 4).
  if (!writePage(kHeaderBos, 0, head.data(), head.size(), error) ||
      !writePage(0, 0, tags.data(), tags.size(), error)) {
    // The reason is already in `error`. Neither header can hit the "too large"
    // refusal (19 and 29 octets), so the failure here is the write itself and
    // writePage() has closed the stream; closing again is a no-op. The file
    // holds at most one unusable page, so remove it rather than leave a
    // plausible-looking fragment behind.
    close_file(file_);
    const std::string failed_path = path_;
    std::remove(failed_path.c_str());
    return false;
  }
  return true;
}

bool OggOpusWriter::writePacket(const uint8_t *payload, size_t length,
                                uint64_t rtp_timestamp, std::string &error) {
  error.clear();
  if (finalized_) {
    return refuse("Ogg Opus writer is already finalized.", error);
  }
  if (!file_) {
    // Also the state a caller is in after an open() the caller ignored, which
    // is how the non-48 kHz contract is upheld on this side.
    return refuse("Ogg Opus writer is not open.", error);
  }
  if (failed_) {
    error = error_;
    return false;
  }
  if (payload == nullptr || length == 0) {
    // An Opus packet is never empty (RFC 6716 section 3.2); a zero-octet one
    // would be a packet a decoder must reject, so it is not written. The
    // stream stays usable: this is one bad packet, not a broken file.
    return refuse("Ogg Opus packet is empty.", error);
  }
  // The granule position is the RTP timestamp taken as-is. RFC 7587 already
  // defines the Opus RTP timestamp as a count of 48 kHz samples, which is the
  // clock RFC 7845 wants the granule on, so there is no conversion to do. A
  // lost packet simply leaves a gap and the next granule jumps: no attempt is
  // made to fill the timeline in.
  if (!writePage(0, rtp_timestamp, payload, length, error)) {
    return false;
  }
  last_granule_ = rtp_timestamp;
  return true;
}

bool OggOpusWriter::finalize(std::string &error) {
  error.clear();
  if (finalized_) {
    return true;
  }
  if (!file_) {
    if (error_.empty()) {
      error_ = "Ogg Opus writer is not open.";
    }
    error = error_;
    return false;
  }
  if (failed_) {
    error = error_;
    close_file(file_);
    return false;
  }

  // The EOS page carries no packet at all: zero segments, an empty body. A
  // zero-length *Opus* packet is invalid (RFC 6716 section 3.2) and a decoder
  // reaching end-of-stream would try to decode it, whereas a page whose
  // segment count is zero holds nothing for any decoder to attempt -- it is
  // legal Ogg and it is what marks the stream as complete. Its granule is the
  // last granule written, or 0 when no packet was written.
  if (!writePage(kHeaderEos, last_granule_, nullptr, 0, error)) {
    return false;
  }
  if (std::fflush(file_) != 0) {
    return fail("Unable to flush Ogg Opus file.", error);
  }
  if (std::fclose(file_) != 0) {
    file_ = nullptr;
    return fail("Unable to close Ogg Opus file.", error);
  }
  file_ = nullptr;
  finalized_ = true;
  error_.clear();
  return true;
}

bool OggOpusWriter::writePage(uint8_t header_type, uint64_t granule,
                              const uint8_t *packet, size_t length,
                              std::string &error) {
  // Lacing (RFC 3533 section 6): a packet of L octets is described by L / 255
  // lacing values of 255 followed by one final value of L % 255. The final
  // value is always emitted even when it is zero, because a packet whose
  // length is an exact multiple of 255 (255, 510, 765, ...) has to end on a
  // zero-length segment: without that terminator a reader cannot tell the
  // packet ended and keeps concatenating 255-octet segments into it. The
  // card's shorthand "[len/255] * (len/255) + [len%255]" reads as if the last
  // term could be dropped, which loses exactly that terminator.
  //
  //   L = 0   -> [0]           L = 255 -> [255, 0]
  //   L = 5   -> [5]           L = 260 -> [255, 5]
  //                            L = 510 -> [255, 255, 0]
  //
  // `packet == nullptr` is the no-packet form (the EOS page): an empty segment
  // table, not a single zero-length segment, so nothing is announced at all.
  size_t segment_count = 0;
  if (packet != nullptr) {
    segment_count = length / 255 + 1;
    // One lacing value needs one octet, and a page holds at most 255 of them.
    // With the terminator counted, the real limit is 65024 octets per page --
    // 65025 (255 * 255) would need 256. Opus RTP payloads are orders of
    // magnitude smaller, so this is a fail-closed guard against a caller
    // handing over a buffer that no page can describe.
    if (segment_count > kMaxPageSegments) {
      return refuse("Ogg Opus packet is too large for one page.", error);
    }
  }

  std::vector<uint8_t> page;
  page.reserve(kOggPageHeaderSize + segment_count + length);
  page.push_back('O');
  page.push_back('g');
  page.push_back('g');
  page.push_back('S');
  page.push_back(kOggVersion);
  page.push_back(header_type);
  push_le64(page, granule);
  push_le32(page, kOggOpusSerial);
  push_le32(page, page_sequence_);
  const size_t crc_offset = page.size();
  push_le32(page, 0);  // CRC placeholder: the field is zeroed while it is computed
  page.push_back(static_cast<uint8_t>(segment_count));
  if (packet != nullptr) {
    const size_t whole_segments = length / 255;
    for (size_t i = 0; i < whole_segments; ++i) {
      page.push_back(255);
    }
    page.push_back(static_cast<uint8_t>(length % 255));
    if (length > 0) {
      page.insert(page.end(), packet, packet + length);
    }
  }

  // The CRC covers the whole page, header included, with the CRC field holding
  // zero (RFC 3533 section 6).
  const uint32_t crc = ogg_crc32(page.data(), page.size());
  store_le32(page.data() + crc_offset, crc);

  if (!write_bytes(file_, page.data(), page.size())) {
    return fail("Unable to write Ogg Opus page.", error);
  }
  ++page_sequence_;
  return true;
}

}  // namespace layanalyzer::rtp
