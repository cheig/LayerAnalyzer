// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Ogg Opus container writer (RFC 7845) for exported RTP/Opus streams.
//
// Uses only the C++ standard library -- no Wireshark, GLib, JNI or nlohmann
// header -- so the host tests can compile and exercise it on the development
// machine without the Android toolchain (cards/README.md section 4.1, the
// "pure algorithm file" rule that also covers core/, codecs/ and depack/).
//
// The shape follows the other streaming writers in this tree
// (core/WavWriter.h, core/RtppFile.h): open(path, ..., error) first, one call
// per chunk, finalize(error) last, a std::string error out-parameter on every
// method, no exceptions, and an RAII file handle (the destructor closes what
// is still open and never writes anything).
//
// What the writer emits, in order:
//   page 0  BOS, granule 0   one packet: OpusHead
//   page 1  granule 0        one packet: OpusTags
//   page N  granule = the RTP timestamp of the packet, one Opus packet each
//   last    EOS, granule = the last granule written, no packet
// One packet per page is all RFC 3533 requires and keeps the lacing simple;
// RFC 7845 allows an Opus stream to be cut up that way.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

struct OggOpusOptions {
  uint8_t channels = 1;
  uint32_t pre_skip = 312;
  std::string vendor = "LayerAnalyzer";
  uint64_t input_sample_rate = 48000;   // Opus 固定 48 kHz
};

// The 19-octet OpusHead identification header (RFC 7845 section 5.1) for
// `options`, with the field order and widths the RFC fixes: magic, version,
// channel count, pre-skip, original sample rate, output gain, channel mapping
// family. It is the same header the writer puts on page 0.
//
// Exported rather than private because RTP4-NAT-06 returns it a second time as
// the `csd-0` the platform Opus decoder parses, and the header a stream is
// decoded with has to be the header the stream is exported with: one builder,
// so the two can never drift apart.
std::vector<uint8_t> build_opus_head(const OggOpusOptions &options);

class OggOpusWriter {
 public:
  OggOpusWriter() = default;
  ~OggOpusWriter();

  OggOpusWriter(const OggOpusWriter &) = delete;
  OggOpusWriter &operator=(const OggOpusWriter &) = delete;

  // Writes the OpusHead (BOS) and OpusTags pages, then leaves the file open for
  // writePacket(). Fails, without touching any existing writer state, when the
  // writer is already open, when the path is empty, and on the header fields
  // that would silently produce an invalid stream (see the .cpp).
  //
  // input_sample_rate must be 48000, and that is a deliberate deviation from
  // the task card, forced by this frozen signature: RFC 7845 expresses the
  // granule position on the 48 kHz clock and OpusHead's own sample-rate field
  // is informational only, so a 16 kHz (or 8 kHz) input would build a granule
  // timeline off by a factor of three while still looking well formed. The
  // card's test 4 asks for a non-48 kHz *rtp_timestamp* to be rejected, but a
  // bare uint64_t carries no unit, so writePacket() cannot see it. Rejecting
  // the rate here is the only place the writer can still catch it; the
  // writePacket() half of that contract is upheld by refusing to write on a
  // writer that is not open, which is what a caller that ignored this failure
  // ends up holding. See OggOpusWriterTest.cpp for the observable contract.
  bool open(const std::string &path, const OggOpusOptions &options, std::string &error);

  // 每个 RTP 包一个 Ogg packet；granule 用 RTP 时间戳（48 kHz）转成 48 kHz 采样数
  bool writePacket(const uint8_t *payload, size_t length, uint64_t rtp_timestamp,
                   std::string &error);

  // Writes the EOS page and closes the file. Idempotent: a second call returns
  // true without writing another page.
  bool finalize(std::string &error);

  const std::string &error() const { return error_; }
  const std::string &path() const { return path_; }

 private:
  // Records `message` and returns false while leaving the stream open. Used
  // for refusals that are the caller's mistake and that do not make the pages
  // already written unusable -- an empty packet, an oversized one -- so the
  // caller can skip that packet and carry on with the stream.
  bool refuse(const std::string &message, std::string &error);

  // Records `message`, closes the stream and returns false, so that a stream
  // that failed mid-page is never left looking like a good one.
  bool fail(const std::string &message, std::string &error);

  // One Ogg page. `packet == nullptr` is the "this page carries no packet"
  // form used for EOS; it emits an empty segment table.
  bool writePage(uint8_t header_type, uint64_t granule, const uint8_t *packet,
                 size_t length, std::string &error);

  std::FILE *file_ = nullptr;
  std::string path_;
  std::string error_;
  uint32_t page_sequence_ = 0;
  uint64_t last_granule_ = 0;
  bool failed_ = false;
  bool finalized_ = false;
};

}  // namespace layanalyzer::rtp
