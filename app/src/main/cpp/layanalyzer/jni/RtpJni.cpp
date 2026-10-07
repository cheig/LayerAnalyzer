// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// RTP stream discovery and payload-decoding JNI endpoints.
//
// RTP1-ARCH-01 froze the entry points in
// NativeEngine.kt and model/RtpModels.kt RTP1-NAT-04
// implements `scanRtpStreams` (frame traversal + `rtp` tap collector +
// serialisation + `rtp_last_scan` publication). RTP1-NAT-05 implements the
// process-wide heuristic toggle. RTP1-NAT-06 implements the session-level
// payload-override table (`setRtpPayloadOverrides`) and wires
// codec / codecSource / clockRate / decodable into `scanRtpStreams`.
// Keep business logic out of this file.
#include <wsutil/nstime.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <system_error>
#include <utility>
#include <vector>

#include <epan/disabled_protos.h>

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/internal/EngineState.h"
#include "layanalyzer/internal/TextUtils.h"
#include "layanalyzer/session/WiresharkSession.h"
#include "layanalyzer/projection/ProtocolProjection.h"
#include "layanalyzer/rtp/RtpDecodeRequest.h"
#include "layanalyzer/rtp/RtpMediaSnapshot.h"
#include "layanalyzer/rtp/RtpPayloadExtractor.h"
#include "layanalyzer/rtp/RtpScanSnapshot.h"
#include "layanalyzer/rtp/RtpSetupInfo.h"
#include "layanalyzer/rtp/RtpStreamCollector.h"
#include "layanalyzer/rtp/core/FrameMapWriter.h"
#include "layanalyzer/rtp/core/PeaksBuilder.h"
#include "layanalyzer/rtp/core/RtpCodecNames.h"
#include "layanalyzer/rtp/core/RtpDecodability.h"
#include "layanalyzer/rtp/core/DtmfParser.h"
#include "layanalyzer/rtp/core/FidxFile.h"
#include "layanalyzer/rtp/core/RtpMediaDecoder.h"
#include "layanalyzer/rtp/core/RtpPayloadOverrides.h"
#include "layanalyzer/rtp/core/RtpAudioRenderer.h"
#include "layanalyzer/rtp/core/RtppFile.h"
#include "layanalyzer/rtp/core/RtppIndex.h"
#include "layanalyzer/rtp/core/VidxFile.h"
#include "layanalyzer/rtp/core/WavWriter.h"
#include "layanalyzer/rtp/depack/AmrDepack.h"
#include "layanalyzer/rtp/depack/H264Depack.h"
#include "layanalyzer/rtp/depack/H265Depack.h"
#include "layanalyzer/rtp/depack/SpsParser.h"
#include "layanalyzer/rtp/depack/VideoAccessUnitBuilder.h"
#include "layanalyzer/rtp/io/OggOpusWriter.h"

namespace {
// `RtpStreamAnalysis::primaryPayloadType()` 在没有任何候选（全部是
// CN/telephone-event，或一个包都没收到）时返回 PT_UNDEFINED（0xFFFFFFFF）；
// 序列化成 -1 交给 Kotlin。
constexpr uint32_t kRtpPtUndefined = 0xFFFFFFFFu;

// Opus' RTP clock and its Ogg granule clock are both 48 kHz (RFC 7587 section
// 4.1, RFC 7845 section 4). This is the same rate `run_codec_frames_extraction`
// reports as the Opus `sampleRate`, and the clock OpusHead's pre-skip is
// counted on, so the two stay tied together by one constant.
constexpr uint64_t kOpusClockRate = 48000;

// The seek pre-roll `extractRtpCodecFrames` hands the platform Opus decoder as
// `csd-2`, in nanoseconds (MediaCodec reads both `csd-1` and `csd-2` as 64-bit
// little-endian nanosecond counts). RFC 7845 section 4.2 fixes the value a
// decoder should use at 80 ms, and nothing in the RTP stream names another one.
constexpr uint64_t kOpusSeekPrerollNs = 80000000ull;

enum class RtpRawExportOrder { Sequence, Arrival };

struct RtpRawExportRequest {
  uint64_t scan_generation = 0;
  std::string stream_id;
  RtpRawExportOrder order = RtpRawExportOrder::Sequence;
};

bool parse_rtp_raw_export_request(const std::string &text,
                                  RtpRawExportRequest &request,
                                  std::string &error) {
  const json parsed = json::parse(text, nullptr, false);
  if (parsed.is_discarded() || !parsed.is_object()) {
    error = "Invalid RTP raw export request.";
    return false;
  }

  const auto generation_it = parsed.find("scanGeneration");
  if (generation_it == parsed.end() || !generation_it->is_number_integer()) {
    error = "scanGeneration is required and must be an integer.";
    return false;
  }
  if (generation_it->is_number_unsigned()) {
    request.scan_generation = generation_it->get<uint64_t>();
  } else {
    const int64_t generation = generation_it->get<int64_t>();
    if (generation < 0) {
      error = "scanGeneration must be a non-negative integer.";
      return false;
    }
    request.scan_generation = static_cast<uint64_t>(generation);
  }

  const auto stream_it = parsed.find("streamId");
  if (stream_it == parsed.end() || !stream_it->is_string() ||
      stream_it->get_ref<const std::string &>().empty()) {
    error = "streamId is required and must be a non-empty string.";
    return false;
  }
  request.stream_id = stream_it->get<std::string>();

  const auto order_it = parsed.find("order");
  if (order_it == parsed.end()) {
    request.order = RtpRawExportOrder::Sequence;
  } else if (!order_it->is_string()) {
    error = "order must be seq or arrival.";
    return false;
  } else {
    const std::string order = order_it->get<std::string>();
    if (order == "seq") {
      request.order = RtpRawExportOrder::Sequence;
    } else if (order == "arrival") {
      request.order = RtpRawExportOrder::Arrival;
    } else {
      error = "order must be seq or arrival.";
      return false;
    }
  }

  error.clear();
  return true;
}

class ScopedPathRemoval {
 public:
  explicit ScopedPathRemoval(std::filesystem::path path)
      : path_(std::move(path)) {}

  ~ScopedPathRemoval() {
    if (!active_ || path_.empty()) return;
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  void release() { active_ = false; }

 private:
  std::filesystem::path path_;
  bool active_ = true;
};

bool create_unique_work_directory(const std::filesystem::path &parent,
                                  const std::string &output_name,
                                  std::filesystem::path &work_directory,
                                  std::string &error) {
  static std::atomic<uint64_t> sequence{0};
  const uint64_t tick = static_cast<uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  for (uint32_t attempt = 0; attempt < 100; ++attempt) {
    const std::string name =
        "." + output_name + ".rtpp-export-" + std::to_string(tick) + "-" +
        std::to_string(sequence.fetch_add(1));
    std::filesystem::path candidate = parent / name;
    std::error_code create_error;
    if (std::filesystem::create_directory(candidate, create_error)) {
      work_directory = std::move(candidate);
      error.clear();
      return true;
    }
    if (create_error) {
      error = "Unable to create RTP raw export work directory.";
      return false;
    }
  }
  error = "Unable to allocate an RTP raw export work directory.";
  return false;
}

bool write_raw_payload(std::FILE *output, const uint8_t *payload,
                       size_t length, uint64_t &total_bytes,
                       std::string &error) {
  if (length != 0 && std::fwrite(payload, 1, length, output) != length) {
    error = "Unable to write RTP raw payload output.";
    return false;
  }
  if (length > std::numeric_limits<uint64_t>::max() - total_bytes) {
    error = "RTP raw payload output is too large.";
    return false;
  }
  total_bytes += static_cast<uint64_t>(length);
  return true;
}

bool close_raw_output(std::FILE *&output, const std::filesystem::path &path,
                      std::string &error) {
  bool ok = output != nullptr;
  if (output && std::fflush(output) != 0) {
    ok = false;
  }
  if (output && std::fclose(output) != 0) {
    ok = false;
  }
  output = nullptr;
  if (!ok) {
    std::error_code remove_error;
    std::filesystem::remove(path, remove_error);
    error = "Unable to finalize RTP raw payload output.";
    return false;
  }
  return true;
}

uint32_t sample_rate_for_codec(const std::string &codec) {
  if (codec == "g711A" || codec == "g711U") {
    return 8000;
  }
  if (codec == "L16") {
    return 44100;
  }
  return 0;
}

// RTP5-NAT-01：视频流的时间戳速率。RFC 6184 / 7798 / GB28181 都用 90 kHz 时钟，
// 也就是 M5 的 VideoAuBuilderOptions::timestamp_rate 与 RTP5-NAT-03 的 PTS 换算
// 所用的那个 90000。
constexpr uint32_t kRtpVideoTimestampRate = 90000;

// RTP5-NAT-01：规范 ID 是否属于 kSupportedVideoCodecs。用一份小循环而不是
// std::find，是为了让「视频编码集合只有 kSupportedVideoCodecs 一处定义」这件事
// 在调用点也看得出来（不引入第二张表）。
bool is_supported_video_codec(const std::string &codec) {
  for (const char *id : layanalyzer::rtp::kSupportedVideoCodecs) {
    if (codec == id) {
      return true;
    }
  }
  return false;
}

std::string join_path(const std::string &directory, const std::string &name) {
  if (directory.empty()) {
    return name;
  }
  const char last = directory.back();
  if (last == '/' || last == '\\') {
    return directory + name;
  }
  return directory + "/" + name;
}

bool remove_request_dir(const std::string &out_dir) {
  if (out_dir.empty()) {
    return true;
  }
  std::error_code error;
  std::filesystem::remove_all(std::filesystem::path(out_dir), error);
  return !error;
}

const char *unsupported_reason(
    const layanalyzer::rtp::RtpStreamMediaInfo &media) {
  if (media.is_srtp ||
      media.decodable == layanalyzer::rtp::RtpDecodability::Srtp) {
    return "srtp";
  }
  if (media.decodable == layanalyzer::rtp::RtpDecodability::NeedsMapping) {
    return "needsMapping";
  }
  if (media.decodable == layanalyzer::rtp::RtpDecodability::Unsupported) {
    return "unsupported";
  }
  return nullptr;
}

// `exportRtpPayloadRaw` dumps `rtp.payload` byte for byte and runs no codec, so
// a codec this build cannot decode is still exportable -- with
// `-PlayanalyzerEnableG729=false` a G.729 stream's bitstream is exactly the
// bytes the tap hands over. Only a missing bitstream is a rejection here.
// `unsupported_reason()` above keeps answering the decoder question for the
// paths that really decode.
const char *raw_export_unsupported_reason(
    const layanalyzer::rtp::RtpStreamMediaInfo &media) {
  if (media.is_srtp ||
      media.decodable == layanalyzer::rtp::RtpDecodability::Srtp) {
    return "srtp";
  }
  if (media.decodable == layanalyzer::rtp::RtpDecodability::NeedsMapping) {
    return "needsMapping";
  }
  return nullptr;
}

uint32_t estimate_record_at_ms(
    const layanalyzer::rtp::RtppRecordHeader &record,
    const layanalyzer::rtp::RtppRecordHeader &first_decoded,
    layanalyzer::rtp::RtpTimingMode timing, unsigned timestamp_rate) {
  double milliseconds = 0.0;
  if (timing == layanalyzer::rtp::RtpTimingMode::Uninterrupted) {
    milliseconds =
        (record.arrival_rel_sec - first_decoded.arrival_rel_sec) * 1000.0;
  } else if (timestamp_rate != 0 && record.ext_ts >= first_decoded.ext_ts) {
    milliseconds = static_cast<double>(record.ext_ts - first_decoded.ext_ts) *
                   1000.0 / static_cast<double>(timestamp_rate);
  } else {
    milliseconds =
        (record.arrival_rel_sec - first_decoded.arrival_rel_sec) * 1000.0;
  }
  if (!(milliseconds > 0.0)) {
    return 0;
  }
  if (milliseconds >=
      static_cast<double>(std::numeric_limits<uint32_t>::max())) {
    return std::numeric_limits<uint32_t>::max();
  }
  return static_cast<uint32_t>(milliseconds);
}

uint32_t record_duration_ms(
    const layanalyzer::rtp::RtppRecordHeader &record,
    const layanalyzer::rtp::RtppRecordHeader *next, unsigned timestamp_rate) {
  if (next == nullptr || timestamp_rate == 0 ||
      next->ext_ts <= record.ext_ts) {
    return 0;
  }
  const uint64_t timestamp_delta = next->ext_ts - record.ext_ts;
  const uint64_t max_timestamp_delta =
      static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) *
      timestamp_rate / 1000u;
  if (timestamp_delta >= max_timestamp_delta) {
    return std::numeric_limits<uint32_t>::max();
  }
  const uint64_t milliseconds =
      timestamp_delta * 1000u / timestamp_rate;
  return milliseconds > std::numeric_limits<uint32_t>::max()
             ? std::numeric_limits<uint32_t>::max()
             : static_cast<uint32_t>(milliseconds);
}

const layanalyzer::rtp::RtpCollectedStream *find_scan_stream(
    const std::shared_ptr<const layanalyzer::rtp::RtpScanSnapshot> &snapshot,
    const std::string &stream_id) {
  if (!snapshot || stream_id.size() < 2 || stream_id[0] != 's') {
    return nullptr;
  }
  size_t index = 0;
  for (size_t position = 1; position < stream_id.size(); ++position) {
    const char digit = stream_id[position];
    if (digit < '0' || digit > '9') {
      return nullptr;
    }
    index = index * 10u + static_cast<size_t>(digit - '0');
  }
  return index < snapshot->streams.size() ? &snapshot->streams[index] : nullptr;
}

// ---------------------------------------------------------------------------
// RTP4-KT-02: `csd` encoding helpers.
//
// The codec-specific data `extractRtpCodecFrames` returns crosses JNI as JSON,
// so its binary half (the OpusHead) travels base64-encoded. The encoder is
// written here rather than taken from GLib: this is ten lines of pure
// arithmetic over a short byte vector, and keeping it local leaves the host
// tests and the request contract with one fewer dependency to reason about.
// ---------------------------------------------------------------------------

// Standard base64 with padding (RFC 4648 section 4) -- the alphabet and the
// padding `android.util.Base64.DEFAULT` decodes.
std::string base64_encode(const std::vector<uint8_t> &bytes) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve((bytes.size() + 2u) / 3u * 4u);

  size_t index = 0;
  while (index + 3u <= bytes.size()) {
    const uint32_t block = (static_cast<uint32_t>(bytes[index]) << 16u) |
                           (static_cast<uint32_t>(bytes[index + 1u]) << 8u) |
                           static_cast<uint32_t>(bytes[index + 2u]);
    out.push_back(kAlphabet[(block >> 18u) & 0x3fu]);
    out.push_back(kAlphabet[(block >> 12u) & 0x3fu]);
    out.push_back(kAlphabet[(block >> 6u) & 0x3fu]);
    out.push_back(kAlphabet[block & 0x3fu]);
    index += 3u;
  }

  const size_t remaining = bytes.size() - index;
  if (remaining == 1u) {
    const uint32_t block = static_cast<uint32_t>(bytes[index]) << 16u;
    out.push_back(kAlphabet[(block >> 18u) & 0x3fu]);
    out.push_back(kAlphabet[(block >> 12u) & 0x3fu]);
    out.push_back('=');
    out.push_back('=');
  } else if (remaining == 2u) {
    const uint32_t block = (static_cast<uint32_t>(bytes[index]) << 16u) |
                           (static_cast<uint32_t>(bytes[index + 1u]) << 8u);
    out.push_back(kAlphabet[(block >> 18u) & 0x3fu]);
    out.push_back(kAlphabet[(block >> 12u) & 0x3fu]);
    out.push_back(kAlphabet[(block >> 6u) & 0x3fu]);
    out.push_back('=');
  }
  return out;
}

// A 64-bit value as the eight little-endian octets MediaCodec's Opus decoder
// reads `csd-1` (pre-skip) and `csd-2` (seek pre-roll) as.
std::vector<uint8_t> le_u64_bytes(uint64_t value) {
  std::vector<uint8_t> bytes(8u, 0u);
  for (size_t index = 0; index < 8u; ++index) {
    bytes[index] = static_cast<uint8_t>((value >> (8u * index)) & 0xffu);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// RTP4-NAT-06: `extractRtpCodecFrames` / `exportRtpContainer`.
//
// Both endpoints do the same thing up to the point where they write: resolve
// the stream out of the media snapshot, route it by codec id, extract this
// one stream's payloads into a private `.rtpp` work directory, and turn those
// records into an in-memory `.frames` blob plus its `.fidx` entries. Only the
// last step differs (two files vs. one container), so everything before it
// lives in the shared helpers below rather than being written twice.
// ---------------------------------------------------------------------------

// Where the stream's packets have to go. Decided from the canonical codec id
// and never from `decodable`: `rtp_codec_is_supported_audio` still holds only
// M1's three codecs (core/RtpCodecNames.h `kSupportedAudioCodecs`), and an
// existing test pins that list, so `decodable` reports `unsupported` for AMR,
// AMR-WB and Opus too. Routing on it would send every MEDIACODEC stream to
// `nativeDecode`. Widening `kSupportedAudioCodecs` is RTP4-KT-05's job.
enum class RtpCodecRoute { AmrNb, AmrWb, Opus };

struct RtpCodecFramesRequest {
  uint64_t scan_generation = 0;
  std::string stream_id;
  // Normalized to one of "auto" / "octet" / "be".
  std::string amr_mode = "auto";
  // The SDP `fmtp octet-align=1` value, when the caller already knows it.
  // Callers may obtain it from readRtpSetupInfo/readSdpFmtpValues; codec-frame
  // extraction still uses this explicit field and does not read SDP itself.
  bool has_amr_octet_aligned = false;
  bool amr_octet_aligned = false;
  bool amr_crc = false;
  bool amr_interleaved = false;
  // exportRtpContainer only. Empty for extractRtpCodecFrames.
  std::string format;
};

bool parse_rtp_codec_frames_request(const std::string &text,
                                    RtpCodecFramesRequest &request,
                                    std::string &error) {
  const json parsed = json::parse(text, nullptr, false);
  if (parsed.is_discarded() || !parsed.is_object()) {
    error = "Invalid RTP codec frames request.";
    return false;
  }

  const auto generation_it = parsed.find("scanGeneration");
  if (generation_it == parsed.end() || !generation_it->is_number_integer()) {
    error = "scanGeneration is required and must be an integer.";
    return false;
  }
  if (generation_it->is_number_unsigned()) {
    request.scan_generation = generation_it->get<uint64_t>();
  } else {
    const int64_t generation = generation_it->get<int64_t>();
    if (generation < 0) {
      error = "scanGeneration must be a non-negative integer.";
      return false;
    }
    request.scan_generation = static_cast<uint64_t>(generation);
  }

  const auto stream_it = parsed.find("streamId");
  if (stream_it == parsed.end() || !stream_it->is_string() ||
      stream_it->get_ref<const std::string &>().empty()) {
    error = "streamId is required and must be a non-empty string.";
    return false;
  }
  request.stream_id = stream_it->get<std::string>();

  const auto mode_it = parsed.find("amrMode");
  if (mode_it != parsed.end()) {
    if (!mode_it->is_string()) {
      error = "amrMode must be auto, octet or be.";
      return false;
    }
    // The card documents "auto" as the default and asks for the long SDP
    // spellings to be accepted too, so they are folded here once instead of at
    // every use site.
    const std::string mode = mode_it->get<std::string>();
    if (mode == "auto") {
      request.amr_mode = "auto";
    } else if (mode == "octet" || mode == "octetAligned") {
      request.amr_mode = "octet";
    } else if (mode == "be" || mode == "bandwidthEfficient") {
      request.amr_mode = "be";
    } else {
      error = "amrMode must be auto, octet or be.";
      return false;
    }
  }

  const auto octet_aligned_it = parsed.find("amrOctetAligned");
  if (octet_aligned_it != parsed.end() && !octet_aligned_it->is_null()) {
    if (!octet_aligned_it->is_boolean()) {
      error = "amrOctetAligned must be a boolean or null.";
      return false;
    }
    request.has_amr_octet_aligned = true;
    request.amr_octet_aligned = octet_aligned_it->get<bool>();
  }

  const auto crc_it = parsed.find("amrCrc");
  if (crc_it != parsed.end() && !crc_it->is_null()) {
    if (!crc_it->is_boolean()) {
      error = "amrCrc must be a boolean.";
      return false;
    }
    request.amr_crc = crc_it->get<bool>();
  }

  const auto interleaved_it = parsed.find("amrInterleaved");
  if (interleaved_it != parsed.end() && !interleaved_it->is_null()) {
    if (!interleaved_it->is_boolean()) {
      error = "amrInterleaved must be a boolean.";
      return false;
    }
    request.amr_interleaved = interleaved_it->get<bool>();
  }

  const auto format_it = parsed.find("format");
  if (format_it != parsed.end() && !format_it->is_null()) {
    if (!format_it->is_string()) {
      error = "format must be amr, awb or opus.";
      return false;
    }
    request.format = format_it->get<std::string>();
  }

  error.clear();
  return true;
}

const char *codec_frames_reject_reason(
    const layanalyzer::rtp::RtpStreamMediaInfo &media) {
  if (media.is_srtp ||
      media.decodable == layanalyzer::rtp::RtpDecodability::Srtp) {
    return "srtp";
  }
  if (media.decodable == layanalyzer::rtp::RtpDecodability::NeedsMapping) {
    return "needsMapping";
  }
  // `decodable == Unsupported` is deliberately *not* a rejection here: AMR,
  // AMR-WB and Opus are all reported that way today. Routing decides.
  return nullptr;
}

struct RtpCodecFramesContext {
  layanalyzer::rtp::RtpStreamKey key;
  layanalyzer::rtp::RtpStreamMediaInfo media;
  RtpCodecRoute route = RtpCodecRoute::AmrNb;
  bool limit_to_display_filter = false;
};

// Snapshot lookup, shared by every endpoint that is handed a stream id: the
// freshness rules are decodeRtpAudio's, including the display-filter
// comparison, because they guard exactly the same assumption -- a stream id is
// an index into the published snapshot.
//
// On failure `error` is one of the two short codes the card fixes for a
// resolution failure, in its order: "staleScan", "notFound". Everything after
// the lookup -- the codec rejection reasons and the codec routing -- is the
// caller's business, because RTP4-NAT-07 resolves the same stream with none of
// it.
bool resolve_scan_stream(WiresharkSession *session, uint64_t scan_generation,
                         const std::string &stream_id,
                         RtpCodecFramesContext &context, std::string &error) {
  const uint64_t current_generation =
      session->rtp_scan_generation.load(std::memory_order_acquire);
  if (scan_generation != current_generation) {
    error = "staleScan";
    return false;
  }

  std::shared_ptr<const layanalyzer::rtp::RtpMediaSnapshot> media_snapshot;
  {
    std::lock_guard<std::mutex> lk(session->rtp_media_mutex);
    media_snapshot = session->rtp_last_media;
  }
  if (!media_snapshot) {
    error = "notFound";
    return false;
  }
  if (media_snapshot->scan_generation != scan_generation) {
    error = "staleScan";
    return false;
  }
  if (media_snapshot->limit_to_display_filter) {
    std::shared_lock<std::shared_mutex> lock(session->state_mutex);
    if (media_snapshot->filter_expression != session->active_filter) {
      error = "staleScan";
      return false;
    }
  }

  const auto key_it = media_snapshot->stream_keys.find(stream_id);
  const auto media_it = media_snapshot->media.find(stream_id);
  if (key_it == media_snapshot->stream_keys.end() ||
      media_it == media_snapshot->media.end()) {
    error = "notFound";
    return false;
  }

  context.key = key_it->second;
  context.media = media_it->second;
  context.limit_to_display_filter = media_snapshot->limit_to_display_filter;
  error.clear();
  return true;
}

// On failure `error` is one of the short codes the card fixes, in its order:
// "staleScan", "notFound", "srtp", "needsMapping", "nativeDecode".
bool resolve_codec_frames_stream(WiresharkSession *session,
                                 const RtpCodecFramesRequest &request,
                                 RtpCodecFramesContext &context,
                                 std::string &error) {
  if (!resolve_scan_stream(session, request.scan_generation, request.stream_id,
                           context, error)) {
    return false;
  }

  const char *reason = codec_frames_reject_reason(context.media);
  if (reason != nullptr) {
    error = reason;
    return false;
  }

  const std::string &codec = context.media.codec;
  if (codec == "AMR") {
    context.route = RtpCodecRoute::AmrNb;
  } else if (codec == "AMR-WB") {
    context.route = RtpCodecRoute::AmrWb;
  } else if (codec == "opus") {
    context.route = RtpCodecRoute::Opus;
  } else {
    // Everything the native decoder already handles goes through
    // `decodeRtpAudio`, not here: G.711, L16, G.722, the G.726 variants
    // (both packing families), G.729 and iLBC. The card names only
    // G.722/G.726/G.729/iLBC, but "the whole native-decode set" is the rule
    // that keeps this table and KT-02's route table agreeing on every codec.
    error = "nativeDecode";
    return false;
  }

  error.clear();
  return true;
}

// Only the packets carrying the stream's primary codec take part. This mirrors
// `decodeRtpAudio`'s record filter, and it is not optional even though the card
// does not spell it out: a real AMR/Opus stream interleaves RFC 4733
// telephone-event packets (and sometimes CN), and handing a DTMF payload to
// `depack_amr` would either produce a bogus frame or -- because a depack error
// fails the whole extraction -- make the endpoint unusable on exactly the
// streams it exists for.
bool codec_frames_is_primary_record(
    const layanalyzer::rtp::RtpStreamMediaInfo &media, uint32_t payload_type) {
  if (payload_type == 13u || payload_type == 19u) {
    return false;  // CN / CN(old)
  }
  if (media.telephone_event_pt >= 0 &&
      payload_type == static_cast<uint32_t>(media.telephone_event_pt)) {
    return false;
  }
  if (media.primary_pt >= 0 &&
      payload_type != static_cast<uint32_t>(media.primary_pt)) {
    return false;
  }
  return true;
}

// 0x04 = late: the entry arrived more than 200 ms after its earlier sequence
// neighbour (the card's definition). An annotation only -- it can never fail an
// extraction, which is why the helper returns nothing.
//
// "Sequence neighbour" is taken as the previous entry of the list, which is in
// arrival order (the `.rtpp` is written in tap order, see C15). Walking the
// stream in true sequence order would need the `.rtpp` index; the card's point
// is that the annotation is available from `arrival_rel_sec` alone.
void mark_late_codec_frames(std::vector<layanalyzer::rtp::FidxEntry> &entries) {
  constexpr double kLateThresholdSec = 0.2;
  for (size_t index = 1; index < entries.size(); ++index) {
    if (entries[index].arrival_rel - entries[index - 1].arrival_rel >
        kLateThresholdSec) {
      entries[index].flags |= layanalyzer::rtp::kFidxFlagLate;
    }
  }
}

struct RtpCodecFramesResult {
  std::string error;
  bool cancelled = false;
  std::string codec;
  std::string mime;
  uint32_t sample_rate = 0;
  uint32_t channels = 1;
  // "octet" / "be"; empty for Opus, where the field is meaningless.
  std::string detected_amr_mode;
  std::vector<uint8_t> frames;  // the `.frames` blob, in entry order
  std::vector<layanalyzer::rtp::FidxEntry> entries;
  uint64_t speech_lost_frames = 0;
  uint64_t no_data_frames = 0;
  uint64_t zero_payload_records = 0;
};

// Request params > (caller-supplied) SDP value > auto-detection over the first
// 50 packets, per the card. The detector is only consulted for "auto"; its
// result never returns AmrMode::Auto.
bool resolve_amr_octet_aligned(
    const RtpCodecFramesRequest &request, bool is_wb,
    const std::vector<layanalyzer::rtp::RtppFileRecord> &records,
    const std::vector<size_t> &selected) {
  if (request.amr_mode == "octet") return true;
  if (request.amr_mode == "be") return false;
  if (request.has_amr_octet_aligned) return request.amr_octet_aligned;

  layanalyzer::rtp::AmrModeDetector detector;
  const size_t limit = std::min<size_t>(selected.size(), 50);
  for (size_t index = 0; index < limit; ++index) {
    const layanalyzer::rtp::RtppFileRecord &record = records[selected[index]];
    detector.observe(record.payload.data(), record.payload.size(), is_wb);
  }
  return detector.result() == layanalyzer::rtp::AmrMode::OctetAligned;
}

// The shared body. Fills `result` with the whole `.frames` blob and its
// `.fidx` entries. Returns false on a hard error (result.error) or on
// cancellation (result.cancelled); the caller decides what to do with the
// already-created output directory.
bool run_codec_frames_extraction(
    WiresharkSession *session, const RtpCodecFramesContext &context,
    const RtpCodecFramesRequest &request, const std::string &work_parent,
    const std::function<bool(uint32_t, uint32_t)> &report_progress,
    RtpCodecFramesResult &result) {
  using layanalyzer::rtp::FidxEntry;

  result.codec = context.media.codec;
  const bool is_wb = context.route == RtpCodecRoute::AmrWb;
  if (context.route == RtpCodecRoute::Opus) {
    result.mime = "audio/opus";
    result.sample_rate = 48000;
  } else if (is_wb) {
    result.mime = "audio/amr-wb";
    result.sample_rate = 16000;
  } else {
    result.mime = "audio/amr";
    result.sample_rate = 8000;
  }
  result.channels = 1;

  std::vector<int> frames;
  if (context.limit_to_display_filter) {
    frames = snapshot_visible_frames(session);
  } else {
    frames.reserve(session->frame_offsets.size());
    for (size_t index = 0; index < session->frame_offsets.size(); ++index) {
      frames.push_back(static_cast<int>(index));
    }
  }

  // The `.rtpp` is a means to an end here, so it goes into a private hidden
  // directory that is removed on every path out -- success included. `outDir`
  // keeps only the files the caller asked for.
  std::filesystem::path work_directory;
  std::string work_error;
  if (!create_unique_work_directory(std::filesystem::path(work_parent),
                                    request.stream_id, work_directory,
                                    work_error)) {
    result.error = work_error;
    return false;
  }
  ScopedPathRemoval work_cleanup(work_directory);

  layanalyzer::rtp::RtpExtractionRequest extraction_request;
  extraction_request.out_dir = work_directory.string();
  extraction_request.keys.push_back(context.key);
  extraction_request.stream_ids[context.key] = request.stream_id;

  const uint64_t cancel_generation = current_cancel_generation();
  layanalyzer::rtp::RtpExtractionResult extraction =
      layanalyzer::rtp::extract_rtp_payloads(
          session, frames, extraction_request,
          [&](uint32_t done, uint32_t total) {
            if (!report_progress) return true;
            uint32_t percent = 80;
            if (total != 0) {
              percent = static_cast<uint32_t>(std::min<uint64_t>(
                  80u, static_cast<uint64_t>(done) * 80u / total));
            }
            return report_progress(percent, 100);
          },
          cancel_generation);
  if (extraction.cancelled) {
    result.cancelled = true;
    return false;
  }
  if (!extraction.error.empty()) {
    result.error = extraction.error;
    return false;
  }

  const auto rtpp_it = extraction.rtpp_paths.find(request.stream_id);
  if (rtpp_it == extraction.rtpp_paths.end()) {
    result.error = "RTP payload output is missing.";
    return false;
  }

  layanalyzer::rtp::RtppReadResult records;
  std::string file_error;
  if (!layanalyzer::rtp::read_rtpp_file(rtpp_it->second, records, file_error)) {
    result.error = file_error;
    return false;
  }
  if (records.records.empty()) {
    result.error = "No RTP payload records were extracted.";
    return false;
  }

  std::vector<size_t> selected;
  selected.reserve(records.records.size());
  for (size_t index = 0; index < records.records.size(); ++index) {
    if (codec_frames_is_primary_record(context.media,
                                       records.records[index].header.pt)) {
      selected.push_back(index);
    }
  }
  if (selected.empty()) {
    result.error = "No RTP payload records were extracted.";
    return false;
  }

  // Decided once, before any frame is written: the packing mode is a
  // stream-level property, and the card wants the final choice reported in
  // `detectedAmrMode` whether it came from the request, from the SDP value the
  // caller passed in, or from auto-detection.
  bool amr_octet_aligned = false;
  if (context.route != RtpCodecRoute::Opus) {
    amr_octet_aligned =
        resolve_amr_octet_aligned(request, is_wb, records.records, selected);
    result.detected_amr_mode = amr_octet_aligned ? "octet" : "be";
  }

  const uint32_t total_records = static_cast<uint32_t>(selected.size());
  std::vector<uint8_t> frame_bytes;
  std::vector<FidxEntry> entries;
  entries.reserve(selected.size());

  for (size_t index = 0; index < selected.size(); ++index) {
    if (long_operation_cancelled(cancel_generation)) {
      result.cancelled = true;
      return false;
    }
    // Second half of the progress bar, mirroring decodeRtpAudio.
    if (report_progress &&
        ((index + 1) % 256u == 0 || index + 1 == selected.size())) {
      const uint32_t percent = static_cast<uint32_t>(
          80u + std::min<uint64_t>(20u,
                                   static_cast<uint64_t>(index + 1) * 20u /
                                       total_records));
      if (!report_progress(percent, 100)) {
        result.cancelled = true;
        return false;
      }
    }

    const layanalyzer::rtp::RtppFileRecord &record =
        records.records[selected[index]];

    if (context.route == RtpCodecRoute::Opus) {
      // One RTP packet = one Opus packet = one `.frames` record.
      if (record.payload.empty()) {
        // A zero-length Opus payload is a malformed packet, not a lost one:
        // there is no packet for MediaCodec to consume and no packet the
        // sender ever produced at that slot, so it is skipped rather than
        // turned into a `lost` placeholder the way an AMR NO_DATA packet is.
        // `extract_rtp_payloads` already drops zero-length payloads upstream
        // (RtpExtractionResult.zero_payload_packets), so this is a
        // belt-and-braces guard rather than the common path.
        ++result.zero_payload_records;
        continue;
      }
      FidxEntry entry;
      entry.offset = frame_bytes.size();
      entry.length = static_cast<uint32_t>(record.payload.size());
      entry.frame = record.header.frame;
      entry.ext_ts = record.header.ext_ts;
      entry.arrival_rel = record.header.arrival_rel_sec;
      entry.flags = 0x00;
      frame_bytes.insert(frame_bytes.end(), record.payload.begin(),
                         record.payload.end());
      entries.push_back(entry);
      continue;
    }

    const layanalyzer::rtp::AmrDepackResult depacked =
        layanalyzer::rtp::depack_amr(record.payload.data(),
                                     record.payload.size(), is_wb,
                                     amr_octet_aligned, request.amr_crc,
                                     request.amr_interleaved);
    if (!depacked.error.empty()) {
      // Fail the whole extraction, do not skip the packet: "unsupported: crc"
      // has to reach the caller verbatim, and a truncated payload means the
      // frame list we would hand MediaCodec no longer matches the stream.
      result.error = depacked.error;
      return false;
    }

    // One RTP packet may carry several AMR frames (RFC 4867 section 4.4.1), and
    // they are consecutive 20 ms frames. They must not share one RTP
    // timestamp: the renderer would read the later ones as duplicates of the
    // first and drop them. Staggering by the frame duration (8 kHz x 20 ms =
    // 160 for AMR-NB, 16 kHz x 20 ms = 320 for AMR-WB) is what makes the
    // timeline advance once per frame.
    const uint64_t samples_per_frame = is_wb ? 320u : 160u;
    uint32_t slot = 0;
    for (const layanalyzer::rtp::AmrFrame &frame : depacked.frames) {
      FidxEntry entry;
      entry.offset = frame_bytes.size();
      entry.length = 1u + static_cast<uint32_t>(frame.data.size());
      entry.frame = record.header.frame;
      entry.ext_ts = record.header.ext_ts +
                     static_cast<uint64_t>(slot) * samples_per_frame;
      entry.arrival_rel = record.header.arrival_rel_sec;
      entry.flags = frame.is_sid ? layanalyzer::rtp::kFidxFlagSid : 0x00;
      // Storage format: the ToC octet, then this frame's data octets.
      frame_bytes.push_back(frame.toc);
      frame_bytes.insert(frame_bytes.end(), frame.data.begin(),
                         frame.data.end());
      entries.push_back(entry);
      ++slot;
    }

    // FT 15 (NO_DATA) and FT 14 (speech lost) carry no frame data of their own,
    // and AmrDepack reports them at packet level rather than as frames. Each
    // still occupies a 20 ms slot, so each gets one empty `lost` entry: without
    // it the following frame's timestamp would sit one slot too early and the
    // renderer would treat the packet as a gap-free continuation. The card
    // mandates this for `no_data`; `speech_lost` is the same rule for the same
    // reason, and dropping it silently would break the timeline identically.
    if (depacked.no_data) {
      FidxEntry entry;
      entry.offset = frame_bytes.size();
      entry.length = 0;
      entry.frame = record.header.frame;
      entry.ext_ts = record.header.ext_ts +
                     static_cast<uint64_t>(slot) * samples_per_frame;
      entry.arrival_rel = record.header.arrival_rel_sec;
      entry.flags = layanalyzer::rtp::kFidxFlagLost;
      entries.push_back(entry);
      ++slot;
      ++result.no_data_frames;
    }
    if (depacked.speech_lost) {
      FidxEntry entry;
      entry.offset = frame_bytes.size();
      entry.length = 0;
      entry.frame = record.header.frame;
      entry.ext_ts = record.header.ext_ts +
                     static_cast<uint64_t>(slot) * samples_per_frame;
      entry.arrival_rel = record.header.arrival_rel_sec;
      entry.flags = layanalyzer::rtp::kFidxFlagLost;
      entries.push_back(entry);
      ++slot;
      ++result.speech_lost_frames;
    }
  }

  if (entries.empty()) {
    result.error = "No RTP codec frames were extracted.";
    return false;
  }

  mark_late_codec_frames(entries);
  result.frames = std::move(frame_bytes);
  result.entries = std::move(entries);
  return true;
}

// Opens `path` for writing and hands back the raw bytes. Fails closed and
// removes the partial file, so a half-written `.frames` never survives.
bool write_binary_file(const std::string &path, const std::vector<uint8_t> &data,
                       std::string &error) {
  std::FILE *file = std::fopen(path.c_str(), "wb");
  if (!file) {
    error = "Unable to open RTP codec frame output.";
    return false;
  }
  ScopedPathRemoval cleanup(path);
  bool ok = data.empty() ||
            std::fwrite(data.data(), 1, data.size(), file) == data.size();
  if (ok && std::fflush(file) != 0) ok = false;
  if (std::fclose(file) != 0) ok = false;
  if (!ok) {
    error = "Unable to write RTP codec frame output.";
    return false;
  }
  cleanup.release();
  return true;
}

// ---------------------------------------------------------------------------
// RTP4-NAT-07: `renderRtpAudioFromPcm`.
//
// The second half of the MEDIACODEC route. RTP4-NAT-06 has already written the
// stream's codec frames and their `.fidx` index; RTP4-KT-01 has decoded those
// frames through MediaCodec into `.pcmchunks`; this endpoint puts the decoded
// chunks back on the RTP timeline through the same renderer, gaps, events and
// writers `decodeRtpAudio` uses, and answers with the same item shape.
// ---------------------------------------------------------------------------

// Reads a whole file into `data`. Fails closed on an empty path, an unreadable
// file, and a read that comes up short. Deliberately not `ScopedPathRemoval`-
// guarded: this is the caller's input, and a failed read must not delete it.
bool read_binary_file(const std::string &path, std::vector<uint8_t> &data,
                      std::string &error) {
  data.clear();
  if (path.empty()) {
    error = "RTP binary file path is empty.";
    return false;
  }
  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    error = "Unable to open the RTP PCM chunk file.";
    return false;
  }

  bool ok = std::fseek(file, 0, SEEK_END) == 0;
  long size = ok ? std::ftell(file) : -1;
  if (ok && (size < 0 || std::fseek(file, 0, SEEK_SET) != 0)) {
    ok = false;
  }
  if (ok && size > 0) {
    data.resize(static_cast<size_t>(size));
    if (std::fread(data.data(), 1, data.size(), file) != data.size()) {
      ok = false;
    }
  }
  if (std::fclose(file) != 0) {
    ok = false;
  }
  if (!ok) {
    data.clear();
    error = "Unable to read the RTP PCM chunk file.";
    return false;
  }
  error.clear();
  return true;
}

uint16_t read_le_u16(const uint8_t *bytes) {
  return static_cast<uint16_t>(static_cast<uint32_t>(bytes[0]) |
                               (static_cast<uint32_t>(bytes[1]) << 8u));
}

uint32_t read_le_u32(const uint8_t *bytes) {
  return static_cast<uint32_t>(bytes[0]) |
         (static_cast<uint32_t>(bytes[1]) << 8u) |
         (static_cast<uint32_t>(bytes[2]) << 16u) |
         (static_cast<uint32_t>(bytes[3]) << 24u);
}

int16_t read_le_i16(const uint8_t *bytes) {
  return static_cast<int16_t>(read_le_u16(bytes));
}

// One decoded chunk from `.pcmchunks`, already mono: a stereo chunk is downmixed
// by averaging its two channels here, so every path below deals with one
// channel only.
struct RtpPcmChunk {
  uint32_t fidx_index = 0;
  std::vector<int16_t> samples;
};

// Parses the `.pcmchunks` RTP4-KT-01 writes:
//
//   "PCM1"           4 octets
//   u32 sampleRate   little-endian
//   u16 channels     little-endian
//   then blocks of (u32 fidxIndex, u32 samples, i16[samples * channels])
//
// Fails closed on everything the card asks about -- the magic, a header whose
// sample rate or channel count does not match the request, a `fidxIndex` outside
// the `.fidx`, a duplicate `fidxIndex`, and a block whose declared sample count
// runs past the end of the file (a block truncated by EOF is rejected, never
// partially accepted).
bool parse_pcm_chunks(const std::vector<uint8_t> &data, uint32_t request_rate,
                      uint32_t request_channels, size_t fidx_count,
                      std::vector<RtpPcmChunk> &chunks, std::string &error) {
  chunks.clear();
  if (data.size() < 10u) {
    error = "RTP PCM chunk file is truncated.";
    return false;
  }
  if (data[0] != 'P' || data[1] != 'C' || data[2] != 'M' || data[3] != '1') {
    error = "RTP PCM chunk file has an invalid header.";
    return false;
  }
  const uint32_t file_rate = read_le_u32(data.data() + 4u);
  const uint32_t file_channels = read_le_u16(data.data() + 8u);
  if (file_rate != request_rate) {
    error = "RTP PCM chunk sample rate does not match the request.";
    return false;
  }
  if (file_channels != request_channels) {
    error = "RTP PCM chunk channel count does not match the request.";
    return false;
  }

  std::vector<uint8_t> seen(fidx_count, 0);
  size_t offset = 10u;
  while (offset < data.size()) {
    if (data.size() - offset < 8u) {
      error = "RTP PCM chunk file is truncated.";
      return false;
    }
    const uint32_t fidx_index = read_le_u32(data.data() + offset);
    const uint32_t samples = read_le_u32(data.data() + offset + 4u);
    offset += 8u;

    const uint64_t block_bytes = static_cast<uint64_t>(samples) *
                                 request_channels * sizeof(int16_t);
    if (block_bytes > static_cast<uint64_t>(data.size() - offset)) {
      error = "RTP PCM chunk file is truncated.";
      return false;
    }
    if (fidx_index >= fidx_count) {
      error = "RTP PCM chunk index is out of range.";
      return false;
    }
    if (seen[fidx_index] != 0) {
      error = "RTP PCM chunk index is duplicated.";
      return false;
    }
    seen[fidx_index] = 1;

    RtpPcmChunk chunk;
    chunk.fidx_index = fidx_index;
    chunk.samples.reserve(samples);
    if (request_channels == 1u) {
      for (uint32_t index = 0; index < samples; ++index) {
        chunk.samples.push_back(read_le_i16(data.data() + offset +
                                            static_cast<size_t>(index) * 2u));
      }
    } else {
      // M4's MEDIACODEC codecs (AMR, AMR-WB, Opus) are all mono, so this is the
      // defensive branch the card asks for rather than the common one.
      for (uint32_t index = 0; index < samples; ++index) {
        const uint8_t *frame = data.data() + offset +
                               static_cast<size_t>(index) * 4u;
        const int32_t left = read_le_i16(frame);
        const int32_t right = read_le_i16(frame + 2u);
        chunk.samples.push_back(static_cast<int16_t>((left + right) / 2));
      }
    }
    offset += static_cast<size_t>(block_bytes);
    chunks.push_back(std::move(chunk));
  }

  error.clear();
  return true;
}

// `.fidx` and `.rtpp` describe the same packet, so the renderer's timeline
// helpers -- written against `RtppRecordHeader` -- are reused on a `.fidx`
// entry through this adapter instead of a second copy of their arithmetic.
layanalyzer::rtp::RtppRecordHeader rtpp_header_from_fidx(
    const layanalyzer::rtp::FidxEntry &entry) {
  layanalyzer::rtp::RtppRecordHeader header;
  header.frame = entry.frame;
  header.arrival_rel_sec = entry.arrival_rel;
  header.ext_ts = entry.ext_ts;
  return header;
}

// The duration of a `lost` entry's slot, taken from the `.fidx` timestamps:
// RTP4-NAT-06 staggers each entry's `extTs` by one frame period, so the delta to
// the neighbouring entry is exact rather than a guess.
//
// The card phrases this as "the difference to the next non-lost entry's
// timestamp, or the previous non-lost entry's duration at the tail". Both are
// the same number whenever the entry that follows is decoded, which is the
// usual, isolated-loss case; they differ only inside a run of two or more
// consecutive lost entries, where the card's wording would span the whole run
// from its first entry and over-count it. The neighbouring entry is used
// instead, so a run of lost slots reports one frame period each and their sum
// is the run's true length.
uint32_t pcm_lost_gap_duration_ms(const std::vector<layanalyzer::rtp::FidxEntry> &entries,
                                  size_t index, unsigned timestamp_rate) {
  if (timestamp_rate == 0u || entries.empty()) {
    return 0;
  }
  uint64_t from = 0;
  uint64_t to = 0;
  if (index + 1u < entries.size()) {
    from = entries[index].ext_ts;
    to = entries[index + 1u].ext_ts;
  } else if (index > 0u) {
    from = entries[index - 1u].ext_ts;
    to = entries[index].ext_ts;
  } else {
    return 0;
  }
  if (to <= from) {
    return 0;
  }
  const uint64_t delta = to - from;
  if (delta > std::numeric_limits<uint64_t>::max() / 1000u) {
    return std::numeric_limits<uint32_t>::max();
  }
  const uint64_t milliseconds = delta * 1000u / timestamp_rate;
  return milliseconds > std::numeric_limits<uint32_t>::max()
             ? std::numeric_limits<uint32_t>::max()
             : static_cast<uint32_t>(milliseconds);
}

// Everything the `decodeRtpAudio` item says about a stream that the two
// endpoints do not derive the same way. The counters are arguments and not
// recomputed inside the builder: only the caller knows which path produced them
// (a native decode counts its own packets and payloads, RTP4-NAT-07 hands over
// the scan snapshot's loss counters and has no payloads at all).
struct RtpDecodedAudioItemMetadata {
  std::string stream_id;
  std::string codec;
  uint64_t first_abs_epoch_us = 0;
  double start_rel_sec = 0.0;
  unsigned channels = 1;
  uint64_t decoded_packets = 0;
  int64_t lost = 0;
  uint64_t truncated_packets = 0;
  uint64_t zero_payload_packets = 0;
};

struct RtpDecodedAudioItem {
  std::string wav_path;
  std::string peaks_path;
  std::string map_path;
  json item;
};

// Writes `<out_dir>/<streamId>.wav`, `.peaks` and `.map` from `rendered` and
// fills `output.item` with the object `decodeRtpAudio` puts in `items[i]`. The
// `dtmf` array is not part of it: only `decodeRtpAudio` has telephone-event
// records to fill it from, so that caller adds the key itself when it has one.
//
// On failure `error` carries the writer's own message and neither `output.item`
// nor any path in `output` is meaningful. Removing the partial output is the
// caller's job, because the caller owns the output directory.
bool build_rtp_decoded_audio_item(
    const layanalyzer::rtp::RtpRenderResult &rendered,
    const RtpDecodedAudioItemMetadata &metadata, const std::string &out_dir,
    RtpDecodedAudioItem &output, std::string &error) {
  output.wav_path = join_path(out_dir, metadata.stream_id + ".wav");
  output.peaks_path = join_path(out_dir, metadata.stream_id + ".peaks");
  output.map_path = join_path(out_dir, metadata.stream_id + ".map");

  layanalyzer::rtp::WavWriter wav;
  layanalyzer::rtp::PeaksBuilder peaks;
  layanalyzer::rtp::FrameMapWriter frame_map;
  std::string write_error;
  if (!wav.open(output.wav_path, rendered.sample_rate,
                static_cast<uint16_t>(metadata.channels), write_error) ||
      !peaks.open(output.peaks_path, rendered.sample_rate, write_error) ||
      !frame_map.open(output.map_path, write_error)) {
    error = write_error.empty() ? "Unable to open RTP output files."
                                : write_error;
    return false;
  }
  if (!wav.append(rendered.samples) || !peaks.append(rendered.samples)) {
    error = !wav.error().empty() ? wav.error() : peaks.error();
    return false;
  }
  for (const layanalyzer::rtp::RtpRenderMapEntry &entry : rendered.map) {
    if (!frame_map.append(entry.at_ms, entry.frame)) {
      error = frame_map.error();
      return false;
    }
  }
  if (!wav.finalize(write_error) || !peaks.finalize(write_error) ||
      !frame_map.finalize(write_error)) {
    error = !wav.error().empty()
                ? wav.error()
                : (!peaks.error().empty() ? peaks.error() : frame_map.error());
    return false;
  }

  const uint64_t duration_ms =
      static_cast<uint64_t>(rendered.samples.size() / metadata.channels) *
      1000u / rendered.sample_rate;

  json gaps = json::array();
  for (const layanalyzer::rtp::RtpRenderGap &gap : rendered.gaps) {
    gaps.push_back({{"atMs", gap.at_ms},
                    {"durMs", gap.dur_ms},
                    {"reason", gap.reason},
                    {"clipped", gap.clipped},
                    {"frame", gap.frame}});
  }
  json events = json::array();
  for (const layanalyzer::rtp::RtpRenderEvent &event : rendered.events) {
    events.push_back({{"atMs", event.at_ms},
                      {"type", event.type},
                      {"value", event.value},
                      {"frame", event.frame}});
  }

  output.item = {
      {"streamId", metadata.stream_id},
      {"codec", metadata.codec},
      {"sampleRate", rendered.sample_rate},
      {"channels", metadata.channels},
      {"wavPath", output.wav_path},
      {"peaksPath", output.peaks_path},
      {"mapPath", output.map_path},
      {"durationMs", duration_ms},
      {"startRel", metadata.start_rel_sec},
      {"startAbsEpochMs",
       static_cast<int64_t>(metadata.first_abs_epoch_us / 1000u)},
      {"gaps", std::move(gaps)},
      {"events", std::move(events)},
      {"stats",
       {{"decodedPackets", metadata.decoded_packets},
        {"droppedLate", rendered.dropped_late},
        {"lost", metadata.lost},
        {"truncatedPackets", metadata.truncated_packets},
        {"zeroPayloadPackets", metadata.zero_payload_packets}}}};
  error.clear();
  return true;
}

// RTP4-NAT-07 request. `timing` and `jitterMs` are the same two fields, with the
// same spellings and the same defaults, that `decodeRtpAudio` reads.
struct RtpPcmRenderRequest {
  uint64_t scan_generation = 0;
  std::string stream_id;
  std::string pcm_path;
  uint32_t sample_rate = 0;
  uint32_t channels = 0;
  layanalyzer::rtp::RtpTimingMode timing =
      layanalyzer::rtp::RtpTimingMode::JitterBuffer;
  int jitter_ms = 50;
};

bool parse_rtp_pcm_render_request(const std::string &text,
                                  RtpPcmRenderRequest &request,
                                  std::string &error) {
  const json parsed = json::parse(text, nullptr, false);
  if (parsed.is_discarded() || !parsed.is_object()) {
    error = "Invalid RTP PCM render request.";
    return false;
  }

  const auto generation_it = parsed.find("scanGeneration");
  if (generation_it == parsed.end() || !generation_it->is_number_integer()) {
    error = "scanGeneration is required and must be an integer.";
    return false;
  }
  if (generation_it->is_number_unsigned()) {
    request.scan_generation = generation_it->get<uint64_t>();
  } else {
    const int64_t generation = generation_it->get<int64_t>();
    if (generation < 0) {
      error = "scanGeneration must be a non-negative integer.";
      return false;
    }
    request.scan_generation = static_cast<uint64_t>(generation);
  }

  const auto stream_it = parsed.find("streamId");
  if (stream_it == parsed.end() || !stream_it->is_string() ||
      stream_it->get_ref<const std::string &>().empty()) {
    error = "streamId is required and must be a non-empty string.";
    return false;
  }
  request.stream_id = stream_it->get<std::string>();

  const auto pcm_it = parsed.find("pcmPath");
  if (pcm_it == parsed.end() || !pcm_it->is_string() ||
      pcm_it->get_ref<const std::string &>().empty()) {
    error = "pcmPath is required and must be a non-empty string.";
    return false;
  }
  request.pcm_path = pcm_it->get<std::string>();

  // The request's own rate and channel count are validated against the file
  // header, never against the media snapshot: the snapshot's `sampleRate` is
  // `sample_rate_for_codec`, which is 0 for every codec on this path.
  const auto rate_it = parsed.find("sampleRate");
  if (rate_it == parsed.end() || !rate_it->is_number_integer()) {
    error = "sampleRate is required and must be an integer.";
    return false;
  }
  const int64_t rate = rate_it->get<int64_t>();
  if (rate <= 0 ||
      rate > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
    error = "sampleRate must be a positive integer.";
    return false;
  }
  request.sample_rate = static_cast<uint32_t>(rate);

  const auto channels_it = parsed.find("channels");
  if (channels_it == parsed.end() || !channels_it->is_number_integer()) {
    error = "channels is required and must be an integer.";
    return false;
  }
  const int64_t channels = channels_it->get<int64_t>();
  if (channels < 1 || channels > 2) {
    error = "channels must be 1 or 2.";
    return false;
  }
  request.channels = static_cast<uint32_t>(channels);

  const auto timing_it = parsed.find("timing");
  if (timing_it != parsed.end() && !timing_it->is_null()) {
    if (!timing_it->is_string()) {
      error = "timing must be jitter, rtp, or uninterrupted.";
      return false;
    }
    const std::string timing = timing_it->get<std::string>();
    if (timing == "jitter") {
      request.timing = layanalyzer::rtp::RtpTimingMode::JitterBuffer;
    } else if (timing == "rtp") {
      request.timing = layanalyzer::rtp::RtpTimingMode::RtpTimestamp;
    } else if (timing == "uninterrupted") {
      request.timing = layanalyzer::rtp::RtpTimingMode::Uninterrupted;
    } else {
      error = "timing must be jitter, rtp, or uninterrupted.";
      return false;
    }
  }

  const auto jitter_it = parsed.find("jitterMs");
  if (jitter_it != parsed.end() && !jitter_it->is_null()) {
    if (!jitter_it->is_number_integer()) {
      error = "jitterMs must be a non-negative integer.";
      return false;
    }
    const int64_t jitter = jitter_it->get<int64_t>();
    if (jitter < 0 || jitter > std::numeric_limits<int>::max()) {
      error = "jitterMs must be a non-negative integer.";
      return false;
    }
    request.jitter_ms = static_cast<int>(jitter);
  }

  error.clear();
  return true;
}

jstring read_setup_info_json(JNIEnv *env, jlong session_handle,
                             jstring frames_json, bool sdp_only) {
  try {
    auto session = acquire_session(session_handle);
    if (!session || !session->wth || !session->epan) {
      return new_java_string(env,
          R"({"schemaVersion":1,"error":"No capture is open.","cancelled":false,"frames":[]})");
    }
    if (!frames_json) {
      return new_java_string(env,
          R"({"schemaVersion":1,"error":"Missing setup request.","cancelled":false,"frames":[]})");
    }
    std::string request;
    {
      const auto release = [env, frames_json](const char *chars) {
        env->ReleaseStringUTFChars(frames_json, chars);
      };
      std::unique_ptr<const char, decltype(release)> chars(
          env->GetStringUTFChars(frames_json, nullptr), release);
      if (!chars) return nullptr;  // Preserve the pending JNI allocation exception.
      request.assign(chars.get());
    }
    const json result = layanalyzer::rtp::read_rtp_setup_info(
        session.get(), request, sdp_only);
    return new_java_string(env, result.dump());
  } catch (...) {
    // Parser/dissection/serialization errors must not cross JNI or disclose
    // input-bearing exception messages (SIP URIs and fmtp can be sensitive).
    return new_java_string(env,
        R"({"schemaVersion":1,"error":"Unable to read RTP setup information.","cancelled":false,"frames":[]})");
  }
}

// The directory `path` lives in, so that the `.fidx` that drove the decode can
// be found next to the `.pcmchunks` it produced (RTP4-KT-01 writes both into the
// caller's request directory).
std::string parent_directory_of(const std::string &path) {
  return std::filesystem::path(path).parent_path().string();
}
}  // namespace

// RTP3-NAT-04: the two projections share the same bounded, lease-backed read.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_readRtpSetupInfo(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring framesJson) {
  return read_setup_info_json(env, sessionPtr, framesJson, false);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_readSdpFmtpValues(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring framesJson) {
  return read_setup_info_json(env, sessionPtr, framesJson, true);
}

// request {"limitToDisplayFilter": false} -> M1 §3.2 result
// (NativeEngine.kt and model/RtpModels.kt).
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_scanRtpStreams(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring requestJson,
    jobject progress) {
  json root = {{"schemaVersion", 1},
               {"error", ""},
               {"cancelled", false},
               {"scanGeneration", 0},
               {"framesScanned", 0},
               {"heuristicEnabled", false},
               {"streamsTruncated", false},
               {"streams", json::array()}};
  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }

  // 解析请求：解析失败（或字段缺失/类型不对）时保持默认值
  // limitToDisplayFilter=false，不抛异常。
  bool limit_to_display_filter = false;
  if (requestJson) {
    const char *requestChars = env->GetStringUTFChars(requestJson, nullptr);
    if (requestChars) {
      json request = json::parse(requestChars, nullptr, false);
      if (!request.is_discarded() && request.is_object()) {
        auto it = request.find("limitToDisplayFilter");
        if (it != request.end() && it->is_boolean()) {
          limit_to_display_filter = it->get<bool>();
        }
      }
      env->ReleaseStringUTFChars(requestJson, requestChars);
    }
  }

  const uint64_t generation = session->rtp_scan_generation.fetch_add(1) + 1;
  root["scanGeneration"] = generation;

  // 覆盖表在 rtp_mutex 下取一份快照（setRtpPayloadOverrides 会整体替换它），
  // 之后的整趟遍历只看这份快照，避免每条流都加锁。
  layanalyzer::rtp::RtpPayloadOverrides overrides_snapshot;
  {
    std::lock_guard<std::mutex> lk(session->rtp_mutex);
    overrides_snapshot = session->rtp_overrides;
  }

  const auto scan_start = std::chrono::steady_clock::now();
  const uint64_t cancel_generation = current_cancel_generation();

  // 抓包第 0 帧的绝对时间（毫秒）。C10：本项目 pinfo->rel_ts 恒为 0，到达时间
  // 一律用 abs_ts 减它，见 RtpStreamCollector 的约定。
  double first_frame_abs_ms = 0.0;
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    DissectedFrame first;
    if (!session->frame_offsets.empty() &&
        dissect_frame(session, 0, FALSE, FALSE, nullptr, first)) {
      first_frame_abs_ms = nstime_to_msec(&first.fd.abs_ts);
    }
  }

  // 帧列表：默认扫描全量，不受显示过滤器影响（C4）。
  std::vector<int> frames;
  std::string filter_expression;
  if (limit_to_display_filter) {
    frames = snapshot_visible_frames(session);
    filter_expression = session->active_filter;
  } else {
    frames.reserve(session->frame_offsets.size());
    for (size_t index = 0; index < session->frame_offsets.size(); ++index) {
      frames.push_back(static_cast<int>(index));
    }
  }

  layanalyzer::rtp::RtpStreamCollector collector(session.get(),
                                                 first_frame_abs_ms);
  std::string tap_error;
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    if (!collector.registerTap(tap_error)) {
      root["error"] = tap_error;
      return new_java_string(env, root.dump());
    }
  }

  jmethodID progress_method = nullptr;
  if (progress) {
    jclass progress_class = env->GetObjectClass(progress);
    progress_method = env->GetMethodID(progress_class, "onProgress", "(II)Z");
    env->DeleteLocalRef(progress_class);
    if (env->ExceptionCheck()) env->ExceptionClear();
  }
  const jint total_frames = static_cast<jint>(frames.size());

  bool cancelled = false;
  bool session_closed = false;
  size_t frames_scanned = 0;
  for (size_t i = 0; i < frames.size(); ++i) {
    if (session->closed.load(std::memory_order_acquire)) {
      session_closed = true;
      break;
    }
    if (long_operation_cancelled(cancel_generation)) {
      cancelled = true;
      break;
    }
    // dissect_mutex 只包住单帧，好让分页/搜索在帧之间插进来。
    {
      std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
      DissectedFrame frame;
      dissect_frame_with_taps(session, frames[i], FALSE, FALSE, nullptr, frame);
    }
    frames_scanned = i + 1;
    yield_to_interactive_reads(session);
    // 进度回调：每 256 帧，以及最后一次；返回 false 视为取消。
    if (progress && progress_method &&
        ((i + 1) % 256 == 0 || i + 1 == frames.size())) {
      jboolean keep = env->CallBooleanMethod(progress, progress_method,
                                             static_cast<jint>(i + 1),
                                             total_frames);
      if (env->ExceptionCheck()) {
        env->ExceptionClear();
        keep = JNI_FALSE;
      }
      if (keep == JNI_FALSE) {
        cancelled = true;
        break;
      }
    }
  }
  if (!session_closed && session->closed.load(std::memory_order_acquire)) {
    session_closed = true;
  }
  // 无论正常结束还是取消，都必须摘掉进程全局的 tap。
  {
    std::unique_lock<std::mutex> dissect_lock(session->dissect_mutex);
    collector.removeTap();
  }

  const long long take_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - scan_start)
                                .count();

  if (session_closed) {
    root["error"] = "Capture was closed.";
    root["streams"] = json::array();
    root["framesScanned"] = static_cast<uint64_t>(frames_scanned);
    LOGI("scanRtpStreams: session closed after %zu frames take=%lldms",
         frames_scanned, take_ms);
    return new_java_string(env, root.dump());
  }
  if (cancelled) {
    // 绝不返回部分结果，也绝不写 rtp_last_scan。
    root["cancelled"] = true;
    root["framesScanned"] = static_cast<uint64_t>(frames_scanned);
    LOGI("scanRtpStreams: frames=%zu streams=0 take=%lldms", frames_scanned,
         take_ms);
    return new_java_string(env, root.dump());
  }

  collector.finalize(&overrides_snapshot);
  const std::vector<layanalyzer::rtp::RtpCollectedStream> &collected =
      collector.streams();

  // 发布 M1 快照（M2 的入口靠 scanGeneration 校验新鲜度）。
  {
    std::lock_guard<std::mutex> lk(session->rtp_mutex);
    session->rtp_last_scan =
        std::make_shared<layanalyzer::rtp::RtpScanSnapshot>(
            layanalyzer::rtp::RtpScanSnapshot{
                generation, collected, limit_to_display_filter,
                filter_expression});
  }

  layanalyzer::rtp::RtpMediaSnapshot media_snapshot;
  media_snapshot.scan_generation = generation;
  media_snapshot.limit_to_display_filter = limit_to_display_filter;
  media_snapshot.filter_expression = filter_expression;

  json streams = json::array();
  char ssrc_hex[16];
  for (size_t index = 0; index < collected.size(); ++index) {
    const layanalyzer::rtp::RtpCollectedStream &stream = collected[index];
    const layanalyzer::rtp::RtpStreamStats &stats = stream.stats;
    const std::string stream_id = "s" + std::to_string(index);
    std::snprintf(ssrc_hex, sizeof(ssrc_hex), "0x%08x", stream.key.ssrc);

    // primary_pt 为 PT_UNDEFINED 时统一序列化成 -1。
    const int primary_pt =
        stream.primary_pt == kRtpPtUndefined
            ? -1
            : static_cast<int>(stream.primary_pt);

    std::vector<int> pts_seen;
    pts_seen.reserve(stream.payload_types_seen.size());
    for (uint8_t pt : stream.payload_types_seen) {
      pts_seen.push_back(static_cast<int>(pt));
    }

    // codec_pt 的取法（卡片没写死，约定如下）：primary_pt 有值（非 PT_UNDEFINED）
    // 时用它；否则取 payload_types_seen 里最小的 PT（该列表是升序去重的）；
    // 再否则取 0。这样「只有 CN/telephone-event 的流」（primary_pt 为
    // PT_UNDEFINED）也能查到静态表名字 / 覆盖表。
    uint32_t codec_pt = stream.primary_pt;
    if (codec_pt == kRtpPtUndefined) {
      codec_pt = stream.payload_types_seen.empty()
                     ? 0u
                     : static_cast<uint32_t>(stream.payload_types_seen.front());
    }

    // 编码来源判定，优先级 override > sdp > static（卡片 §「编码名与来源的判定」）。
    // codec 一律用规范 ID；codecSource=="unknown" 时 codec 为空。
    const layanalyzer::rtp::RtpPayloadOverride *override_entry =
        overrides_snapshot.find(codec_pt);
    std::string codec;
    std::string codec_source;
    bool codec_known = false;
    int clock_rate = 0;
    std::string payload_type_name;
    const auto payload_name_it = stream.payload_type_names.find(
        static_cast<uint8_t>(codec_pt));
    if (payload_name_it != stream.payload_type_names.end()) {
      payload_type_name = payload_name_it->second;
    }

    if (override_entry != nullptr) {
      const layanalyzer::rtp::CodecInfo info =
          layanalyzer::rtp::canonical_codec(override_entry->codec);
      codec = info.id;
      codec_source = "override";
      codec_known = layanalyzer::rtp::rtp_codec_is_known(codec);
      if (override_entry->clock_rate != 0) {
        clock_rate = override_entry->clock_rate;
      }
    } else if (!payload_type_name.empty()) {
      const layanalyzer::rtp::CodecInfo info =
          layanalyzer::rtp::canonical_codec(payload_type_name);
      codec = info.id;
      codec_source = "sdp";
      codec_known = layanalyzer::rtp::rtp_codec_is_known(codec);
    } else {
      const char *static_name = codec_pt < 96
                                    ? layanalyzer::rtp::rtp_static_pt_codec_name(codec_pt)
                                    : nullptr;
      if (static_name != nullptr) {
        codec = static_name;
        codec_source = "static";
        codec_known = true;
      } else {
        codec_source = "unknown";
        codec_known = false;
      }
    }

    // clockRate：覆盖表 > stream.payload_rate > 静态表 > 动态表 > 0。
    if (clock_rate == 0) {
      if (stream.payload_rate != 0) {
        clock_rate = stream.payload_rate;
      } else {
        const uint32_t static_rate = layanalyzer::rtp::rtp_static_clock_rate(codec_pt);
        if (static_rate != 0) {
          clock_rate = static_cast<int>(static_rate);
        } else {
          const std::string &dynamic_name =
              override_entry != nullptr ? override_entry->codec
                                        : payload_type_name;
          clock_rate = static_cast<int>(layanalyzer::rtp::rtp_dynamic_clock_rate(
              dynamic_name.empty() ? nullptr : dynamic_name.c_str()));
        }
      }
    }

    // 可解码判定：输入映射见卡片 §「编码名与来源的判定」。
    const bool codec_is_event = layanalyzer::rtp::rtp_codec_is_event(codec);
    layanalyzer::rtp::RtpDecodabilityInput decodability_input;
    decodability_input.is_srtp = stream.is_srtp;
    decodability_input.canonical_codec = codec;
    decodability_input.codec_known = codec_known;
    decodability_input.primary_pt = codec_pt;
    decodability_input.primary_pt_is_event =
        codec_is_event || (stream.primary_pt == kRtpPtUndefined);
    decodability_input.any_non_event_codec = codec_known && !codec_is_event;
    decodability_input.packets = stats.packets;
    decodability_input.truncated = stats.truncated;
    const layanalyzer::rtp::RtpDecodability decodability =
        layanalyzer::rtp::rtp_decodability(decodability_input);
    const std::string decodability_reason =
        layanalyzer::rtp::rtp_decodability_reason(decodability_input);

    layanalyzer::rtp::RtpStreamMediaInfo media_info;
    media_info.codec = codec;
    media_info.clock_rate = static_cast<uint32_t>(std::max(0, clock_rate));
    media_info.primary_pt = primary_pt;
    media_info.telephone_event_pt = stream.telephone_event_pt;
    media_info.decodable = decodability;
    media_info.is_srtp = stream.is_srtp;
    media_info.first_abs_epoch_us = stream.first_abs_epoch_us;
    media_info.sample_rate = sample_rate_for_codec(codec);
    // RTP5-NAT-01：视频路径需要的两个字段。primary_codec_id 就是上面算好的规范
    // ID（JSON 的 codec 字段照原样输出，一个字节都没改）；video_timestamp_rate
    // 只对 kSupportedVideoCodecs（H264/H265/PS）给 90 kHz，其余为 0 —— 消费者
    // 据此区分「这条流没有视频时间轴」和「有，但速率未知」，所以不拿 clock_rate
    // 兜底（H265/PS 在动态时钟表里没有条目，clock_rate 会是 0）。
    media_info.primary_codec_id = codec;
    if (!codec.empty() && is_supported_video_codec(codec)) {
      media_info.video_timestamp_rate = kRtpVideoTimestampRate;
    }
    media_snapshot.stream_keys[stream_id] = stream.key;
    media_snapshot.media[stream_id] = std::move(media_info);

    json entry;
    entry["id"] = stream_id;
    entry["src"] = stream.key.src;
    entry["srcPort"] = stream.key.src_port;
    entry["dst"] = stream.key.dst;
    entry["dstPort"] = stream.key.dst_port;
    entry["ssrc"] = static_cast<uint64_t>(stream.key.ssrc);  // 十进制
    entry["ssrcHex"] = ssrc_hex;
    // pt 与 primaryPayloadType 都取 NAT-02 的 primaryPayloadType()（忽略
    // CN/telephone-event，并列取较小 PT）；primaryPayloadType 是后补的冗余字段。
    entry["pt"] = primary_pt;
    // codec 用规范 ID（C13）；codecSource ∈ override / sdp / static / unknown。
    entry["codec"] = codec;
    entry["codecSource"] = codec_source;
    entry["clockRate"] = clock_rate;
    entry["telephoneEventPt"] = stream.telephone_event_pt;
    entry["setupFrame"] = stream.setup_frame;
    // Optional scan enrichment is deferred: setup-info callers can read the
    // selected setupFrame directly; the 4.0.10 RTP tap does not expose a method.
    entry["setupMethod"] = "";
    entry["isSrtp"] = stream.is_srtp;
    entry["packets"] = stats.packets;
    entry["expected"] = stats.expected;
    entry["lost"] = stats.lost;  // 可以为负（重复包），见 C12
    entry["lostPct"] = stats.lost_pct;
    entry["seqErrors"] = stats.seq_errors;
    entry["outOfOrder"] = stats.out_of_order;
    entry["truncated"] = stats.truncated;
    entry["problem"] = stats.problem;
    entry["maxDeltaMs"] = stats.max_delta_ms;
    entry["maxDeltaFrame"] = stats.max_delta_frame;
    entry["minDeltaMs"] = stats.min_delta_ms;
    entry["meanDeltaMs"] = stats.mean_delta_ms;
    entry["maxJitterMs"] = stats.max_jitter_ms;
    entry["meanJitterMs"] = stats.mean_jitter_ms;
    entry["minJitterMs"] = stats.min_jitter_ms;
    entry["jitterAvailable"] = stats.jitter_available;
    entry["maxSkewMs"] = stats.max_skew_ms;
    entry["bytes"] = stream.bytes;
    entry["firstFrame"] = stats.first_frame;
    entry["lastFrame"] = stats.last_frame;
    entry["startRel"] = stats.start_rel_ms / 1000.0;  // 秒
    entry["endRel"] = stats.end_rel_ms / 1000.0;      // 秒
    entry["firstAbsEpochUs"] =
        static_cast<int64_t>(stream.first_abs_epoch_us);
    entry["ptsSeen"] = pts_seen;
    entry["decodable"] = layanalyzer::rtp::rtp_decodability_name(decodability);
    entry["decodableReason"] = decodability_reason;
    entry["primaryPayloadType"] = primary_pt;
    streams.push_back(std::move(entry));
  }

  root["streams"] = std::move(streams);
  root["streamsTruncated"] = collector.truncated_streams();
  root["framesScanned"] = static_cast<uint64_t>(frames_scanned);
  root["heuristicEnabled"] = rtp_heuristic_enabled();
  {
    std::lock_guard<std::mutex> lk(session->rtp_media_mutex);
    session->rtp_last_media =
        std::make_shared<const layanalyzer::rtp::RtpMediaSnapshot>(
            std::move(media_snapshot));
  }
  LOGI("scanRtpStreams: frames=%zu streams=%zu take=%lldms", frames_scanned,
       collected.size(), take_ms);
  return new_java_string(env, root.dump());
}

// ---------------------------------------------------------------------------
// RTP4-KT-02: the WAV mix inputs.
//
// `decodeRtpAudio` grows one optional pair of fields, so the stereo mix the M3
// card asked for can be built from two tracks the caller already rendered
// instead of from two streams this call decodes:
//
//   "mix":{"left":"s1","right":"s2","align":"absArrival",
//          "leftWav":".../s1.wav","rightWav":".../s2.wav",
//          "leftPeaks":".../s1.peaks","leftMap":".../s1.map",
//          "rightPeaks":".../s2.peaks","rightMap":".../s2.map"}
//
// When `leftWav` and `rightWav` are both given, nothing is extracted and
// nothing is decoded -- the renderer never runs -- and the two files are read
// as PCM and handed to `mix_stereo` directly. `leftPeaks`/`leftMap`/
// `rightPeaks`/`rightMap` are optional and are echoed back as the `mix`
// object's four path fields, because on this path those files belong to the
// caller; a missing one is reported as an empty string rather than invented.
//
// `streams` and `mix.left`/`mix.right` stay required: `absArrival` alignment
// subtracts the two streams' first-packet absolute arrival times, and those are
// still read from the media snapshot under `mix.left`/`mix.right`. The streams
// named there are not decoded, so it does not matter whether this build could
// decode them.
//
// The shortcut is rejected, not guessed at, when only one of the two WAVs is
// given, and when either is missing, is not a 16-bit PCM RIFF/WAVE file, or
// does not hold a whole number of frames. A rejected mix writes no `mix.wav`
// and -- unlike the decode path -- does not remove the request directory: on
// this path that directory holds the caller's own inputs.
// ---------------------------------------------------------------------------

// One track that is ready to be mixed: its mono samples, its own sample rate
// and the absolute arrival time of its first packet (epoch seconds), which is
// what `absArrival` alignment subtracts. The three paths are the files the
// caller is told about in the `items[i]` / `mix` objects.
struct RenderedAudioOutput {
  std::string stream_id;
  std::vector<int16_t> samples;
  unsigned sample_rate = 0;
  double start_abs_sec = 0.0;
  std::string wav_path;
  std::string peaks_path;
  std::string map_path;
};

// The optional `mix` inputs above. An empty string means "not given".
struct RtpWavMixInputs {
  std::string left_wav;
  std::string right_wav;
  std::string left_peaks;
  std::string right_peaks;
  std::string left_map;
  std::string right_map;

  bool has_any_wav() const {
    return !left_wav.empty() || !right_wav.empty();
  }
  bool has_both_wavs() const {
    return !left_wav.empty() && !right_wav.empty();
  }
};

// Reads the six optional fields out of the already-validated request text.
//
// They are read here, with a second local pass, because the frozen request
// parser (`rtp/RtpDecodeRequest.cpp`) owns the rest of `decodeRtpAudio`'s
// shape and has no field for them: it skips unknown keys, so the fields reach
// this function intact and untouched. A field that is present but not a string
// fails closed rather than being ignored -- silently mixing nothing would be
// worse than refusing the request.
bool parse_wav_mix_inputs(const std::string &text, RtpWavMixInputs &inputs,
                          std::string &error) {
  const json parsed = json::parse(text, nullptr, false);
  if (parsed.is_discarded() || !parsed.is_object()) {
    error = "Invalid RTP decode request.";
    return false;
  }
  const auto mix_it = parsed.find("mix");
  if (mix_it == parsed.end() || !mix_it->is_object()) {
    error.clear();
    return true;
  }

  const std::pair<const char *, std::string *> fields[] = {
      {"leftWav", &inputs.left_wav},   {"rightWav", &inputs.right_wav},
      {"leftPeaks", &inputs.left_peaks}, {"rightPeaks", &inputs.right_peaks},
      {"leftMap", &inputs.left_map},   {"rightMap", &inputs.right_map}};
  for (const auto &field : fields) {
    const auto it = mix_it->find(field.first);
    if (it == mix_it->end() || it->is_null()) {
      continue;
    }
    if (!it->is_string()) {
      error = std::string("mix.") + field.first + " must be a string.";
      return false;
    }
    *field.second = it->get<std::string>();
  }
  error.clear();
  return true;
}

// The PCM half of a WAV file, 16-bit, one or two channels, interleaved.
struct RtpWavPcm {
  uint32_t sample_rate = 0;
  uint16_t channels = 0;
  std::vector<int16_t> samples;
};

// Reads the one WAV shape this pipeline writes (`WavWriter`'s canonical 44
// octet RIFF/WAVE header with 16-bit PCM) and nothing else. It is the C++ half
// of `data/RtpBinaryReaders.kt`'s `WavHeader.parse` and refuses exactly what
// that one refuses: a missing or unreadable file, a header that is not
// RIFF/WAVE, no usable `fmt ` chunk, a sample rate or channel count that cannot
// be read, a format that is not 16-bit PCM, and a `data` length that is not a
// whole number of frames. A rejected read leaves no samples at all.
bool read_pcm_wav(const std::string &path, RtpWavPcm &out, std::string &error) {
  out = RtpWavPcm();
  std::vector<uint8_t> data;
  std::string read_error;
  if (!read_binary_file(path, data, read_error) || data.size() < 12u) {
    error = "Unable to read the RTP mix input WAV.";
    return false;
  }
  if (std::memcmp(data.data(), "RIFF", 4u) != 0 ||
      std::memcmp(data.data() + 8u, "WAVE", 4u) != 0) {
    error = "The RTP mix input is not a PCM WAV file.";
    return false;
  }
  const uint64_t riff_end = 8u + static_cast<uint64_t>(read_le_u32(data.data() + 4u));
  if (riff_end > data.size()) {
    error = "The RTP mix input WAV is truncated.";
    return false;
  }

  bool have_format = false;
  const uint8_t *payload = nullptr;
  uint64_t payload_bytes = 0;
  uint64_t offset = 12u;
  while (offset + 8u <= riff_end) {
    const uint8_t *chunk = data.data() + offset;
    const uint64_t chunk_size = read_le_u32(chunk + 4u);
    if (offset + 8u + chunk_size > riff_end) {
      error = "The RTP mix input WAV is truncated.";
      return false;
    }

    if (std::memcmp(chunk, "fmt ", 4u) == 0) {
      if (chunk_size < 16u) {
        error = "The RTP mix input WAV has no usable format chunk.";
        return false;
      }
      const uint16_t audio_format = read_le_u16(chunk + 8u);
      const uint16_t channels = read_le_u16(chunk + 10u);
      const uint32_t sample_rate = read_le_u32(chunk + 12u);
      const uint16_t block_align = read_le_u16(chunk + 20u);
      const uint16_t bits_per_sample = read_le_u16(chunk + 22u);
      const uint32_t expected_align =
          static_cast<uint32_t>(channels) * (bits_per_sample / 8u);
      if (audio_format != 1u || bits_per_sample != 16u ||
          (channels != 1u && channels != 2u) || sample_rate == 0u ||
          block_align != expected_align) {
        error = "The RTP mix input WAV is not 16-bit PCM audio.";
        return false;
      }
      out.channels = channels;
      out.sample_rate = sample_rate;
      have_format = true;
    } else if (std::memcmp(chunk, "data", 4u) == 0 && payload == nullptr) {
      payload = chunk + 8u;
      payload_bytes = chunk_size;
    }

    offset += 8u + chunk_size + (chunk_size & 1u);
  }

  if (!have_format || payload == nullptr) {
    error = "The RTP mix input WAV has no PCM audio data.";
    return false;
  }
  const uint64_t block_align = static_cast<uint64_t>(out.channels) * 2u;
  if (payload_bytes % block_align != 0u) {
    error = "The RTP mix input WAV is not a whole number of frames.";
    return false;
  }

  out.samples.reserve(static_cast<size_t>(payload_bytes / 2u));
  for (uint64_t index = 0; index < payload_bytes; index += 2u) {
    out.samples.push_back(read_le_i16(payload + index));
  }
  error.clear();
  return true;
}

// The mono samples of a 16-bit WAV. A stereo file is averaged channel by
// channel, the same reduction `parse_pcm_chunks` applies to a stereo
// `.pcmchunks` block, so the shortcut and the decoded path treat a stereo
// track alike.
std::vector<int16_t> wav_mono_samples(const RtpWavPcm &wav) {
  if (wav.channels <= 1u) {
    return wav.samples;
  }
  std::vector<int16_t> mono;
  mono.reserve(wav.samples.size() / 2u);
  for (size_t index = 0; index + 1u < wav.samples.size(); index += 2u) {
    mono.push_back(static_cast<int16_t>(
        (static_cast<int32_t>(wav.samples[index]) +
         static_cast<int32_t>(wav.samples[index + 1u])) /
        2));
  }
  return mono;
}

// Writes `mix.wav` into `output_directory` and fills `mix_json` from the native
// `mix_stereo` result. Shared by the decoded path (both tracks came from
// `RtpAudioRenderer`) and the RTP4-KT-02 shortcut (both came from a caller's
// rendered WAV), so both answer with one `mix` object shape.
//
// Only a half-written `mix.wav` is removed on failure: on the shortcut path the
// request directory holds the caller's own inputs, and those are not this
// function's to delete.
bool write_mix_output(const std::string &output_directory,
                      const RenderedAudioOutput &left,
                      const RenderedAudioOutput &right,
                      const layanalyzer::rtp::RtpMixRequest &mix_request,
                      json &mix_json, std::string &error) {
  const layanalyzer::rtp::RtpMixedAudio mixed = layanalyzer::rtp::mix_stereo(
      left.samples, left.sample_rate, left.start_abs_sec, right.samples,
      right.sample_rate, right.start_abs_sec, mix_request);
  if (!mixed.error.empty()) {
    error = mixed.error;
    return false;
  }
  if (mixed.interleaved.empty() || mixed.sample_rate == 0) {
    error = "RTP mix produced no audio.";
    return false;
  }

  const std::string mix_wav_path = join_path(output_directory, "mix.wav");
  layanalyzer::rtp::WavWriter mix_wav;
  std::string mix_write_error;
  if (!mix_wav.open(mix_wav_path, mixed.sample_rate, 2, mix_write_error) ||
      !mix_wav.append(mixed.interleaved) ||
      !mix_wav.finalize(mix_write_error)) {
    std::remove(mix_wav_path.c_str());
    error = mix_write_error.empty() ? "Unable to write RTP mix output."
                                    : mix_write_error;
    return false;
  }

  const uint64_t mix_duration_ms =
      static_cast<uint64_t>(mixed.interleaved.size() / 2u) * 1000u /
      mixed.sample_rate;
  mix_json = {
      {"wavPath", mix_wav_path},
      {"channels", 2},
      {"sampleRate", mixed.sample_rate},
      {"durationMs", mix_duration_ms},
      {"leftOffsetMs", mixed.left_offset_ms},
      {"rightOffsetMs", mixed.right_offset_ms},
      {"resampled", mixed.resampled},
      {"peaksLeftPath", left.peaks_path},
      {"peaksRightPath", right.peaks_path},
      {"mapLeftPath", left.map_path},
      {"mapRightPath", right.map_path},
  };
  error.clear();
  return true;
}

// The RTP4-KT-02 shortcut end to end: read the caller's two rendered WAVs, turn
// each into one mono track, and mix them.
bool build_wav_mix(const std::string &output_directory,
                   const RtpWavMixInputs &inputs,
                   const layanalyzer::rtp::RtpMixRequest &mix_request,
                   double left_epoch_sec, double right_epoch_sec,
                   json &mix_json, std::string &error) {
  RtpWavPcm left;
  RtpWavPcm right;
  if (!read_pcm_wav(inputs.left_wav, left, error) ||
      !read_pcm_wav(inputs.right_wav, right, error)) {
    return false;
  }

  RenderedAudioOutput left_track;
  left_track.stream_id = mix_request.left_stream_id;
  left_track.samples = wav_mono_samples(left);
  left_track.sample_rate = left.sample_rate;
  left_track.start_abs_sec = left_epoch_sec;
  left_track.wav_path = inputs.left_wav;
  left_track.peaks_path = inputs.left_peaks;
  left_track.map_path = inputs.left_map;

  RenderedAudioOutput right_track;
  right_track.stream_id = mix_request.right_stream_id;
  right_track.samples = wav_mono_samples(right);
  right_track.sample_rate = right.sample_rate;
  right_track.start_abs_sec = right_epoch_sec;
  right_track.wav_path = inputs.right_wav;
  right_track.peaks_path = inputs.right_peaks;
  right_track.map_path = inputs.right_map;

  return write_mix_output(output_directory, left_track, right_track,
                          mix_request, mix_json, error);
}

// decodeRtpAudio request/result contract:
// NativeEngine.kt and model/RtpModels.kt, extended
// by RTP4-KT-02's optional `mix.leftWav`/`mix.rightWav` (see the note above).
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_decodeRtpAudio(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring requestJson,
    jstring outDir, jobject progress) {
  json root = {{"schemaVersion", 1},
               {"error", ""},
               {"cancelled", false},
               {"items", json::array()},
               {"unsupported", json::array()}};
  const auto decode_start = std::chrono::steady_clock::now();

  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }
  if (!requestJson || !outDir) {
    root["error"] = "Missing decode request or output directory.";
    return new_java_string(env, root.dump());
  }

  std::string request_text;
  const char *request_chars = env->GetStringUTFChars(requestJson, nullptr);
  if (request_chars) {
    request_text.assign(request_chars);
    env->ReleaseStringUTFChars(requestJson, request_chars);
  }
  std::string output_directory;
  const char *out_dir_chars = env->GetStringUTFChars(outDir, nullptr);
  if (out_dir_chars) {
    output_directory.assign(out_dir_chars);
    env->ReleaseStringUTFChars(outDir, out_dir_chars);
  }
  if (output_directory.empty()) {
    root["error"] = "RTP output directory is empty.";
    return new_java_string(env, root.dump());
  }

  layanalyzer::rtp::RtpDecodeRequest request;
  std::string request_error;
  if (!layanalyzer::rtp::parse_rtp_decode_request(request_text, request,
                                                  request_error)) {
    root["error"] = request_error;
    return new_java_string(env, root.dump());
  }

  const uint64_t current_generation =
      session->rtp_scan_generation.load(std::memory_order_acquire);
  std::shared_ptr<const layanalyzer::rtp::RtpMediaSnapshot> media_snapshot;
  std::shared_ptr<const layanalyzer::rtp::RtpScanSnapshot> scan_snapshot;
  {
    std::lock_guard<std::mutex> lk(session->rtp_media_mutex);
    media_snapshot = session->rtp_last_media;
  }
  {
    std::lock_guard<std::mutex> lk(session->rtp_mutex);
    scan_snapshot = session->rtp_last_scan;
  }

  json unsupported = json::array();
  if (request.scan_generation != current_generation) {
    for (const std::string &stream_id : request.stream_ids) {
      unsupported.push_back(
          {{"streamId", stream_id}, {"reason", "staleScan"}});
    }
    root["unsupported"] = std::move(unsupported);
    return new_java_string(env, root.dump());
  }

  bool snapshot_stale =
      media_snapshot &&
      media_snapshot->scan_generation != request.scan_generation;
  std::string current_filter;
  if (media_snapshot && media_snapshot->limit_to_display_filter) {
    std::shared_lock<std::shared_mutex> lock(session->state_mutex);
    current_filter = session->active_filter;
    if (media_snapshot->filter_expression != current_filter) {
      snapshot_stale = true;
    }
  }

  // RTP4-KT-02: the WAV mix shortcut, checked before the per-stream selection
  // loop below runs at all, because on this path nothing is decoded: whether
  // this build could decode `mix.left`/`mix.right` is exactly the question the
  // caller answered by rendering them itself. The streams are therefore
  // reported neither as items nor as unsupported -- the two WAVs are the whole
  // input, and the two arrival times below are the only thing the snapshot is
  // still needed for.
  if (request.has_mix) {
    RtpWavMixInputs wav_mix;
    std::string wav_mix_error;
    if (!parse_wav_mix_inputs(request_text, wav_mix, wav_mix_error)) {
      root["error"] = wav_mix_error;
      return new_java_string(env, root.dump());
    }
    if (wav_mix.has_any_wav()) {
      if (!wav_mix.has_both_wavs()) {
        root["error"] = "mix.leftWav and mix.rightWav must be given together.";
        return new_java_string(env, root.dump());
      }
      if (snapshot_stale || !media_snapshot) {
        root["error"] = "staleScan";
        return new_java_string(env, root.dump());
      }
      const auto left_it =
          media_snapshot->media.find(request.mix.left_stream_id);
      const auto right_it =
          media_snapshot->media.find(request.mix.right_stream_id);
      if (left_it == media_snapshot->media.end() ||
          right_it == media_snapshot->media.end()) {
        root["error"] = "RTP mix requires two decoded streams.";
        return new_java_string(env, root.dump());
      }

      json mix_json;
      if (!build_wav_mix(
              output_directory, wav_mix, request.mix,
              static_cast<double>(left_it->second.first_abs_epoch_us) /
                  1000000.0,
              static_cast<double>(right_it->second.first_abs_epoch_us) /
                  1000000.0,
              mix_json, wav_mix_error)) {
        root["error"] = wav_mix_error.empty() ? "Unable to build the RTP mix."
                                              : wav_mix_error;
        return new_java_string(env, root.dump());
      }
      root["mix"] = std::move(mix_json);
      LOGI(
          "decodeRtpAudio: wav mix left=%s right=%s take=%lldms",
          request.mix.left_stream_id.c_str(),
          request.mix.right_stream_id.c_str(),
          static_cast<long long>(
              std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - decode_start)
                  .count()));
      return new_java_string(env, root.dump());
    }
  }

  struct SelectedStream {
    std::string id;
    layanalyzer::rtp::RtpStreamKey key;
    layanalyzer::rtp::RtpStreamMediaInfo media;
  };
  std::vector<SelectedStream> selected;
  for (const std::string &stream_id : request.stream_ids) {
    if (snapshot_stale) {
      unsupported.push_back(
          {{"streamId", stream_id}, {"reason", "staleScan"}});
      continue;
    }

    if (!media_snapshot) {
      unsupported.push_back(
          {{"streamId", stream_id}, {"reason", "notFound"}});
      continue;
    }

    const auto key_it = media_snapshot->stream_keys.find(stream_id);
    const auto media_it = media_snapshot->media.find(stream_id);
    if (key_it == media_snapshot->stream_keys.end() ||
        media_it == media_snapshot->media.end()) {
      unsupported.push_back(
          {{"streamId", stream_id}, {"reason", "notFound"}});
      continue;
    }

    const char *reason = unsupported_reason(media_it->second);
    if (reason != nullptr) {
      unsupported.push_back(
          {{"streamId", stream_id}, {"reason", reason}});
      continue;
    }

    selected.push_back({stream_id, key_it->second, media_it->second});
  }
  root["unsupported"] = std::move(unsupported);

  if (selected.empty()) {
    return new_java_string(env, root.dump());
  }

  std::error_code directory_error;
  std::filesystem::create_directories(
      std::filesystem::path(output_directory), directory_error);
  if (directory_error) {
    remove_request_dir(output_directory);
    root["error"] = "Unable to create RTP output directory.";
    return new_java_string(env, root.dump());
  }

  std::vector<int> frames;
  if (media_snapshot->limit_to_display_filter) {
    frames = snapshot_visible_frames(session.get());
  } else {
    frames.reserve(session->frame_offsets.size());
    for (size_t index = 0; index < session->frame_offsets.size(); ++index) {
      frames.push_back(static_cast<int>(index));
    }
  }

  jmethodID progress_method = nullptr;
  if (progress) {
    jclass progress_class = env->GetObjectClass(progress);
    progress_method =
        env->GetMethodID(progress_class, "onProgress", "(II)Z");
    env->DeleteLocalRef(progress_class);
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
    }
  }
  auto report_progress = [&](uint32_t done, uint32_t total) {
    if (!progress || !progress_method) {
      return true;
    }
    jboolean keep = env->CallBooleanMethod(
        progress, progress_method, static_cast<jint>(done),
        static_cast<jint>(total));
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      keep = JNI_FALSE;
    }
    return keep != JNI_FALSE;
  };

  layanalyzer::rtp::RtpExtractionRequest extraction_request;
  extraction_request.out_dir = output_directory;
  for (const SelectedStream &stream : selected) {
    extraction_request.keys.push_back(stream.key);
    extraction_request.stream_ids[stream.key] = stream.id;
  }

  const uint64_t cancel_generation = current_cancel_generation();
  const uint32_t total_frames = static_cast<uint32_t>(frames.size());
  layanalyzer::rtp::RtpExtractionResult extraction =
      layanalyzer::rtp::extract_rtp_payloads(
          session.get(), frames, extraction_request,
          [&](uint32_t done, uint32_t total) {
            uint32_t percent = 80;
            if (total != 0) {
              percent = static_cast<uint32_t>(
                  std::min<uint64_t>(
                      80u, static_cast<uint64_t>(done) * 80u / total));
            }
            return report_progress(percent, 100);
          },
          cancel_generation);

  if (extraction.cancelled) {
    remove_request_dir(output_directory);
    root["cancelled"] = true;
    return new_java_string(env, root.dump());
  }
  if (!extraction.error.empty()) {
    remove_request_dir(output_directory);
    root["error"] = extraction.error;
    return new_java_string(env, root.dump());
  }
  if (total_frames == 0) {
    report_progress(80, 100);
  }

  uint64_t total_records = 0;
  for (const SelectedStream &stream : selected) {
    const auto count_it = extraction.record_counts.find(stream.id);
    if (count_it != extraction.record_counts.end()) {
      total_records += count_it->second;
    }
  }
  uint64_t processed_records = 0;

  std::vector<RenderedAudioOutput> rendered_outputs;
  if (request.has_mix) {
    rendered_outputs.reserve(selected.size());
  }

  json items = json::array();
  for (const SelectedStream &stream : selected) {
    if (long_operation_cancelled(cancel_generation)) {
      remove_request_dir(output_directory);
      root["cancelled"] = true;
      return new_java_string(env, root.dump());
    }

    const auto path_it = extraction.rtpp_paths.find(stream.id);
    if (path_it == extraction.rtpp_paths.end()) {
      remove_request_dir(output_directory);
      root["error"] = "RTP payload output is missing.";
      return new_java_string(env, root.dump());
    }

    layanalyzer::rtp::RtppReadResult records;
    std::string file_error;
    if (!layanalyzer::rtp::read_rtpp_file(path_it->second, records,
                                          file_error)) {
      remove_request_dir(output_directory);
      root["error"] = file_error;
      return new_java_string(env, root.dump());
    }
    if (records.records.empty()) {
      remove_request_dir(output_directory);
      root["error"] = "No RTP payload records were extracted.";
      return new_java_string(env, root.dump());
    }

    layanalyzer::rtp::RtpMediaDecoder decoder(stream.media.codec);
    if (!decoder.available()) {
      remove_request_dir(output_directory);
      root["error"] = "RTP codec is unavailable.";
      return new_java_string(env, root.dump());
    }

    std::vector<layanalyzer::rtp::RtpRenderPacket> packets;
    std::vector<layanalyzer::rtp::RtppRecordHeader> cn_records;
    std::vector<layanalyzer::rtp::RtppRecordHeader> event_records;
    std::vector<const layanalyzer::rtp::RtppFileRecord *> dtmf_records;
    layanalyzer::rtp::RtppRecordHeader first_decoded_header;
    bool have_first_decoded_header = false;
    uint64_t decoded_packets = 0;
    unsigned stream_channels = decoder.channels();
    unsigned timestamp_rate = decoder.timestamp_rate();
    if (stream_channels == 0) {
      stream_channels = 1;
    }

    for (size_t record_index = 0; record_index < records.records.size();
         ++record_index) {
      if (long_operation_cancelled(cancel_generation)) {
        remove_request_dir(output_directory);
        root["cancelled"] = true;
        return new_java_string(env, root.dump());
      }

      const layanalyzer::rtp::RtppFileRecord &record =
          records.records[record_index];
      ++processed_records;
      if (total_records != 0 &&
          (processed_records % 256u == 0 ||
           processed_records == total_records)) {
        const uint32_t percent = static_cast<uint32_t>(
            80u + std::min<uint64_t>(
                      20u, processed_records * 20u / total_records));
        if (!report_progress(percent, 100)) {
          remove_request_dir(output_directory);
          root["cancelled"] = true;
          return new_java_string(env, root.dump());
        }
      }

      const uint32_t payload_type = record.header.pt;
      if (request.dtmf && stream.media.telephone_event_pt >= 0 &&
          payload_type ==
              static_cast<uint32_t>(stream.media.telephone_event_pt)) {
        dtmf_records.push_back(&record);
      }
      if (payload_type == 13u || payload_type == 19u) {
        cn_records.push_back(record.header);
        continue;
      }
      if ((stream.media.telephone_event_pt >= 0 &&
           payload_type ==
               static_cast<uint32_t>(stream.media.telephone_event_pt)) ||
          (stream.media.primary_pt >= 0 &&
           payload_type !=
               static_cast<uint32_t>(stream.media.primary_pt))) {
        event_records.push_back(record.header);
        continue;
      }

      layanalyzer::rtp::RtpRenderPacket packet;
      packet.frame_number = record.header.frame;
      packet.arrival_rel_sec = record.header.arrival_rel_sec;
      packet.ext_ts = record.header.ext_ts;
      packet.pt = record.header.pt;
      packet.marker = record.header.marker != 0;
      packet.ext_seq = record.header.ext_seq;
      const layanalyzer::rtp::RtpMediaDecoderResult decoded =
          decoder.decodePacket(payload_type, record.payload.data(),
                               record.payload.size(), packet.samples);
      if (!decoded.ok) {
        continue;
      }
      if (!have_first_decoded_header) {
        first_decoded_header = record.header;
        have_first_decoded_header = true;
      }
      ++decoded_packets;
      stream_channels = decoder.channels();
      if (stream_channels == 0) {
        stream_channels = 1;
      }
      timestamp_rate = decoder.timestamp_rate();
      packet.channels = stream_channels;
      packet.sample_rate = decoder.sample_rate();
      packet.timestamp_rate = timestamp_rate;
      packets.push_back(std::move(packet));
    }

    if (packets.empty()) {
      remove_request_dir(output_directory);
      root["error"] = "No decodable RTP packets were found.";
      return new_java_string(env, root.dump());
    }

    layanalyzer::rtp::RtpRenderOptions render_options;
    render_options.timing = request.timing;
    render_options.jitter_buffer_ms = request.jitter_ms;
    layanalyzer::rtp::RtpRenderResult rendered =
        layanalyzer::rtp::render_rtp_audio(packets, render_options);
    if (!rendered.error.empty()) {
      remove_request_dir(output_directory);
      root["error"] = rendered.error;
      return new_java_string(env, root.dump());
    }
    if (rendered.samples.empty() || rendered.sample_rate == 0) {
      remove_request_dir(output_directory);
      root["error"] = "RTP rendering produced no audio.";
      return new_java_string(env, root.dump());
    }

    const layanalyzer::rtp::RtppRecordHeader &first_decoded =
        first_decoded_header;
    json dtmf = json::array();
    if (request.dtmf && stream.media.telephone_event_pt >= 0) {
      std::vector<layanalyzer::rtp::DtmfPacket> dtmf_packets;
      dtmf_packets.reserve(dtmf_records.size());
      for (const layanalyzer::rtp::RtppFileRecord *record : dtmf_records) {
        layanalyzer::rtp::DtmfPacket packet;
        packet.pt = record->header.pt;
        packet.payload = record->payload;
        packet.at_ms =
            estimate_record_at_ms(record->header, first_decoded,
                                  request.timing, timestamp_rate);
        packet.frame = record->header.frame;
        packet.rtp_timestamp = record->header.ext_ts;
        dtmf_packets.push_back(std::move(packet));
      }

      unsigned dtmf_clock_rate = stream.media.clock_rate;
      if (dtmf_clock_rate == 0u) {
        dtmf_clock_rate = timestamp_rate;
      }
      const std::vector<layanalyzer::rtp::DtmfEvent> parsed_dtmf =
          layanalyzer::rtp::parse_dtmf_events(
              dtmf_packets,
              static_cast<uint32_t>(stream.media.telephone_event_pt),
              dtmf_clock_rate);
      for (const layanalyzer::rtp::DtmfEvent &event : parsed_dtmf) {
        dtmf.push_back({{"digit", event.digit},
                        {"atMs", event.at_ms},
                        {"durMs", event.dur_ms},
                        {"volume", event.volume},
                        {"frame", event.frame}});
      }
    }
    for (size_t cn_index = 0; cn_index < cn_records.size(); ++cn_index) {
      const layanalyzer::rtp::RtppRecordHeader &cn = cn_records[cn_index];
      const uint32_t at_ms =
          estimate_record_at_ms(cn, first_decoded, request.timing,
                                timestamp_rate);
      const layanalyzer::rtp::RtppRecordHeader *next = nullptr;
      if (cn_index + 1 < cn_records.size()) {
        next = &cn_records[cn_index + 1];
      }
      rendered.gaps.push_back(
          {at_ms, record_duration_ms(cn, next, timestamp_rate), "cn",
           cn.frame, false});
    }
    for (const layanalyzer::rtp::RtppRecordHeader &event : event_records) {
      rendered.events.push_back(
          {estimate_record_at_ms(event, first_decoded, request.timing,
                                 timestamp_rate),
           "ptChange", std::to_string(event.pt), event.frame});
    }
    std::stable_sort(
        rendered.gaps.begin(), rendered.gaps.end(),
        [](const layanalyzer::rtp::RtpRenderGap &left,
           const layanalyzer::rtp::RtpRenderGap &right) {
          return left.at_ms < right.at_ms;
        });
    std::stable_sort(
        rendered.events.begin(), rendered.events.end(),
        [](const layanalyzer::rtp::RtpRenderEvent &left,
           const layanalyzer::rtp::RtpRenderEvent &right) {
          return left.at_ms < right.at_ms;
        });

    int64_t lost = 0;
    uint64_t truncated_packets = extraction.truncated_packets;
    const layanalyzer::rtp::RtpCollectedStream *scan_stream =
        find_scan_stream(scan_snapshot, stream.id);
    if (scan_stream) {
      lost = scan_stream->stats.lost;
      truncated_packets = scan_stream->stats.truncated;
    }

    // The WAV/peaks/map writers and the `items[i]` object are shared verbatim
    // with RTP4-NAT-07, which renders decoded PCM instead of decoding payloads
    // itself: one builder, so the two endpoints cannot drift apart.
    RtpDecodedAudioItemMetadata item_metadata;
    item_metadata.stream_id = stream.id;
    item_metadata.codec = stream.media.codec;
    item_metadata.first_abs_epoch_us = stream.media.first_abs_epoch_us;
    item_metadata.start_rel_sec =
        records.records.front().header.arrival_rel_sec;
    item_metadata.channels = stream_channels;
    item_metadata.decoded_packets = decoded_packets;
    item_metadata.lost = lost;
    item_metadata.truncated_packets = truncated_packets;
    item_metadata.zero_payload_packets = extraction.zero_payload_packets;

    RtpDecodedAudioItem audio_item;
    std::string item_error;
    if (!build_rtp_decoded_audio_item(rendered, item_metadata,
                                      output_directory, audio_item,
                                      item_error)) {
      remove_request_dir(output_directory);
      root["error"] = item_error;
      return new_java_string(env, root.dump());
    }
    if (request.dtmf && stream.media.telephone_event_pt >= 0) {
      audio_item.item["dtmf"] = std::move(dtmf);
    }
    items.push_back(std::move(audio_item.item));

    if (request.has_mix) {
      rendered_outputs.push_back(
          {stream.id, std::move(rendered.samples), rendered.sample_rate,
           static_cast<double>(stream.media.first_abs_epoch_us) / 1000000.0,
           audio_item.wav_path, audio_item.peaks_path, audio_item.map_path});
    }
  }

  if (request.has_mix) {
    const auto find_rendered =
        [&](const std::string &stream_id) -> const RenderedAudioOutput * {
      const auto it = std::find_if(
          rendered_outputs.begin(), rendered_outputs.end(),
          [&](const RenderedAudioOutput &output) {
            return output.stream_id == stream_id;
          });
      return it == rendered_outputs.end() ? nullptr : &*it;
    };
    const RenderedAudioOutput *left =
        find_rendered(request.mix.left_stream_id);
    const RenderedAudioOutput *right =
        find_rendered(request.mix.right_stream_id);
    if (left == nullptr || right == nullptr) {
      remove_request_dir(output_directory);
      root["error"] = "RTP mix requires two decoded streams.";
      return new_java_string(env, root.dump());
    }

    json mix_json;
    std::string mix_error;
    if (!write_mix_output(output_directory, *left, *right, request.mix,
                          mix_json, mix_error)) {
      // The request directory is scratch on this path -- it holds only what
      // this call wrote -- so a rejected mix takes it with it.
      remove_request_dir(output_directory);
      root["error"] = mix_error.empty() ? "Unable to write RTP mix output."
                                        : mix_error;
      return new_java_string(env, root.dump());
    }
    root["mix"] = std::move(mix_json);
  }

  root["items"] = std::move(items);
  LOGI("decodeRtpAudio: streams=%zu ok=%zu unsupported=%zu take=%lldms",
       request.stream_ids.size(), selected.size(),
       root["unsupported"].size(),
       std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - decode_start)
           .count());
  return new_java_string(env, root.dump());
}

// exportRtpPayloadRaw request/result contract:
// NativeEngine.kt and model/RtpModels.kt
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_exportRtpPayloadRaw(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring requestJson,
    jstring outPath) {
  json root = {{"schemaVersion", 1},
               {"bytes", 0},
               {"packets", 0},
               {"error", ""}};

  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }
  if (!requestJson || !outPath) {
    root["error"] = "Missing RTP raw export request or output path.";
    return new_java_string(env, root.dump());
  }

  std::string request_text;
  const char *request_chars = env->GetStringUTFChars(requestJson, nullptr);
  if (request_chars) {
    request_text.assign(request_chars);
    env->ReleaseStringUTFChars(requestJson, request_chars);
  }
  std::string output_path_text;
  const char *output_chars = env->GetStringUTFChars(outPath, nullptr);
  if (output_chars) {
    output_path_text.assign(output_chars);
    env->ReleaseStringUTFChars(outPath, output_chars);
  }
  if (output_path_text.empty()) {
    root["error"] = "RTP raw export output path is empty.";
    return new_java_string(env, root.dump());
  }

  RtpRawExportRequest request;
  std::string request_error;
  if (!parse_rtp_raw_export_request(request_text, request, request_error)) {
    root["error"] = request_error;
    return new_java_string(env, root.dump());
  }

  const uint64_t current_generation =
      session->rtp_scan_generation.load(std::memory_order_acquire);
  if (request.scan_generation != current_generation) {
    root["error"] = "staleScan";
    return new_java_string(env, root.dump());
  }

  std::shared_ptr<const layanalyzer::rtp::RtpMediaSnapshot> media_snapshot;
  {
    std::lock_guard<std::mutex> lk(session->rtp_media_mutex);
    media_snapshot = session->rtp_last_media;
  }
  if (!media_snapshot ||
      media_snapshot->scan_generation != request.scan_generation) {
    root["error"] = "notFound";
    return new_java_string(env, root.dump());
  }

  const auto key_it =
      media_snapshot->stream_keys.find(request.stream_id);
  const auto media_it = media_snapshot->media.find(request.stream_id);
  if (key_it == media_snapshot->stream_keys.end() ||
      media_it == media_snapshot->media.end()) {
    root["error"] = "notFound";
    return new_java_string(env, root.dump());
  }

  const char *unsupported =
      raw_export_unsupported_reason(media_it->second);
  if (unsupported != nullptr) {
    root["error"] = unsupported;
    return new_java_string(env, root.dump());
  }
  if (media_it->second.primary_pt < 0) {
    root["error"] = "No primary RTP payload type was found.";
    return new_java_string(env, root.dump());
  }

  const std::filesystem::path output_path(output_path_text);
  if (output_path.filename().empty()) {
    root["error"] = "RTP raw export output path is invalid.";
    return new_java_string(env, root.dump());
  }

  std::filesystem::path output_parent = output_path.parent_path();
  if (output_parent.empty()) {
    std::error_code current_path_error;
    output_parent = std::filesystem::current_path(current_path_error);
    if (current_path_error) {
      root["error"] = "Unable to resolve RTP raw export output directory.";
      return new_java_string(env, root.dump());
    }
  }
  std::error_code parent_error;
  std::filesystem::create_directories(output_parent, parent_error);
  if (parent_error) {
    root["error"] = "Unable to create RTP raw export output directory.";
    return new_java_string(env, root.dump());
  }

  std::filesystem::path work_directory;
  std::string work_error;
  if (!create_unique_work_directory(
          output_parent, output_path.filename().string(), work_directory,
          work_error)) {
    root["error"] = work_error;
    return new_java_string(env, root.dump());
  }
  ScopedPathRemoval work_cleanup(work_directory);

  std::vector<int> frames;
  if (media_snapshot->limit_to_display_filter) {
    frames = snapshot_visible_frames(session.get());
  } else {
    frames.reserve(session->frame_offsets.size());
    for (size_t index = 0; index < session->frame_offsets.size(); ++index) {
      frames.push_back(static_cast<int>(index));
    }
  }

  layanalyzer::rtp::RtpExtractionRequest extraction_request;
  extraction_request.out_dir = work_directory.string();
  extraction_request.keys.push_back(key_it->second);
  extraction_request.stream_ids[key_it->second] = request.stream_id;

  const uint64_t cancel_generation = current_cancel_generation();
  layanalyzer::rtp::RtpExtractionResult extraction =
      layanalyzer::rtp::extract_rtp_payloads(
          session.get(), frames, extraction_request,
          std::function<bool(uint32_t, uint32_t)>(), cancel_generation);
  if (extraction.cancelled) {
    root["error"] = "cancelled";
    return new_java_string(env, root.dump());
  }
  if (!extraction.error.empty()) {
    root["error"] = extraction.error;
    return new_java_string(env, root.dump());
  }

  const auto rtpp_it = extraction.rtpp_paths.find(request.stream_id);
  if (rtpp_it == extraction.rtpp_paths.end()) {
    root["error"] = "RTP payload extraction output is missing.";
    return new_java_string(env, root.dump());
  }

  layanalyzer::rtp::RtppReadResult records;
  std::string records_error;
  if (!layanalyzer::rtp::read_rtpp_file(
          rtpp_it->second, records, records_error)) {
    root["error"] = records_error;
    return new_java_string(env, root.dump());
  }
  if (records.records.empty()) {
    root["error"] = "No RTP payload records were extracted.";
    return new_java_string(env, root.dump());
  }

  std::vector<layanalyzer::rtp::RtppIndexEntry> sequence_index;
  if (request.order == RtpRawExportOrder::Sequence) {
    const auto index_it = extraction.index_paths.find(request.stream_id);
    if (index_it == extraction.index_paths.end()) {
      root["error"] = "RTP payload index is missing.";
      return new_java_string(env, root.dump());
    }
    std::string index_error;
    if (!layanalyzer::rtp::read_rtpp_index(
            index_it->second, sequence_index, index_error)) {
      root["error"] = index_error;
      return new_java_string(env, root.dump());
    }
  }

  std::FILE *output = std::fopen(output_path_text.c_str(), "wb");
  if (!output) {
    root["error"] = "Unable to open RTP raw payload output.";
    return new_java_string(env, root.dump());
  }
  ScopedPathRemoval output_cleanup(output_path);

  uint64_t total_bytes = 0;
  uint64_t packet_count = 0;
  std::string write_error;
  const uint32_t primary_pt =
      static_cast<uint32_t>(media_it->second.primary_pt);

  auto write_record =
      [&](const layanalyzer::rtp::RtppRecordHeader &header,
          const uint8_t *payload, size_t length) {
        if (header.pt != primary_pt) {
          return true;
        }
        if (!write_raw_payload(output, payload, length, total_bytes,
                               write_error)) {
          return false;
        }
        ++packet_count;
        return true;
      };

  bool write_ok = true;
  if (request.order == RtpRawExportOrder::Arrival) {
    for (const layanalyzer::rtp::RtppFileRecord &record : records.records) {
      if (!write_record(record.header, record.payload.data(),
                        record.payload.size())) {
        write_ok = false;
        break;
      }
    }
  } else {
    std::FILE *input = std::fopen(rtpp_it->second.c_str(), "rb");
    if (!input) {
      write_error = "Unable to open extracted RTP payload file.";
      write_ok = false;
    }
    std::vector<uint8_t> payload;
    for (const layanalyzer::rtp::RtppIndexEntry &entry : sequence_index) {
      if (!write_ok) break;
      if (entry.record_index >= records.records.size()) {
        write_error = "RTP payload index references an invalid record.";
        write_ok = false;
        break;
      }
      const layanalyzer::rtp::RtppFileRecord &record =
          records.records[entry.record_index];
      if (entry.length != record.payload.size()) {
        write_error = "RTP payload index length does not match the record.";
        write_ok = false;
        break;
      }
      if (entry.offset >
              static_cast<uint64_t>(LONG_MAX) -
                  layanalyzer::rtp::kRtppRecordHeaderSize ||
          std::fseek(input, static_cast<long>(
                                entry.offset +
                                layanalyzer::rtp::kRtppRecordHeaderSize),
                     SEEK_SET) != 0) {
        write_error = "Unable to seek to an RTP payload record.";
        write_ok = false;
        break;
      }
      payload.resize(entry.length);
      if (entry.length != 0 &&
          std::fread(payload.data(), 1, entry.length, input) !=
              entry.length) {
        write_error = "Unable to read an RTP payload record.";
        write_ok = false;
        break;
      }
      if (!write_record(record.header, payload.data(), payload.size())) {
        write_ok = false;
        break;
      }
    }
    if (input) {
      std::fclose(input);
    }
  }

  if (!write_ok) {
    std::fclose(output);
    output = nullptr;
    root["error"] =
        write_error.empty() ? "Unable to write RTP raw payload output."
                            : write_error;
    return new_java_string(env, root.dump());
  }
  if (!close_raw_output(output, output_path, write_error)) {
    root["error"] = write_error;
    return new_java_string(env, root.dump());
  }

  output_cleanup.release();
  root["bytes"] = total_bytes;
  root["packets"] = packet_count;
  LOGI("exportRtpPayloadRaw: stream=%s packets=%llu bytes=%llu order=%s",
       request.stream_id.c_str(),
       static_cast<unsigned long long>(packet_count),
       static_cast<unsigned long long>(total_bytes),
       request.order == RtpRawExportOrder::Sequence ? "seq" : "arrival");
  return new_java_string(env, root.dump());
}

// {"schemaVersion":1,"enabled":<值>,"failed":[...],"error":""}.
// Enables/disables the four `rtp_*` heuristic dissectors process-wide. The
// whole transition runs inside RuntimeExclusiveGuard: the heuristic table is
// process-global epan state, so no session may be dissecting. The guard must
// stay short-lived -- never run a scan inside it.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_setRtpHeuristicEnabled(JNIEnv *env,
                                                                 jobject /* this */,
                                                                 jboolean enabled) {
  RuntimeExclusiveGuard runtime_guard;
  const bool next_enabled = enabled == JNI_TRUE;

  // Names from reference/wireshark-4.0.10/epan/dissectors/packet-rtp.c:3398-3401
  // and epan/disabled_protos.h:38. A FALSE return only records the name; the
  // remaining heuristics are still applied.
  static const char *const kHeuristicNames[] = {
      "rtp_udp", "rtp_stun", "rtp_classicstun", "rtp_rtsp"};
  json failed = json::array();
  for (const char *name : kHeuristicNames) {
    if (proto_enable_heuristic_by_name(name, next_enabled ? TRUE : FALSE) ==
        FALSE) {
      failed.push_back(name);
    }
  }

  set_rtp_heuristic_enabled(next_enabled);

  // Which UDP flows count as RTP changes dissection, so Wireshark's cross-frame
  // state has to go with the caches (see reset_dissection_state).
  reset_dissection_state();

  json root = {{"schemaVersion", 1},
               {"enabled", next_enabled},
               {"failed", std::move(failed)},
               {"error", ""}};
  return new_java_string(env, root.dump());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_layanalyzer_NativeEngine_isRtpHeuristicEnabled(JNIEnv * /* env */,
                                                                jobject /* this */) {
  return rtp_heuristic_enabled() ? JNI_TRUE : JNI_FALSE;
}

// RTP4-KT-05: this build's codec capabilities. Process-wide and session-less
// by design -- the two build switches are compile-time facts about the shipped
// library, not about a capture, so there is nothing to acquire and no
// RuntimeExclusiveGuard to take (nothing here mutates engine or session state).
//
//   {"schemaVersion":1,"error":"","audio":[...],"video":[...],
//    "g729":true,"ilbc":false}
//
// `audio` and `video` are copies of the two lists in core/RtpCodecNames.h
// rather than a second table: the point of this endpoint is that Kotlin can
// check its own catalog against the very list rtp_decodability() consults
// (RtpCodecConsistencyTest). `g729` / `ilbc` answer "did this build link the
// optional codec?", which is what the PT mapping dialog greys an entry out on.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getRtpCodecCapabilities(
    JNIEnv *env, jobject /* this */) {
  json audio = json::array();
  for (const char *id : layanalyzer::rtp::kSupportedAudioCodecs) {
    audio.push_back(id);
  }
  json video = json::array();
  for (const char *id : layanalyzer::rtp::kSupportedVideoCodecs) {
    video.push_back(id);
  }

  json root = {{"schemaVersion", 1},
               {"error", ""},
               {"audio", std::move(audio)},
               {"video", std::move(video)},
               {"g729", layanalyzer::rtp::kBuildIncludesG729},
               {"ilbc", layanalyzer::rtp::kBuildIncludesIlbc}};
  return new_java_string(env, root.dump());
}

// {"overrides":[{"pt":96,"codec":"AMR-WB","clockRate":16000,"channels":1}]}
//   -> {"schemaVersion":1,"error":"","count":N}
// 任何一条不合法（pt 越界 / codec 为空 / JSON 结构错误）都返回 error 且**整体不替换**
// （fail-closed，RtpPayloadOverrides::set_from_json 保证）。成功后替换会话的
// rtp_overrides 并让 rtp_scan_generation 自增。
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_setRtpPayloadOverrides(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring jsonArg) {
  json root = {{"schemaVersion", 1}, {"error", ""}, {"count", 0}};
  auto session = acquire_session(sessionPtr);
  if (!session) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }
  if (!jsonArg) {
    root["error"] = "Missing overrides JSON.";
    return new_java_string(env, root.dump());
  }

  std::string request;
  const char *request_chars = env->GetStringUTFChars(jsonArg, nullptr);
  if (request_chars) {
    request.assign(request_chars);
    env->ReleaseStringUTFChars(jsonArg, request_chars);
  }

  // 先解析到临时表：只有完全成功才替换会话里的那一份。
  layanalyzer::rtp::RtpPayloadOverrides parsed;
  std::string error;
  if (!parsed.set_from_json(request, error)) {
    root["error"] = error;
    LOGW("setRtpPayloadOverrides: rejected overrides request");
    return new_java_string(env, root.dump());
  }

  // clockRate 不在 {0,8000,16000,44100,48000} 的条目：接受但记 warning（只打 PT 与
  // 数值，不打 codec 名字以外的任何负载信息）。
  static const int kAllowedClockRates[] = {0, 8000, 16000, 44100, 48000};
  for (const layanalyzer::rtp::RtpPayloadOverride &item : parsed.items()) {
    bool allowed = false;
    for (int rate : kAllowedClockRates) {
      if (item.clock_rate == rate) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      LOGW("setRtpPayloadOverrides: pt=%u nonstandard clockRate=%d",
           static_cast<unsigned>(item.pt), item.clock_rate);
    }
  }

  const size_t count = parsed.size();
  {
    std::lock_guard<std::mutex> lk(session->rtp_mutex);
    session->rtp_overrides = std::move(parsed);
  }
  session->rtp_scan_generation.fetch_add(1);

  root["count"] = static_cast<int>(count);
  LOGI("setRtpPayloadOverrides: count=%zu", count);
  return new_java_string(env, root.dump());
}

// extractRtpCodecFrames request/result contract: RTP4-NAT-06 card (m4.md), and
// the signature from task_rtp_m4_codecs.md section 3.2.
//
//   {"scanGeneration":7,"streamId":"s3","amrMode":"auto|octet|be",
//    "amrOctetAligned":true|null,"amrCrc":false,"amrInterleaved":false}
//   -> {"schemaVersion":1,"error":"","cancelled":false,
//       "framesPath":".../s3.frames","indexPath":".../s3.fidx","codec":"AMR-WB",
//       "sampleRate":16000,"channels":1,"mime":"audio/amr-wb","csd":[],
//       "frameCount":1500,"detectedAmrMode":"octet",
//       "speechLostFrames":2,"noDataFrames":3}
//
// `csd` is `[]` for AMR and AMR-WB, and for Opus it is three base64 entries --
// OpusHead, the pre-skip in nanoseconds and the seek pre-roll in nanoseconds --
// because the platform Opus decoder will not start without `csd-0` (RTP4-KT-02;
// see the note where it is filled in below).
//
// `detectedAmrMode` is omitted for Opus, where it has no meaning.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_extractRtpCodecFrames(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring requestJson,
    jstring outDir, jobject progress) {
  json root = {{"schemaVersion", 1},
               {"error", ""},
               {"cancelled", false},
               {"framesPath", ""},
               {"indexPath", ""},
               {"codec", ""},
               {"sampleRate", 0},
               {"channels", 1},
               {"mime", ""},
               {"csd", json::array()},
               {"frameCount", 0},
               {"speechLostFrames", 0},
               {"noDataFrames", 0}};
  const auto extract_start = std::chrono::steady_clock::now();

  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }
  if (!requestJson || !outDir) {
    root["error"] = "Missing codec frame request or output directory.";
    return new_java_string(env, root.dump());
  }

  std::string request_text;
  const char *request_chars = env->GetStringUTFChars(requestJson, nullptr);
  if (request_chars) {
    request_text.assign(request_chars);
    env->ReleaseStringUTFChars(requestJson, request_chars);
  }
  std::string output_directory;
  const char *out_dir_chars = env->GetStringUTFChars(outDir, nullptr);
  if (out_dir_chars) {
    output_directory.assign(out_dir_chars);
    env->ReleaseStringUTFChars(outDir, out_dir_chars);
  }
  if (output_directory.empty()) {
    root["error"] = "RTP output directory is empty.";
    return new_java_string(env, root.dump());
  }

  RtpCodecFramesRequest request;
  std::string request_error;
  if (!parse_rtp_codec_frames_request(request_text, request, request_error)) {
    root["error"] = request_error;
    return new_java_string(env, root.dump());
  }

  RtpCodecFramesContext context;
  std::string reject_reason;
  if (!resolve_codec_frames_stream(session.get(), request, context,
                                   reject_reason)) {
    root["error"] = reject_reason;
    return new_java_string(env, root.dump());
  }

  std::error_code directory_error;
  std::filesystem::create_directories(
      std::filesystem::path(output_directory), directory_error);
  if (directory_error) {
    remove_request_dir(output_directory);
    root["error"] = "Unable to create RTP output directory.";
    return new_java_string(env, root.dump());
  }

  jmethodID progress_method = nullptr;
  if (progress) {
    jclass progress_class = env->GetObjectClass(progress);
    progress_method = env->GetMethodID(progress_class, "onProgress", "(II)Z");
    env->DeleteLocalRef(progress_class);
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
    }
  }
  auto report_progress = [&](uint32_t done, uint32_t total) {
    if (!progress || !progress_method) {
      return true;
    }
    jboolean keep = env->CallBooleanMethod(
        progress, progress_method, static_cast<jint>(done),
        static_cast<jint>(total));
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      keep = JNI_FALSE;
    }
    return keep != JNI_FALSE;
  };

  RtpCodecFramesResult extracted;
  if (!run_codec_frames_extraction(session.get(), context, request,
                                   output_directory, report_progress,
                                   extracted)) {
    // Never leave partial results behind: the request directory is the
    // caller's, and it only ever holds files this call produced.
    remove_request_dir(output_directory);
    if (extracted.cancelled) {
      root["cancelled"] = true;
      return new_java_string(env, root.dump());
    }
    root["error"] = extracted.error.empty()
                        ? "Unable to extract RTP codec frames."
                        : extracted.error;
    return new_java_string(env, root.dump());
  }

  const std::string frames_path =
      join_path(output_directory, request.stream_id + ".frames");
  const std::string index_path =
      join_path(output_directory, request.stream_id + ".fidx");
  std::string write_error;
  if (!write_binary_file(frames_path, extracted.frames, write_error) ||
      !layanalyzer::rtp::write_fidx_file(index_path, extracted.entries,
                                         write_error)) {
    remove_request_dir(output_directory);
    root["error"] =
        write_error.empty() ? "Unable to write RTP codec frame output."
                            : write_error;
    return new_java_string(env, root.dump());
  }

  root["framesPath"] = frames_path;
  root["indexPath"] = index_path;
  root["codec"] = extracted.codec;
  root["sampleRate"] = static_cast<uint32_t>(extracted.sample_rate);
  root["channels"] = static_cast<uint32_t>(extracted.channels);
  root["mime"] = extracted.mime;
  // `csd` is what the platform decoder needs before it will start, and the
  // answer is not the same for every codec. RTP4-NAT-06's card item 6 said
  // "Opus 为 `[]`（MediaCodec 的 Opus 解码器不需要 CSD）"; that was measured
  // wrong, and RTP4-KT-01 on a MI 9 (arm64, API 30) showed how:
  //
  //   E C2SoftOpusDec: process encountered error in GetOpusHeaderBuffers
  //
  // The AOSP Opus decoder parses the RFC 7845 OpusHead identification header
  // out of `csd-0` and refuses to start without it; RTP4-KT-01 reports the
  // dead `dequeueOutputBuffer` that follows as `IllegalStateException`. The
  // task doc's section 3.2 keeps `csd` in the result for exactly this need, so
  // it is filled here:
  //
  //   Opus    `csd-0` the 19-octet OpusHead, base64-encoded (the same bytes
  //           `build_opus_head` puts on page 0 of the Ogg export), `csd-1` the
  //           pre-skip and `csd-2` the seek pre-roll, each a 64-bit
  //           little-endian nanosecond count as MediaCodec documents them.
  //   AMR/AMR-WB  empty. The card is right about these two: neither platform
  //           decoder takes codec-specific data, and an AMR CSD would be
  //           invented rather than described.
  //
  // Requesting `csd-1`/`csd-2` in nanoseconds is what the AOSP decoder reads
  // (`C2SoftOpusDec`), and the values come from the same options the export
  // uses, so the two containers describe one stream.
  root["csd"] = json::array();
  if (extracted.codec == "opus") {
    // `channels` is 1 for every stream this endpoint accepts (see
    // `run_codec_frames_extraction`), and `OggOpusOptions` defaults to 1, so a
    // zero here leaves the header saying mono rather than claiming zero
    // channels.
    layanalyzer::rtp::OggOpusOptions opus_options;
    if (extracted.channels != 0u) {
      opus_options.channels = static_cast<uint8_t>(extracted.channels);
    }
    const uint64_t pre_skip_ns =
        static_cast<uint64_t>(opus_options.pre_skip) * 1000000000ull /
        kOpusClockRate;
    root["csd"].push_back(
        base64_encode(layanalyzer::rtp::build_opus_head(opus_options)));
    root["csd"].push_back(base64_encode(le_u64_bytes(pre_skip_ns)));
    root["csd"].push_back(base64_encode(le_u64_bytes(kOpusSeekPrerollNs)));
  }
  // What the caller indexes: the `.fidx` entry count, lost placeholders
  // included.
  root["frameCount"] = static_cast<uint64_t>(extracted.entries.size());
  if (!extracted.detected_amr_mode.empty()) {
    root["detectedAmrMode"] = extracted.detected_amr_mode;
  }
  root["speechLostFrames"] = extracted.speech_lost_frames;
  root["noDataFrames"] = extracted.no_data_frames;

  LOGI(
      "extractRtpCodecFrames: stream=%s codec=%s frames=%zu lost=%llu sid=%llu "
      "empty=%llu take=%lldms",
      request.stream_id.c_str(), extracted.codec.c_str(),
      extracted.entries.size(),
      static_cast<unsigned long long>(extracted.no_data_frames),
      static_cast<unsigned long long>(extracted.speech_lost_frames),
      static_cast<unsigned long long>(extracted.zero_payload_records),
      static_cast<long long>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - extract_start)
              .count()));
  return new_java_string(env, root.dump());
}

// exportRtpContainer contract.
//
// The RTP4-NAT-06 card requires this endpoint but freezes neither its signature
// nor its JSON shape, so the contract below is chosen here and RTP4-KT-03
// consumes it as written:
//
//   external fun exportRtpContainer(sessionPtr: Long, requestJson: String, outDir: String): String
//   request: {"scanGeneration":7,"streamId":"s3","format":"amr|awb|opus",
//             "amrMode":"auto|octet|be","amrOctetAligned":true|null,
//             "amrCrc":false,"amrInterleaved":false}
//   result:  {"schemaVersion":1,"error":"","cancelled":false,
//             "path":".../s3.amr","format":"amr","frameCount":1500,"byteCount":45600}
//
// It runs the same extraction as extractRtpCodecFrames, but entirely in
// memory: no `.frames` and no `.fidx` are left behind, only the one container.
// `frameCount` is the number of frames actually written, so the lost
// placeholders an `.amr`/`.awb` container skips are not counted (unlike
// extractRtpCodecFrames, where the caller indexes every entry).
//
// `outDir` is written into, never removed: unlike extractRtpCodecFrames, whose
// output directory is a private per-request directory that holds only that
// call's files, this endpoint's contract says "writes one file into outDir", so
// it assumes nothing about what else is there. A failure therefore removes only
// the half-written container (`ScopedPathRemoval`), which is exactly what the
// card asks for.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_exportRtpContainer(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring requestJson,
    jstring outDir) {
  json root = {{"schemaVersion", 1}, {"error", ""}, {"cancelled", false},
               {"path", ""},     {"format", ""},   {"frameCount", 0},
               {"byteCount", 0}};
  const auto export_start = std::chrono::steady_clock::now();

  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }
  if (!requestJson || !outDir) {
    root["error"] = "Missing container export request or output directory.";
    return new_java_string(env, root.dump());
  }

  std::string request_text;
  const char *request_chars = env->GetStringUTFChars(requestJson, nullptr);
  if (request_chars) {
    request_text.assign(request_chars);
    env->ReleaseStringUTFChars(requestJson, request_chars);
  }
  std::string output_directory;
  const char *out_dir_chars = env->GetStringUTFChars(outDir, nullptr);
  if (out_dir_chars) {
    output_directory.assign(out_dir_chars);
    env->ReleaseStringUTFChars(outDir, out_dir_chars);
  }
  if (output_directory.empty()) {
    root["error"] = "RTP output directory is empty.";
    return new_java_string(env, root.dump());
  }

  RtpCodecFramesRequest request;
  std::string request_error;
  if (!parse_rtp_codec_frames_request(request_text, request, request_error)) {
    root["error"] = request_error;
    return new_java_string(env, root.dump());
  }
  if (request.format != "amr" && request.format != "awb" &&
      request.format != "opus") {
    root["error"] = "format must be amr, awb or opus.";
    return new_java_string(env, root.dump());
  }

  RtpCodecFramesContext context;
  std::string reject_reason;
  if (!resolve_codec_frames_stream(session.get(), request, context,
                                   reject_reason)) {
    root["error"] = reject_reason;
    return new_java_string(env, root.dump());
  }

  // The caller names the container, so the name has to agree with the stream: a
  // `#!AMR\n` file full of AMR-WB frames is not playable anywhere, and writing
  // it would turn a caller mistake into a corrupt artefact.
  const char *expected_format = context.route == RtpCodecRoute::AmrWb
                                    ? "awb"
                                    : (context.route == RtpCodecRoute::Opus
                                           ? "opus"
                                           : "amr");
  if (request.format != expected_format) {
    root["error"] = "format does not match the stream codec.";
    return new_java_string(env, root.dump());
  }

  std::error_code directory_error;
  std::filesystem::create_directories(
      std::filesystem::path(output_directory), directory_error);
  if (directory_error) {
    root["error"] = "Unable to create RTP container output directory.";
    return new_java_string(env, root.dump());
  }

  RtpCodecFramesResult extracted;
  if (!run_codec_frames_extraction(
          session.get(), context, request, output_directory,
          std::function<bool(uint32_t, uint32_t)>(), extracted)) {
    if (extracted.cancelled) {
      root["cancelled"] = true;
      return new_java_string(env, root.dump());
    }
    root["error"] = extracted.error.empty()
                        ? "Unable to export the RTP container."
                        : extracted.error;
    return new_java_string(env, root.dump());
  }

  const std::string container_path =
      join_path(output_directory, request.stream_id + "." + expected_format);
  // Declared before the writer so it outlives it: on Windows a still-open file
  // cannot be unlinked, and the writer has to be destructed first.
  ScopedPathRemoval container_cleanup(container_path);

  uint64_t byte_count = 0;
  uint64_t frame_count = 0;
  std::string write_error;
  bool write_ok = false;

  if (context.route == RtpCodecRoute::Opus) {
    {
      layanalyzer::rtp::OggOpusOptions options;
      options.channels = 1;
      options.pre_skip = 312;
      layanalyzer::rtp::OggOpusWriter writer;
      // No early return inside this block: the writer closes the file in its
      // destructor, and the removal guard below runs after it.
      write_ok = writer.open(container_path, options, write_error);
      if (write_ok) {
        for (const layanalyzer::rtp::FidxEntry &entry : extracted.entries) {
          if (entry.offset + entry.length > extracted.frames.size()) {
            write_ok = false;
            write_error = "RTP codec frame index is out of range.";
            break;
          }
          // One RTP packet per Ogg packet, granule = the packet's RTP
          // timestamp (the 48 kHz clock Ogg Opus pages are counted on).
          if (!writer.writePacket(extracted.frames.data() + entry.offset,
                                  entry.length, entry.ext_ts, write_error)) {
            write_ok = false;
            break;
          }
          ++frame_count;
        }
      }
      if (write_ok) {
        write_ok = writer.finalize(write_error);
      }
    }
    if (write_ok) {
      std::error_code size_error;
      const uintmax_t size =
          std::filesystem::file_size(container_path, size_error);
      if (!size_error) {
        byte_count = static_cast<uint64_t>(size);
      }
    }
  } else {
    // "#!AMR\n" is 6 octets, "#!AMR-WB\n" is 9 (RFC 4867 section 5).
    static const char kAmrMagic[] = "#!AMR\n";
    static const char kAmrWbMagic[] = "#!AMR-WB\n";
    const bool is_wb = context.route == RtpCodecRoute::AmrWb;
    const char *magic = is_wb ? kAmrWbMagic : kAmrMagic;
    const size_t magic_length = is_wb ? 9u : 6u;

    std::FILE *file = std::fopen(container_path.c_str(), "wb");
    if (!file) {
      root["error"] = "Unable to open RTP container output.";
      return new_java_string(env, root.dump());
    }
    write_ok = std::fwrite(magic, 1, magic_length, file) == magic_length;
    if (write_ok) {
      byte_count = magic_length;
    }
    for (const layanalyzer::rtp::FidxEntry &entry : extracted.entries) {
      if (!write_ok) break;
      // A lost placeholder occupies a timeline slot but carries no frame, and
      // the storage format has no way to express one -- it is simply absent.
      if (entry.length == 0) continue;
      if (entry.offset + entry.length > extracted.frames.size()) {
        write_ok = false;
        write_error = "RTP codec frame index is out of range.";
        break;
      }
      if (std::fwrite(extracted.frames.data() + entry.offset, 1, entry.length,
                      file) != entry.length) {
        write_ok = false;
        break;
      }
      byte_count += entry.length;
      ++frame_count;
    }
    if (write_ok && std::fflush(file) != 0) write_ok = false;
    if (std::fclose(file) != 0) write_ok = false;
  }

  if (!write_ok) {
    // The guard removes the half-written container on the way out.
    root["error"] = write_error.empty() ? "Unable to write the RTP container."
                                        : write_error;
    return new_java_string(env, root.dump());
  }
  container_cleanup.release();

  root["path"] = container_path;
  root["format"] = request.format;
  root["frameCount"] = frame_count;
  root["byteCount"] = byte_count;

  LOGI("exportRtpContainer: stream=%s format=%s frames=%llu bytes=%llu "
       "take=%lldms",
       request.stream_id.c_str(), request.format.c_str(),
       static_cast<unsigned long long>(frame_count),
       static_cast<unsigned long long>(byte_count),
       static_cast<long long>(
           std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - export_start)
               .count()));
  return new_java_string(env, root.dump());
}

// renderRtpAudioFromPcm request/result contract: RTP4-NAT-07 card (m4.md) and
// the signature from task_rtp_m4_codecs.md section 3.2.
//
//   {"scanGeneration":7,"streamId":"s3","pcmPath":".../s3.pcmchunks",
//    "sampleRate":16000,"channels":1,"timing":"jitter","jitterMs":50}
//   -> the `decodeRtpAudio` `items[i]` object, plus the envelope:
//      {"schemaVersion":1,"error":"","cancelled":false,
//       "streamId":"s3","codec":"AMR-WB","sampleRate":16000,"channels":1,
//       "wavPath":".../s3.wav","peaksPath":".../s3.peaks","mapPath":".../s3.map",
//       "durationMs":30000,"startRel":1.25,"startAbsEpochMs":1500000000000,
//       "gaps":[...],"events":[...],
//       "stats":{"decodedPackets":1500,"droppedLate":0,"lost":0,
//                "truncatedPackets":0,"zeroPayloadPackets":0}}
//
// `dtmf` is absent: this path has no telephone-event records, so there is
// nothing that could fill it. The item keys are pre-populated with neutral
// values so the shape the Kotlin parser sees does not depend on success, and
// every failure leaves them at those neutral values.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_renderRtpAudioFromPcm(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring requestJson,
    jstring outDir) {
  json root = {{"schemaVersion", 1},
               {"error", ""},
               {"cancelled", false},
               {"streamId", ""},
               {"codec", ""},
               {"sampleRate", 0},
               {"channels", 1},
               {"wavPath", ""},
               {"peaksPath", ""},
               {"mapPath", ""},
               {"durationMs", 0},
               {"startRel", 0.0},
               {"startAbsEpochMs", 0},
               {"gaps", json::array()},
               {"events", json::array()},
               {"stats",
                {{"decodedPackets", 0},
                 {"droppedLate", 0},
                 {"lost", 0},
                 {"truncatedPackets", 0},
                 {"zeroPayloadPackets", 0}}}};
  const auto render_start = std::chrono::steady_clock::now();

  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }
  if (!requestJson || !outDir) {
    root["error"] = "Missing PCM render request or output directory.";
    return new_java_string(env, root.dump());
  }

  std::string request_text;
  const char *request_chars = env->GetStringUTFChars(requestJson, nullptr);
  if (request_chars) {
    request_text.assign(request_chars);
    env->ReleaseStringUTFChars(requestJson, request_chars);
  }
  std::string output_directory;
  const char *out_dir_chars = env->GetStringUTFChars(outDir, nullptr);
  if (out_dir_chars) {
    output_directory.assign(out_dir_chars);
    env->ReleaseStringUTFChars(outDir, out_dir_chars);
  }
  if (output_directory.empty()) {
    root["error"] = "RTP output directory is empty.";
    return new_java_string(env, root.dump());
  }

  RtpPcmRenderRequest request;
  std::string request_error;
  if (!parse_rtp_pcm_render_request(request_text, request, request_error)) {
    root["error"] = request_error;
    return new_java_string(env, root.dump());
  }

  // The same snapshot lookup RTP4-NAT-06 uses, and deliberately nothing else
  // from it: this endpoint is codec-agnostic. It is the second half of the
  // MEDIACODEC route and only needs the stream's `codec` and
  // `firstAbsEpochUs` for the item; whether the codec is AMR, AMR-WB, Opus or
  // something the native decoder already handles is not its business, and the
  // `srtp` / `needsMapping` / `nativeDecode` rejections would only keep a
  // caller from rendering PCM it already has.
  RtpCodecFramesContext context;
  std::string reject_reason;
  if (!resolve_scan_stream(session.get(), request.scan_generation,
                           request.stream_id, context, reject_reason)) {
    remove_request_dir(output_directory);
    root["error"] = reject_reason;
    return new_java_string(env, root.dump());
  }

  // Everything below up to the first writer is validation: any failure returns
  // with a non-empty `error` and without having created a single output file.
  //
  // Every failure path from here on also removes the caller's request
  // directory, `decodeRtpAudio`'s rule. That directory is scratch by
  // construction -- RTP4-KT-02 keeps `.frames`, `.fidx`, `.pcmchunks` and the
  // rendered WAV in one per-request directory -- so a rejected render must not
  // leave a half-consumed decode behind for a retry to trip over.
  const std::string index_path =
      join_path(parent_directory_of(request.pcm_path),
                request.stream_id + ".fidx");
  std::vector<layanalyzer::rtp::FidxEntry> entries;
  std::string file_error;
  if (!layanalyzer::rtp::read_fidx_file(index_path, entries, file_error)) {
    remove_request_dir(output_directory);
    root["error"] =
        file_error.empty() ? "Unable to read the RTP frame index." : file_error;
    return new_java_string(env, root.dump());
  }
  if (entries.empty()) {
    remove_request_dir(output_directory);
    root["error"] = "The RTP frame index is empty.";
    return new_java_string(env, root.dump());
  }

  std::vector<uint8_t> pcm_bytes;
  if (!read_binary_file(request.pcm_path, pcm_bytes, file_error)) {
    remove_request_dir(output_directory);
    root["error"] = file_error;
    return new_java_string(env, root.dump());
  }
  std::vector<RtpPcmChunk> chunks;
  if (!parse_pcm_chunks(pcm_bytes, request.sample_rate, request.channels,
                        entries.size(), chunks, file_error)) {
    remove_request_dir(output_directory);
    root["error"] = file_error;
    return new_java_string(env, root.dump());
  }

  // `.pcmchunks` is written in decode order and `.fidx` is the order the
  // renderer needs, so one lookup table maps an entry to its chunk.
  constexpr size_t kNoChunk = std::numeric_limits<size_t>::max();
  std::vector<size_t> chunk_by_entry(entries.size(), kNoChunk);
  for (size_t index = 0; index < chunks.size(); ++index) {
    chunk_by_entry[chunks[index].fidx_index] = index;
  }

  const uint64_t cancel_generation = current_cancel_generation();
  std::vector<layanalyzer::rtp::RtpRenderPacket> packets;
  packets.reserve(entries.size());
  layanalyzer::rtp::RtppRecordHeader first_decoded;
  bool have_first_decoded = false;
  uint64_t lost_entries = 0;
  uint64_t missing_chunks = 0;

  for (size_t index = 0; index < entries.size(); ++index) {
    if (long_operation_cancelled(cancel_generation)) {
      remove_request_dir(output_directory);
      root["cancelled"] = true;
      return new_java_string(env, root.dump());
    }

    const layanalyzer::rtp::FidxEntry &entry = entries[index];
    // A lost entry has no frame data at all, so it can never be a render packet
    // and never did decode. It becomes one `lost` gap below instead.
    if ((entry.flags & layanalyzer::rtp::kFidxFlagLost) != 0) {
      ++lost_entries;
      continue;
    }
    const size_t chunk_index = chunk_by_entry[index];
    if (chunk_index == kNoChunk) {
      // MediaCodec produced nothing for this frame. No packet is possible, and
      // no `lost` gap is synthesised either: the renderer advances its own
      // timeline by the timestamp step between the packets it does get, so the
      // slot the missing chunk leaves behind already becomes silence. An
      // explicit gap here would double-count it.
      ++missing_chunks;
      continue;
    }

    if (!have_first_decoded) {
      first_decoded = rtpp_header_from_fidx(entry);
      have_first_decoded = true;
    }

    layanalyzer::rtp::RtpRenderPacket packet;
    packet.frame_number = entry.frame;
    packet.arrival_rel_sec = entry.arrival_rel;
    packet.ext_ts = entry.ext_ts;
    // `pt` and `marker` are never read by `render_rtp_audio`, and `.fidx` holds
    // neither, so both stay at their neutral values rather than being made up.
    packet.pt = 0;
    packet.marker = false;
    // `.fidx` carries no RTP sequence number. The renderer uses `ext_seq` for
    // two things only -- `packet.ext_seq != last_sequence + 1` raises an
    // `outOfOrder` event, and `last_sequence_w < last_sequence` gates whether
    // the packet's samples are written at all -- so a plain count in `.fidx`
    // order is the one assignment that invents nothing: any other value would
    // fabricate events the capture never contained.
    //
    // It starts at 1, not at 0, because the sample write gate starts from
    // `last_sequence_w = 0`: a first packet with `ext_seq == 0` fails `0 < 0`,
    // and its whole 20 ms would be dropped without a word. The discontinuity
    // test is unaffected -- `last_sequence` is primed with `ext_seq - 1` for the
    // first packet -- so the counter still never raises an `outOfOrder` event.
    packet.ext_seq = static_cast<uint32_t>(packets.size()) + 1u;
    packet.samples = std::move(chunks[chunk_index].samples);  // already mono
    packet.channels = 1;
    packet.sample_rate = request.sample_rate;
    // Every codec on this path has identical clock and sample rates (AMR 8 kHz,
    // AMR-WB 16 kHz, Opus 48 kHz), so the request carries no separate field and
    // the two are the same number.
    packet.timestamp_rate = request.sample_rate;
    packets.push_back(std::move(packet));
  }

  if (packets.empty()) {
    remove_request_dir(output_directory);
    root["error"] = "No decoded PCM chunks were found for this stream.";
    return new_java_string(env, root.dump());
  }

  std::vector<layanalyzer::rtp::RtpRenderGap> lost_gaps;
  lost_gaps.reserve(static_cast<size_t>(lost_entries));
  for (size_t index = 0; index < entries.size(); ++index) {
    const layanalyzer::rtp::FidxEntry &entry = entries[index];
    if ((entry.flags & layanalyzer::rtp::kFidxFlagLost) == 0) {
      continue;
    }
    // Deliberate departure from the card, which puts this gap on the
    // capture-relative clock (`arrivalRel * 1000`). Every other entry of the
    // same `gaps` array -- the renderer's own silence and late gaps -- is on the
    // renderer's clock, and the UI draws them all on one timeline, so a capture
    // that does not begin at the renderer's origin would show two clocks side by
    // side. `decodeRtpAudio` computes its own extra gaps (CN, DTMF) against the
    // first decoded packet for exactly this reason, and this does the same.
    const uint32_t at_ms = estimate_record_at_ms(
        rtpp_header_from_fidx(entry), first_decoded, request.timing,
        request.sample_rate);
    lost_gaps.push_back({at_ms,
                         pcm_lost_gap_duration_ms(entries, index,
                                                  request.sample_rate),
                         "lost", entry.frame, false});
  }

  layanalyzer::rtp::RtpRenderOptions render_options;
  render_options.timing = request.timing;
  render_options.jitter_buffer_ms = request.jitter_ms;
  layanalyzer::rtp::RtpRenderResult rendered =
      layanalyzer::rtp::render_rtp_audio(packets, render_options);
  if (!rendered.error.empty()) {
    remove_request_dir(output_directory);
    root["error"] = rendered.error;
    return new_java_string(env, root.dump());
  }
  if (rendered.samples.empty() || rendered.sample_rate == 0) {
    remove_request_dir(output_directory);
    root["error"] = "RTP rendering produced no audio.";
    return new_java_string(env, root.dump());
  }

  // Merge the two gap sources and re-sort by time, the way `decodeRtpAudio`
  // merges its own CN gaps into the renderer's.
  rendered.gaps.insert(rendered.gaps.end(), lost_gaps.begin(),
                       lost_gaps.end());
  std::stable_sort(
      rendered.gaps.begin(), rendered.gaps.end(),
      [](const layanalyzer::rtp::RtpRenderGap &left,
         const layanalyzer::rtp::RtpRenderGap &right) {
        return left.at_ms < right.at_ms;
      });

  // `lost` and `truncatedPackets` come from the scan snapshot when it is
  // available, exactly as `decodeRtpAudio` reads them, so the two routes report
  // the same capture-level numbers for the same stream. The `.fidx` lost count
  // is the fallback.
  std::shared_ptr<const layanalyzer::rtp::RtpScanSnapshot> scan_snapshot;
  {
    std::lock_guard<std::mutex> lk(session->rtp_mutex);
    scan_snapshot = session->rtp_last_scan;
  }
  int64_t lost = static_cast<int64_t>(lost_entries);
  uint64_t truncated_packets = 0;
  const layanalyzer::rtp::RtpCollectedStream *scan_stream =
      find_scan_stream(scan_snapshot, request.stream_id);
  if (scan_stream) {
    lost = scan_stream->stats.lost;
    truncated_packets = scan_stream->stats.truncated;
  }

  RtpDecodedAudioItemMetadata metadata;
  metadata.stream_id = request.stream_id;
  metadata.codec = context.media.codec;
  metadata.first_abs_epoch_us = context.media.first_abs_epoch_us;
  metadata.start_rel_sec = entries.front().arrival_rel;
  metadata.channels = 1;  // the downmix above, or the request's own mono
  metadata.decoded_packets = packets.size();
  metadata.lost = lost;
  metadata.truncated_packets = truncated_packets;
  // No RTP payload is extracted on this path, so nothing can be empty.
  metadata.zero_payload_packets = 0;

  std::error_code directory_error;
  std::filesystem::create_directories(
      std::filesystem::path(output_directory), directory_error);
  if (directory_error) {
    remove_request_dir(output_directory);
    root["error"] = "Unable to create RTP output directory.";
    return new_java_string(env, root.dump());
  }

  RtpDecodedAudioItem audio_item;
  std::string item_error;
  if (!build_rtp_decoded_audio_item(rendered, metadata, output_directory,
                                    audio_item, item_error)) {
    remove_request_dir(output_directory);
    root["error"] = item_error;
    return new_java_string(env, root.dump());
  }

  // The item's key set, spelled out field by field. `dtmf` is the one key
  // `decodeRtpAudio` adds that this endpoint has no records for.
  root["streamId"] = std::move(audio_item.item["streamId"]);
  root["codec"] = std::move(audio_item.item["codec"]);
  root["sampleRate"] = std::move(audio_item.item["sampleRate"]);
  root["channels"] = std::move(audio_item.item["channels"]);
  root["wavPath"] = std::move(audio_item.item["wavPath"]);
  root["peaksPath"] = std::move(audio_item.item["peaksPath"]);
  root["mapPath"] = std::move(audio_item.item["mapPath"]);
  root["durationMs"] = std::move(audio_item.item["durationMs"]);
  root["startRel"] = std::move(audio_item.item["startRel"]);
  root["startAbsEpochMs"] = std::move(audio_item.item["startAbsEpochMs"]);
  root["gaps"] = std::move(audio_item.item["gaps"]);
  root["events"] = std::move(audio_item.item["events"]);
  root["stats"] = std::move(audio_item.item["stats"]);

  LOGI(
      "renderRtpAudioFromPcm: stream=%s codec=%s packets=%zu chunks=%zu "
      "lost=%llu missing=%llu take=%lldms",
      request.stream_id.c_str(), metadata.codec.c_str(), packets.size(),
      chunks.size(), static_cast<unsigned long long>(lost_entries),
      static_cast<unsigned long long>(missing_chunks),
      static_cast<long long>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - render_start)
              .count()));
  return new_java_string(env, root.dump());
}

// ---------------------------------------------------------------------------
// RTP5-NAT-05: `exportRtpVideo`.
//
// Contract (task_rtp_m5_video.md section 3.1, frozen; m5.md card RTP5-NAT-05):
//
//   external fun exportRtpVideo(sessionPtr: Long, requestJson: String,
//                               outDir: String,
//                               progress: RtpProgressCallback?): String
//   request: {"scanGeneration":7,"streamId":"s4","codec":"H264|H265",
//             "paramSets":{"sps":["base64"],"pps":["base64"],"vps":[]},
//             "startAtKeyframe":true,"dropCorrupt":false,
//             "tsRate":90000,"donDiff":0,"paramSetsPresentInStream":false}
//   result:  {"schemaVersion":1,"error":"","cancelled":false,
//             "esPath":".../s4.h264","indexPath":".../s4.vidx","codec":"H264",
//             "width":1280,"height":720,"profile":"High","level":"3.1",
//             "csd":{"sps":"base64","pps":"base64","vps":null},
//             "frames":900,"keyframes":30,"corruptFrames":2,
//             "firstKeyframeIndex":0,"durationMs":30000,"fpsEstimate":29.97,
//             "unsupportedNalCounts":{"STAP-B":0,"MTAP16":0,"FU-B":0,"PACI":0}}
//
// It is the one entry point of M5: one video stream is extracted out of the
// capture with M2's machinery, de-packetized by RTP5-NAT-01 / NAT-02, assembled
// into access units by NAT-03, sized from its SPS by NAT-04, and written out as
// an Annex-B elementary stream plus the `.vidx` index KT-01 muxes from. The
// card's implementation order is kept: 1 staleScan, 2 payload extraction of this
// one stream only, 3 de-packetize in sequence order, 4 assemble + read the SPS,
// 5 reject a stream with no parameter sets at all, 6 write the two files,
// 7 remove the output directory on cancel or failure.
//
// Decisions the card left open, resolved here:
//
// 1. `paramSets`' Base64 is decoded by `base64_decode` below, the inverse of the
//    encoder this file already uses for Opus CSD. An entry that is not decodable
//    or decodes to nothing fails the whole request: the caller is KT-00, whose
//    decoder turns a bad value into an empty list (its card says so), so a
//    malformed entry reaching here is a caller bug and silently dropping it
//    would export a stream the caller thinks is parameter-set-complete.
// 2. "Only that stream's video payload type is de-packetized" is
//    `codec_frames_is_primary_record` verbatim -- the same filter `decodeRtpAudio`
//    and `extractRtpCodecFrames` use. It drops CN (PT 13/19), the stream's
//    telephone-event PT and every PT that is not the stream's primary one, which
//    is exactly the card's "CN / telephone-event / any other PT is ignored".
// 3. Sequence order. The `.rtpp` is written in arrival order (README C15) and
//    both de-packetizers need sequence order, so the selected records are
//    re-ordered by `order_video_records_by_sequence` below, which reproduces
//    `RtppIndex.cpp:build_sequence_index`'s rule (one record per extended
//    sequence number, the latest arrival of a duplicate winning, sorted by the
//    sequence unwrapped around the stream's first record) in memory instead of
//    calling it: the `.rtpp` index stores the record number in a *16-bit* field,
//    so for a stream longer than 65535 packets the file-based index points at the
//    wrong records -- and streams of exactly that length are what this endpoint
//    exists for. The file-based index is not touched; the `.rtpp` itself is read
//    in full through `read_rtpp_file`, so no seek is needed either.
// 4. `sequence_gap` is `ext_seq != previous ext_seq + 1` over the *fed* order,
//    and the first fed packet has no predecessor, so it is never a gap.
// 5. `tsRate` is the builder's `timestamp_rate`. It is taken from the request
//    when the caller sends one, and otherwise from
//    `RtpStreamMediaInfo::video_timestamp_rate` when that is non-zero (NAT-03
//    decision 2's "NAT-05 fills it from the stream"), falling back to the
//    contract's 90000. For every codec this endpoint accepts the two are 90000
//    anyway; the order only matters for a request that says something else. A
//    request value of 0 is passed through -- the builder replaces it with 90000
//    rather than dividing by zero (NAT-03 decision 2).
// 6. `donDiff` is the stream's `sprop-max-don-diff`, and `donl_present` for
//    `H265Depack` is `donDiff > 0` -- the constructor argument, not an
//    `onPacket` one (H265Depack header decision 1). The field is parsed but only
//    H.265 reads it.
// 7. The SPS is read from the NAL unit the de-packetizer handed up, not by
//    splitting the Annex-B bytes back out of the ES. Those are the same bytes:
//    NAT-03 writes every NAL behind a start code and nothing else, and there are
//    exactly two ways a parameter set reaches the ES -- in band, or injected from
//    the request when the stream has none (NAT-03 card rule 4) -- so "the first
//    access unit carrying parameter sets" holds either the stream's own SPS or
//    the caller's, and this picks the same one without a second parser. The
//    record's 0x04 flag is what the "no parameter sets" rule below is checked
//    against.
// 8. A stream with no parameter sets: the request's `paramSets` empty *and*
//    nothing in band and the caller not claiming otherwise -> the card's
//    `error="缺少参数集（SDP 与带内均未找到）"` and no file is written (the output
//    directory is removed, like every other failure).
// 9. `paramSetsPresentInStream` is the caller's assertion about the stream
//    (KT-00's). It is honoured in one direction only: it can keep the error
//    above from firing, it can never cause it. A caller that says "yes" for a
//    stream whose sets this endpoint never saw (they can be dropped by
//    `startAtKeyframe` when they sit in an access unit of their own before the
//    first IDR) still gets its stream exported, with `width` 0 and
//    `widthSource` "unknown" -- which is the caller's cue, exactly as the card
//    describes it.
// 10. `csd` is what the written ES actually begins with, base64: the stream's
//     own set when it has one, otherwise the request's (which is then the set
//     NAT-03 injected into record 0). A kind the codec or the stream does not
//     have is JSON `null` -- H.264 never has a VPS. This is deliberately *not* an
//     echo of the request: echoing a set that was not injected would describe
//     bytes the file does not contain.
// 11. `width`/`height`/`profile`/`level` come from the SPS when it parses. When
//     there is no SPS to parse, or it does not parse, all four keep their
//     neutral values, `error` stays empty, and `"widthSource":"unknown"` is added
//     (the key is absent when the size is known, which is what the card asks
//     for); the parser's own reason (`truncated:<element>`, `notSps`, ...) is
//     logged, never guessed at. Kotlin decides whether a sizeless export is an
//     error.
// 12. All the counts -- `frames`, `keyframes`, `corruptFrames` and
//     `firstKeyframeIndex` -- are over the records written to the `.vidx`, which
//     is the file the caller iterates. That set includes the injected
//     parameter-set pseudo access unit when there is one (record 0, flags 0x04),
//     because KT-01 muxes from those records. `firstKeyframeIndex` is -1 when the
//     written records contain no keyframe -- which can only happen with
//     `startAtKeyframe` off, since with it on a stream without one is the
//     builder's `noKeyframe` error -- rather than 0, which would claim the first
//     record is a keyframe.
// 13. `durationMs` is the PTS span of the written records, `max - min`, in whole
//     milliseconds, and `fpsEstimate` is `frames / (durationMs / 1000)` rounded to
//     two decimals, 0.0 when the span is zero (a one-access-unit export divides
//     by it). The last access unit's own display duration is not counted; the
//     container's duration is KT-01's to report, and one frame of difference is
//     within QA-02's tolerance.
// 14. `unsupportedNalCounts` always carries the four keys section 3.1 fixes, so
//     the Kotlin parser sees a stable shape, plus one key per *observed* NAL unit
//     type that has no key among them -- named by its RFC/standard name
//     (`MTAP24`, `reserved`, `AP(DONL)`, ...) and only when it is non-zero. The
//     depacketizers report one type per packet rather than a histogram, so the
//     count is per packet, not per NAL unit: a STAP-A carrying two NALs of an
//     unsupported type is one packet.
// 15. Failure and cancel remove the caller's output directory (the card's rule
//     7), through `ScopedPathRemoval` armed right after the directory is created
//     and released on the success path -- the same "the request directory only
//     ever holds files this call produced" assumption `extractRtpCodecFrames`
//     makes. A failure before the directory exists (bad request, stale scan, no
//     capture) touches nothing.
// 16. The endpoint refuses a request whose `codec` does not name the same codec
//     the stream was scanned as, and one for an SRTP or unmapped stream: feeding
//     H.265 payloads to `H264Depack` (or ciphertext to either) would write a
//     plausible-looking but wrong `.h264`, and "不要生成坏文件" is a M5 gate item.
//     The first is a guard the card does not name, because the card's caller
//     always passes the stream's own codec; the second reuses the M2/M4
//     rejection (`srtp`, `needsMapping`).
// ---------------------------------------------------------------------------

namespace {

// `codec` is one of the two canonical ids the request contract allows (README
// section 4.3: H264 / H265). PS is RTP5-NAT-06's, optional and not implemented
// in this tree, so a request for it is rejected by the parser rather than
// silently de-packetized as H.264.
enum class RtpVideoCodecKind { H264, H265 };

struct RtpVideoExportRequest {
  uint64_t scan_generation = 0;
  std::string stream_id;
  RtpVideoCodecKind codec = RtpVideoCodecKind::H264;
  std::vector<std::vector<uint8_t>> sps, pps, vps;
  bool start_at_keyframe = true;
  bool drop_corrupt = false;
  // `tsRate`: optional, and the 90 kHz the RTP video clock always is. The
  // "present" flag keeps an explicit value distinguishable from the default, so
  // the stream's own rate can stand in when the caller says nothing (decision 5).
  bool has_ts_rate = false;
  uint32_t ts_rate = kRtpVideoTimestampRate;
  // `donDiff`: the stream's `sprop-max-don-diff` (KT-00 reads it out of the SDP
  // fmtp); > 0 means the stream orders its AP packets with a DONL field, which
  // RTP5-NAT-02 refuses whole. Optional, absent means 0.
  int32_t don_diff = 0;
  // `paramSetsPresentInStream`: KT-00's assertion that the stream carries its
  // parameter sets in band. Absent means false.
  bool param_sets_present_in_stream = false;
};

// Standard base64 with padding (RFC 4648 section 4), the alphabet
// `android.util.Base64.DEFAULT` writes, i.e. the inverse of the `base64_encode`
// above. Whitespace is skipped so a hand-written request may wrap a long value;
// every other octet outside the alphabet, a length that is not a multiple of
// four, and padding anywhere but the end of the string are rejected. Fails
// closed: a parameter set is about to become a NAL unit in the exported stream.
int base64_value(char character) {
  if (character >= 'A' && character <= 'Z') return character - 'A';
  if (character >= 'a' && character <= 'z') return character - 'a' + 26;
  if (character >= '0' && character <= '9') return character - '0' + 52;
  if (character == '+') return 62;
  if (character == '/') return 63;
  return -1;
}

bool base64_decode(const std::string &text, std::vector<uint8_t> &bytes) {
  bytes.clear();
  std::string filtered;
  filtered.reserve(text.size());
  for (char character : text) {
    if (character == ' ' || character == '\t' || character == '\r' ||
        character == '\n') {
      continue;
    }
    filtered.push_back(character);
  }
  if (filtered.empty() || filtered.size() % 4u != 0u) {
    return false;
  }

  bytes.reserve(filtered.size() / 4u * 3u);
  for (size_t index = 0; index < filtered.size(); index += 4u) {
    const bool last_group = index + 4u == filtered.size();
    const int high = base64_value(filtered[index]);
    const int low = base64_value(filtered[index + 1u]);
    if (high < 0 || low < 0) {
      return false;
    }
    const bool pad_third = filtered[index + 2u] == '=';
    const bool pad_fourth = filtered[index + 3u] == '=';
    // Padding is only legal in the final group, and only as "xy==" or "xyz=".
    if ((pad_third || pad_fourth) && !last_group) {
      return false;
    }
    if (pad_third && !pad_fourth) {
      return false;
    }
    const int third = pad_third ? 0 : base64_value(filtered[index + 2u]);
    const int fourth = pad_fourth ? 0 : base64_value(filtered[index + 3u]);
    if (third < 0 || fourth < 0) {
      return false;
    }
    const uint32_t block = (static_cast<uint32_t>(high) << 18u) |
                           (static_cast<uint32_t>(low) << 12u) |
                           (static_cast<uint32_t>(third) << 6u) |
                           static_cast<uint32_t>(fourth);
    bytes.push_back(static_cast<uint8_t>((block >> 16u) & 0xffu));
    if (!pad_third) {
      bytes.push_back(static_cast<uint8_t>((block >> 8u) & 0xffu));
    }
    if (!pad_fourth) {
      bytes.push_back(static_cast<uint8_t>(block & 0xffu));
    }
  }
  return true;
}

// `paramSets` is the one request field that carries binary data. Every entry
// must be a non-empty base64 string; an absent or null kind, and an absent
// object, are the same thing as an empty list (the contract makes the whole
// field optional).
bool parse_video_param_sets(const json &sets, RtpVideoExportRequest &request,
                            std::string &error) {
  if (!sets.is_object()) {
    error = "paramSets must be an object with sps, pps and vps arrays.";
    return false;
  }
  struct Kind {
    const char *key;
    std::vector<std::vector<uint8_t>> *out;
  };
  const Kind kinds[3] = {{"sps", &request.sps},
                         {"pps", &request.pps},
                         {"vps", &request.vps}};
  for (const Kind &kind : kinds) {
    const auto array_it = sets.find(kind.key);
    if (array_it == sets.end() || array_it->is_null()) {
      continue;
    }
    if (!array_it->is_array()) {
      error = "paramSets entries must be arrays of base64 strings.";
      return false;
    }
    for (const json &entry : *array_it) {
      if (!entry.is_string()) {
        error = "paramSets entries must be base64 strings.";
        return false;
      }
      std::vector<uint8_t> bytes;
      if (!base64_decode(entry.get<std::string>(), bytes) || bytes.empty()) {
        error = "paramSets entries must be non-empty base64 strings.";
        return false;
      }
      kind.out->push_back(std::move(bytes));
    }
  }
  return true;
}

bool parse_rtp_video_export_request(const std::string &text,
                                    RtpVideoExportRequest &request,
                                    std::string &error) {
  const json parsed = json::parse(text, nullptr, false);
  if (parsed.is_discarded() || !parsed.is_object()) {
    error = "Invalid RTP video export request.";
    return false;
  }

  const auto generation_it = parsed.find("scanGeneration");
  if (generation_it == parsed.end() || !generation_it->is_number_integer()) {
    error = "scanGeneration is required and must be an integer.";
    return false;
  }
  if (generation_it->is_number_unsigned()) {
    request.scan_generation = generation_it->get<uint64_t>();
  } else {
    const int64_t generation = generation_it->get<int64_t>();
    if (generation < 0) {
      error = "scanGeneration must be a non-negative integer.";
      return false;
    }
    request.scan_generation = static_cast<uint64_t>(generation);
  }

  const auto stream_it = parsed.find("streamId");
  if (stream_it == parsed.end() || !stream_it->is_string() ||
      stream_it->get_ref<const std::string &>().empty()) {
    error = "streamId is required and must be a non-empty string.";
    return false;
  }
  request.stream_id = stream_it->get<std::string>();

  const auto codec_it = parsed.find("codec");
  if (codec_it == parsed.end() || !codec_it->is_string()) {
    error = "codec is required and must be H264 or H265.";
    return false;
  }
  const std::string codec = codec_it->get<std::string>();
  if (codec == "H264") {
    request.codec = RtpVideoCodecKind::H264;
  } else if (codec == "H265") {
    request.codec = RtpVideoCodecKind::H265;
  } else {
    error = "codec must be H264 or H265.";
    return false;
  }

  const auto keyframe_it = parsed.find("startAtKeyframe");
  if (keyframe_it != parsed.end() && !keyframe_it->is_null()) {
    if (!keyframe_it->is_boolean()) {
      error = "startAtKeyframe must be a boolean.";
      return false;
    }
    request.start_at_keyframe = keyframe_it->get<bool>();
  }

  const auto corrupt_it = parsed.find("dropCorrupt");
  if (corrupt_it != parsed.end() && !corrupt_it->is_null()) {
    if (!corrupt_it->is_boolean()) {
      error = "dropCorrupt must be a boolean.";
      return false;
    }
    request.drop_corrupt = corrupt_it->get<bool>();
  }

  const auto ts_rate_it = parsed.find("tsRate");
  if (ts_rate_it != parsed.end() && !ts_rate_it->is_null()) {
    if (!ts_rate_it->is_number_integer()) {
      error = "tsRate must be an integer.";
      return false;
    }
    if (ts_rate_it->is_number_unsigned()) {
      const uint64_t rate = ts_rate_it->get<uint64_t>();
      if (rate > std::numeric_limits<uint32_t>::max()) {
        error = "tsRate must be a non-negative 32-bit integer.";
        return false;
      }
      request.ts_rate = static_cast<uint32_t>(rate);
    } else {
      const int64_t rate = ts_rate_it->get<int64_t>();
      if (rate < 0 ||
          rate > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        error = "tsRate must be a non-negative 32-bit integer.";
        return false;
      }
      request.ts_rate = static_cast<uint32_t>(rate);
    }
    request.has_ts_rate = true;
  }

  const auto don_it = parsed.find("donDiff");
  if (don_it != parsed.end() && !don_it->is_null()) {
    if (!don_it->is_number_integer()) {
      error = "donDiff must be an integer.";
      return false;
    }
    int64_t diff = 0;
    if (don_it->is_number_unsigned()) {
      const uint64_t magnitude = don_it->get<uint64_t>();
      if (magnitude >
          static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
        error = "donDiff must be a non-negative 32-bit integer.";
        return false;
      }
      diff = static_cast<int64_t>(magnitude);
    } else {
      diff = don_it->get<int64_t>();
      if (diff < 0 || diff > std::numeric_limits<int32_t>::max()) {
        error = "donDiff must be a non-negative 32-bit integer.";
        return false;
      }
    }
    request.don_diff = static_cast<int32_t>(diff);
  }

  const auto in_stream_it = parsed.find("paramSetsPresentInStream");
  if (in_stream_it != parsed.end() && !in_stream_it->is_null()) {
    if (!in_stream_it->is_boolean()) {
      error = "paramSetsPresentInStream must be a boolean.";
      return false;
    }
    request.param_sets_present_in_stream = in_stream_it->get<bool>();
  }

  const auto sets_it = parsed.find("paramSets");
  if (sets_it != parsed.end() && !sets_it->is_null() &&
      !parse_video_param_sets(*sets_it, request, error)) {
    return false;
  }

  error.clear();
  return true;
}

// The stream's own parameter sets as the de-packetizer handed them up: the first
// NAL unit of each kind. Only the SPS is consumed (the width/height parse and
// `csd`); the other two are kept because `csd` describes the sets the written ES
// really contains.
struct RtpVideoInBandSets {
  std::vector<uint8_t> sps, pps, vps;
  bool has_sps = false;
  bool has_pps = false;
  bool has_vps = false;
};

// `build_sequence_index`'s unwrapping, copied with its constants (RtppIndex.cpp;
// the rule is "the sequence number closest to the anchor wins", which is what
// makes a 16-bit rollover in the middle of a stream monotonic).
int64_t unwrap_video_sequence(uint32_t sequence, uint32_t anchor) {
  constexpr int64_t kSequenceModulus = INT64_C(0x100000000);
  constexpr int64_t kSequenceHalf = INT64_C(0x80000000);
  int64_t value = static_cast<int64_t>(sequence);
  const int64_t delta = value - static_cast<int64_t>(anchor);
  if (delta > kSequenceHalf) {
    value -= kSequenceModulus;
  } else if (delta < -kSequenceHalf) {
    value += kSequenceModulus;
  }
  return value;
}

// The selected records in sequence order -- see decision 3 in the block above for
// why this is not `build_sequence_index` itself. The rule is that function's: at
// most one record per extended sequence number, the latest arrival of a duplicate
// wins, and the survivors sort by the sequence unwrapped around the stream's
// first record (the anchor is the *stream's* first record, not the first
// selected one, exactly as `build_sequence_index` anchors on `headers.front()`).
std::vector<size_t> order_video_records_by_sequence(
    const std::vector<layanalyzer::rtp::RtppFileRecord> &records,
    const std::vector<size_t> &selected) {
  std::vector<size_t> order;
  if (selected.empty() || records.empty()) {
    return order;
  }
  const uint32_t anchor = records.front().header.ext_seq;

  std::map<uint32_t, size_t> latest_by_sequence;
  for (size_t index : selected) {
    const layanalyzer::rtp::RtppFileRecord &record = records[index];
    const auto found = latest_by_sequence.find(record.header.ext_seq);
    if (found == latest_by_sequence.end() ||
        record.header.arrival_rel_sec >
            records[found->second].header.arrival_rel_sec) {
      latest_by_sequence[record.header.ext_seq] = index;
    }
  }

  order.reserve(latest_by_sequence.size());
  for (const auto &entry : latest_by_sequence) {
    order.push_back(entry.second);
  }
  std::sort(order.begin(), order.end(),
            [&records, anchor](size_t left, size_t right) {
              const int64_t left_key = unwrap_video_sequence(
                  records[left].header.ext_seq, anchor);
              const int64_t right_key = unwrap_video_sequence(
                  records[right].header.ext_seq, anchor);
              if (left_key != right_key) {
                return left_key < right_key;
              }
              return left < right;
            });
  return order;
}

// The names of the NAL unit types an unsupported `unsupported_type` count can
// carry. H.264 and H.265 number their types independently, so the name depends
// on the codec -- and only the four names task_rtp_m5_video.md section 3.1 fixes
// are shared: `STAP-B`, `MTAP16`, `FU-B` and `PACI`. Every type either
// de-packetizer can count has a name in the two switch statements; the numeric
// fallback is what keeps a count from ever being dropped in silence if one of
// them is ever extended.
std::string unsupported_nal_name(const std::string &codec_id,
                                 uint32_t nal_type) {
  if (codec_id == "H264") {
    switch (nal_type) {
      case 0:
        // H.264's nal_unit_type 0 is "unspecified" and has no packetization in
        // RFC 6184, so H264Depack counts it on the unsupported path with
        // `unsupported_type` still 0 (header note 3).
        return "unspecified";
      case 25:
        return "STAP-B";
      case 26:
        return "MTAP16";
      case 27:
        return "MTAP24";
      case 29:
        return "FU-B";
      case 30:
      case 31:
        // RFC 6184 section 5.4 leaves these two reserved; both are one count.
        return "reserved";
      default:
        break;
    }
  } else {
    switch (nal_type) {
      case 48:
        // Only the AP's DONL rejection counts type 48 (H265Depack header
        // decision 4); a well-formed AP never reaches the count.
        return "AP(DONL)";
      case 50:
        return "PACI";
      default:
        break;
    }
    if (nal_type >= 51u && nal_type <= 63u) {
      // RFC 7798 section 4.4's reserved range.
      return "reserved";
    }
  }
  return "type" + std::to_string(nal_type);
}

// Everything the JNI entry point serialises. The ES and the records are the
// builder's output; the rest are the numbers section 3.1 asks for.
struct RtpVideoExportResult {
  std::string error;
  bool cancelled = false;
  std::string codec_id;  // "H264" / "H265"
  std::vector<uint8_t> es;
  std::vector<layanalyzer::rtp::VideoAuRecord> records;
  uint32_t width = 0;
  uint32_t height = 0;
  std::string profile;
  std::string level;
  bool width_source_known = false;
  // The sets the written ES begins with (decision 10). Empty = absent = JSON null.
  std::vector<uint8_t> csd_sps, csd_pps, csd_vps;
  // NAL unit type -> number of *packets* whose payload carried that type as
  // unsupported (decision 14).
  std::map<uint32_t, uint64_t> unsupported_types;
  RtpVideoInBandSets in_band;
  // Diagnostics for the log only; not part of the contract.
  uint64_t depack_error_packets = 0;
  bool partial_fu_dropped = false;

  uint64_t frames = 0;
  uint64_t keyframes = 0;
  uint64_t corrupt_frames = 0;
  int64_t first_keyframe_index = -1;
  uint64_t duration_ms = 0;
  double fps_estimate = 0.0;
};

// One feed loop for both de-packetizers. H264Depack and H265Depack are
// isomorphic on purpose (H265Depack header note 1: same entry point, same output
// members, same error strings), so the endpoint's sequence-gap rule, its
// cancellation checks, its progress reporting, its unsupported-type accumulation
// and its record of the stream's own parameter sets are written once. The only
// codec-dependent step is which NAL header field carries the type, and whether a
// NAL is a VPS.
template <typename Depacketizer>
bool feed_video_packets(
    Depacketizer &depack, const std::string &codec_id,
    const std::vector<layanalyzer::rtp::RtppFileRecord> &records,
    const std::vector<size_t> &order,
    layanalyzer::rtp::VideoAccessUnitBuilder &builder,
    const std::function<bool(uint32_t, uint32_t)> &report_progress,
    uint64_t cancel_generation, RtpVideoExportResult &result) {
  const bool is_h265 = codec_id == "H265";
  const uint8_t sps_type = is_h265 ? 33u : 7u;
  const uint8_t pps_type = is_h265 ? 34u : 8u;
  const uint8_t vps_type = 32u;  // H.265 only; H.264 has no VPS

  bool have_previous = false;
  uint64_t previous_ext_seq = 0;
  const size_t total = order.size();

  for (size_t index = 0; index < order.size(); ++index) {
    if (long_operation_cancelled(cancel_generation)) {
      result.cancelled = true;
      return false;
    }
    // Second half of the progress bar, `run_codec_frames_extraction`'s shape:
    // the extraction reported 0-80, the packet loop reports 80-100.
    if (report_progress && ((index + 1) % 256u == 0u || index + 1 == total)) {
      const uint64_t scaled =
          total == 0 ? 20u : static_cast<uint64_t>(index + 1) * 20u / total;
      const uint32_t percent =
          static_cast<uint32_t>(80u + std::min<uint64_t>(20u, scaled));
      if (!report_progress(percent, 100)) {
        result.cancelled = true;
        return false;
      }
    }

    const layanalyzer::rtp::RtppFileRecord &record = records[order[index]];
    // Decision 4: the first packet fed has no predecessor.
    const bool sequence_gap =
        have_previous && record.header.ext_seq != previous_ext_seq + 1u;
    have_previous = true;
    previous_ext_seq = record.header.ext_seq;

    const auto depacked = depack.onPacket(record.payload.data(),
                                          record.payload.size(), sequence_gap);

    if (depacked.unsupported_type != 0u) {
      ++result.unsupported_types[depacked.unsupported_type];
    } else if (depacked.error == "unsupported") {
      // The one unsupported packet whose type field stays 0 (decision 14).
      ++result.unsupported_types[0];
    }
    if (!depacked.error.empty()) {
      ++result.depack_error_packets;
    }

    // The stream's own parameter sets, recorded here rather than read back out
    // of the ES later (decision 7). They are kept before the builder can drop
    // anything: whether the stream has them is a property of the stream, not of
    // what survives `startAtKeyframe`.
    for (const std::vector<uint8_t> &nal : depacked.nals) {
      if (nal.empty()) {
        continue;
      }
      const uint8_t type =
          is_h265 ? static_cast<uint8_t>((nal[0] >> 1) & 0x3Fu)
                  : static_cast<uint8_t>(nal[0] & 0x1Fu);
      if (type == sps_type) {
        if (!result.in_band.has_sps) {
          result.in_band.has_sps = true;
          result.in_band.sps = nal;
        }
      } else if (type == pps_type) {
        if (!result.in_band.has_pps) {
          result.in_band.has_pps = true;
          result.in_band.pps = nal;
        }
      } else if (is_h265 && type == vps_type) {
        if (!result.in_band.has_vps) {
          result.in_band.has_vps = true;
          result.in_band.vps = nal;
        }
      }
    }

    builder.onPacket(record.header.frame, record.header.ext_ts,
                     record.header.marker != 0u, depacked.nals,
                     depacked.corrupt, sequence_gap);
  }
  return true;
}

// The whole extraction, de-packetization and assembly. Fills `result` and
// returns false on a hard error (`result.error`) or on cancellation
// (`result.cancelled`); the caller owns the output directory either way.
bool run_video_export(
    WiresharkSession *session, const RtpCodecFramesContext &context,
    const RtpVideoExportRequest &request, const std::string &work_parent,
    const std::function<bool(uint32_t, uint32_t)> &report_progress,
    RtpVideoExportResult &result) {
  result.codec_id = request.codec == RtpVideoCodecKind::H264 ? "H264" : "H265";

  std::vector<int> frames;
  if (context.limit_to_display_filter) {
    frames = snapshot_visible_frames(session);
  } else {
    frames.reserve(session->frame_offsets.size());
    for (size_t index = 0; index < session->frame_offsets.size(); ++index) {
      frames.push_back(static_cast<int>(index));
    }
  }

  // The `.rtpp` (and its index) are means to an end, so they go into a private
  // hidden directory removed on every path out, success included.
  std::filesystem::path work_directory;
  std::string work_error;
  if (!create_unique_work_directory(std::filesystem::path(work_parent),
                                    request.stream_id, work_directory,
                                    work_error)) {
    result.error = work_error;
    return false;
  }
  ScopedPathRemoval work_cleanup(work_directory);

  layanalyzer::rtp::RtpExtractionRequest extraction_request;
  extraction_request.out_dir = work_directory.string();
  extraction_request.keys.push_back(context.key);
  extraction_request.stream_ids[context.key] = request.stream_id;

  const uint64_t cancel_generation = current_cancel_generation();
  layanalyzer::rtp::RtpExtractionResult extraction =
      layanalyzer::rtp::extract_rtp_payloads(
          session, frames, extraction_request,
          [&](uint32_t done, uint32_t total) {
            if (!report_progress) return true;
            uint32_t percent = 80;
            if (total != 0) {
              percent = static_cast<uint32_t>(std::min<uint64_t>(
                  80u, static_cast<uint64_t>(done) * 80u / total));
            }
            return report_progress(percent, 100);
          },
          cancel_generation);
  if (extraction.cancelled) {
    result.cancelled = true;
    return false;
  }
  if (!extraction.error.empty()) {
    result.error = extraction.error;
    return false;
  }

  const auto rtpp_it = extraction.rtpp_paths.find(request.stream_id);
  if (rtpp_it == extraction.rtpp_paths.end()) {
    result.error = "RTP payload output is missing.";
    return false;
  }

  layanalyzer::rtp::RtppReadResult records;
  std::string file_error;
  if (!layanalyzer::rtp::read_rtpp_file(rtpp_it->second, records, file_error)) {
    result.error = file_error;
    return false;
  }
  if (records.records.empty()) {
    result.error = "No RTP payload records were extracted.";
    return false;
  }

  // Decision 2: this stream's primary payload type only.
  std::vector<size_t> selected;
  selected.reserve(records.records.size());
  for (size_t index = 0; index < records.records.size(); ++index) {
    if (codec_frames_is_primary_record(context.media,
                                       records.records[index].header.pt)) {
      selected.push_back(index);
    }
  }
  if (selected.empty()) {
    result.error = "No RTP payload records were extracted.";
    return false;
  }

  // Decision 3.
  const std::vector<size_t> order =
      order_video_records_by_sequence(records.records, selected);
  if (order.empty()) {
    result.error = "No RTP payload records were extracted.";
    return false;
  }

  // Decision 5.
  uint32_t timestamp_rate = request.ts_rate;
  if (!request.has_ts_rate && context.media.video_timestamp_rate != 0u) {
    timestamp_rate = context.media.video_timestamp_rate;
  }

  layanalyzer::rtp::VideoAuBuilderOptions options;
  options.codec = request.codec == RtpVideoCodecKind::H264
                      ? layanalyzer::rtp::VideoCodec::H264
                      : layanalyzer::rtp::VideoCodec::H265;
  options.timestamp_rate = timestamp_rate;
  options.start_at_keyframe = request.start_at_keyframe;
  options.drop_corrupt = request.drop_corrupt;
  options.sps = request.sps;
  options.pps = request.pps;
  options.vps = request.vps;

  layanalyzer::rtp::VideoAccessUnitBuilder builder(options);
  bool fed = false;
  if (request.codec == RtpVideoCodecKind::H264) {
    layanalyzer::rtp::H264Depack depack;
    fed = feed_video_packets(depack, result.codec_id, records.records, order,
                             builder, report_progress, cancel_generation,
                             result);
    result.partial_fu_dropped = depack.hasPartialFu();
    depack.reset();
  } else {
    // Decision 6: the AP DONL property is the constructor argument.
    layanalyzer::rtp::H265Depack depack(request.don_diff > 0);
    fed = feed_video_packets(depack, result.codec_id, records.records, order,
                             builder, report_progress, cancel_generation,
                             result);
    result.partial_fu_dropped = depack.hasPartialFu();
    depack.reset();
  }
  if (!fed) {
    return false;  // cancelled
  }

  // Decision 8: no parameter sets anywhere. Checked before anything is written,
  // and before finish() can be misread as "the stream had nothing".
  const bool request_has_sets =
      !request.sps.empty() || !request.pps.empty() || !request.vps.empty();
  const bool stream_has_sets =
      result.in_band.has_sps || result.in_band.has_pps ||
      result.in_band.has_vps || request.param_sets_present_in_stream;
  if (!request_has_sets && !stream_has_sets) {
    result.error = "缺少参数集（SDP 与带内均未找到）";
    return false;
  }

  result.records = builder.finish(result.es);
  if (!builder.error().empty()) {
    result.error = builder.error();
    return false;
  }
  if (result.records.empty()) {
    result.error = "No video access units were extracted.";
    return false;
  }

  // Decision 7: the SPS the written ES carries, whether it came up in band or
  // was injected from the request.
  const std::vector<uint8_t> *sps = nullptr;
  if (result.in_band.has_sps) {
    sps = &result.in_band.sps;
  } else if (!request.sps.empty()) {
    sps = &request.sps.front();
  }
  if (sps != nullptr) {
    const layanalyzer::rtp::SpsInfo info =
        request.codec == RtpVideoCodecKind::H264
            ? layanalyzer::rtp::parse_h264_sps(*sps)
            : layanalyzer::rtp::parse_h265_sps(*sps);
    if (info.ok) {
      result.width = info.width;
      result.height = info.height;
      result.profile = info.profile;
      result.level = info.level;
      result.width_source_known = true;
    } else {
      // Decision 11: never guess a size, and say why in the log.
      LOGW("exportRtpVideo: SPS parse failed: stream=%s codec=%s reason=%s",
           request.stream_id.c_str(), result.codec_id.c_str(),
           info.error.c_str());
    }
  }

  // Decision 10: `csd` describes the sets the ES begins with.
  if (result.in_band.has_sps) {
    result.csd_sps = result.in_band.sps;
  } else if (!request.sps.empty()) {
    result.csd_sps = request.sps.front();
  }
  if (result.in_band.has_pps) {
    result.csd_pps = result.in_band.pps;
  } else if (!request.pps.empty()) {
    result.csd_pps = request.pps.front();
  }
  if (result.in_band.has_vps) {
    result.csd_vps = result.in_band.vps;
  } else if (request.codec == RtpVideoCodecKind::H265 && !request.vps.empty()) {
    // The builder never injects a VPS into an H.264 stream (NAT-03's
    // `build_injection`), so the request's VPS is only in the ES for H.265.
    result.csd_vps = request.vps.front();
  }

  // Decisions 12 and 13: every number is over the records written to the `.vidx`.
  result.frames = result.records.size();
  uint64_t min_pts = result.records.front().pts_us;
  uint64_t max_pts = min_pts;
  for (size_t index = 0; index < result.records.size(); ++index) {
    const layanalyzer::rtp::VideoAuRecord &record = result.records[index];
    if ((record.flags & layanalyzer::rtp::kVideoAuFlagKey) != 0) {
      ++result.keyframes;
      if (result.first_keyframe_index < 0) {
        result.first_keyframe_index = static_cast<int64_t>(index);
      }
    }
    if ((record.flags & layanalyzer::rtp::kVideoAuFlagCorrupt) != 0) {
      ++result.corrupt_frames;
    }
    min_pts = std::min(min_pts, record.pts_us);
    max_pts = std::max(max_pts, record.pts_us);
  }
  result.duration_ms = (max_pts - min_pts) / 1000u;
  if (result.duration_ms != 0u) {
    const double seconds = static_cast<double>(result.duration_ms) / 1000.0;
    result.fps_estimate =
        static_cast<double>(std::llround(
            static_cast<double>(result.frames) / seconds * 100.0)) /
        100.0;
  }

  return true;
}

}  // namespace

// The endpoint itself. `sessionPtr` is the M1 handle, `outDir` is the caller's
// per-request directory, and `progress` is the same `RtpProgressCallback` the
// other long RTP endpoints take: returning false cancels, which removes the
// output directory and answers `cancelled: true`.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_exportRtpVideo(
    JNIEnv *env, jobject /* this */, jlong sessionPtr, jstring requestJson,
    jstring outDir, jobject progress) {
  // Every key of section 3.1's result is pre-populated with its neutral value, so
  // the shape the Kotlin parser sees does not depend on how far the call got.
  json root = {{"schemaVersion", 1},
               {"error", ""},
               {"cancelled", false},
               {"esPath", ""},
               {"indexPath", ""},
               {"codec", ""},
               {"width", 0},
               {"height", 0},
               {"profile", ""},
               {"level", ""},
               {"csd", {{"sps", nullptr}, {"pps", nullptr}, {"vps", nullptr}}},
               {"frames", 0},
               {"keyframes", 0},
               {"corruptFrames", 0},
               {"firstKeyframeIndex", -1},
               {"durationMs", 0},
               {"fpsEstimate", 0.0},
               {"unsupportedNalCounts",
                {{"STAP-B", 0}, {"MTAP16", 0}, {"FU-B", 0}, {"PACI", 0}}}};
  const auto export_start = std::chrono::steady_clock::now();

  auto session = acquire_session(sessionPtr);
  if (!session || !session->wth || !session->epan) {
    root["error"] = "No capture is open.";
    return new_java_string(env, root.dump());
  }
  if (!requestJson || !outDir) {
    root["error"] = "Missing video export request or output directory.";
    return new_java_string(env, root.dump());
  }

  std::string request_text;
  const char *request_chars = env->GetStringUTFChars(requestJson, nullptr);
  if (request_chars) {
    request_text.assign(request_chars);
    env->ReleaseStringUTFChars(requestJson, request_chars);
  }
  std::string output_directory;
  const char *out_dir_chars = env->GetStringUTFChars(outDir, nullptr);
  if (out_dir_chars) {
    output_directory.assign(out_dir_chars);
    env->ReleaseStringUTFChars(outDir, out_dir_chars);
  }
  if (output_directory.empty()) {
    root["error"] = "RTP output directory is empty.";
    return new_java_string(env, root.dump());
  }

  RtpVideoExportRequest request;
  std::string request_error;
  if (!parse_rtp_video_export_request(request_text, request, request_error)) {
    root["error"] = request_error;
    return new_java_string(env, root.dump());
  }

  // Step 1 of the card: the scan generation, the notFound case and the display
  // filter comparison are `resolve_scan_stream`'s. `resolve_codec_frames_stream`
  // is deliberately *not* used: it routes on codec and rejects everything that is
  // not AMR / AMR-WB / Opus as `nativeDecode`, and this endpoint's codecs are
  // neither.
  RtpCodecFramesContext context;
  std::string reject_reason;
  if (!resolve_scan_stream(session.get(), request.scan_generation,
                           request.stream_id, context, reject_reason)) {
    root["error"] = reject_reason;
    return new_java_string(env, root.dump());
  }
  // Decision 16: SRTP and needsMapping, the M2/M4 rejections.
  const char *unsupported = codec_frames_reject_reason(context.media);
  if (unsupported != nullptr) {
    root["error"] = unsupported;
    return new_java_string(env, root.dump());
  }
  if (context.media.primary_pt < 0) {
    root["error"] = "No primary RTP payload type was found.";
    return new_java_string(env, root.dump());
  }
  // Decision 16: the request's codec has to be the stream's, or the
  // de-packetizer would be fed another codec's bytes.
  const std::string &stream_codec = context.media.primary_codec_id;
  const std::string requested_codec =
      request.codec == RtpVideoCodecKind::H264 ? "H264" : "H265";
  if (!stream_codec.empty() && stream_codec != requested_codec) {
    root["error"] = "codec does not match the stream.";
    return new_java_string(env, root.dump());
  }

  std::error_code directory_error;
  std::filesystem::create_directories(
      std::filesystem::path(output_directory), directory_error);
  if (directory_error) {
    root["error"] = "Unable to create RTP output directory.";
    return new_java_string(env, root.dump());
  }
  // Decision 15: armed once the directory exists, so every failure and the
  // cancel path remove it and the success path releases it.
  ScopedPathRemoval output_cleanup(output_directory);

  jmethodID progress_method = nullptr;
  if (progress) {
    jclass progress_class = env->GetObjectClass(progress);
    progress_method = env->GetMethodID(progress_class, "onProgress", "(II)Z");
    env->DeleteLocalRef(progress_class);
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
    }
  }
  // Callers pass a percent in `done` (total is 100). The extraction loop asks
  // again every 256 frames, so the same percent is reported many times on a
  // long capture. Cross into Java only when the number moves; cancellation of
  // the walk itself is still `long_operation_cancelled`, checked every frame.
  uint32_t last_reported_percent = 0xffffffffu;
  auto report_progress = [&](uint32_t done, uint32_t total) {
    if (!progress || !progress_method) {
      return true;
    }
    if (done == last_reported_percent) {
      return true;
    }
    last_reported_percent = done;
    jboolean keep = env->CallBooleanMethod(
        progress, progress_method, static_cast<jint>(done),
        static_cast<jint>(total));
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      keep = JNI_FALSE;
    }
    return keep != JNI_FALSE;
  };

  RtpVideoExportResult exported;
  if (!run_video_export(session.get(), context, request, output_directory,
                        report_progress, exported)) {
    if (exported.cancelled) {
      root["cancelled"] = true;
      return new_java_string(env, root.dump());
    }
    root["error"] = exported.error.empty() ? "Unable to export the RTP video."
                                           : exported.error;
    return new_java_string(env, root.dump());
  }

  const std::string es_path = join_path(
      output_directory,
      request.stream_id +
          (request.codec == RtpVideoCodecKind::H264 ? ".h264" : ".h265"));
  const std::string index_path =
      join_path(output_directory, request.stream_id + ".vidx");

  std::string write_error;
  if (!write_binary_file(es_path, exported.es, write_error)) {
    // No half-written ES survives this: the removal guard is still armed.
    root["error"] = write_error;
    return new_java_string(env, root.dump());
  }
  std::vector<layanalyzer::rtp::VidxEntry> entries;
  entries.reserve(exported.records.size());
  for (const layanalyzer::rtp::VideoAuRecord &record : exported.records) {
    layanalyzer::rtp::VidxEntry entry;
    entry.offset = record.byte_offset;
    entry.length = record.byte_length;
    entry.pts_us = record.pts_us;
    entry.first_frame = record.first_frame;
    entry.flags = record.flags;
    entries.push_back(entry);
  }
  if (!layanalyzer::rtp::write_vidx_file(index_path, entries, write_error)) {
    root["error"] = write_error.empty() ? "Unable to write the video index."
                                        : write_error;
    return new_java_string(env, root.dump());
  }

  // Success: the files stay, the guard goes.
  output_cleanup.release();

  root["esPath"] = es_path;
  root["indexPath"] = index_path;
  root["codec"] = exported.codec_id;
  root["width"] = exported.width;
  root["height"] = exported.height;
  root["profile"] = exported.profile;
  root["level"] = exported.level;
  if (!exported.width_source_known) {
    // Decision 11: only ever added on the unknown path, as the card words it.
    root["widthSource"] = "unknown";
  }
  json csd = {{"sps", nullptr}, {"pps", nullptr}, {"vps", nullptr}};
  if (!exported.csd_sps.empty()) {
    csd["sps"] = base64_encode(exported.csd_sps);
  }
  if (!exported.csd_pps.empty()) {
    csd["pps"] = base64_encode(exported.csd_pps);
  }
  if (!exported.csd_vps.empty()) {
    csd["vps"] = base64_encode(exported.csd_vps);
  }
  root["csd"] = std::move(csd);
  root["frames"] = exported.frames;
  root["keyframes"] = exported.keyframes;
  root["corruptFrames"] = exported.corrupt_frames;
  root["firstKeyframeIndex"] = exported.first_keyframe_index;
  root["durationMs"] = exported.duration_ms;
  root["fpsEstimate"] = exported.fps_estimate;
  for (const auto &count : exported.unsupported_types) {
    // The four fixed keys are already there; this adds the types that have no
    // key among them, and only when they were observed (decision 14).
    root["unsupportedNalCounts"][unsupported_nal_name(exported.codec_id,
                                                      count.first)] =
        count.second;
  }

  uint64_t unsupported_packets = 0;
  for (const auto &count : exported.unsupported_types) {
    unsupported_packets += count.second;
  }
  LOGI(
      "exportRtpVideo: stream=%s codec=%s frames=%llu key=%llu corrupt=%llu "
      "unsupported=%llu depackErrors=%llu partialFu=%s size=%ux%u take=%lldms",
      request.stream_id.c_str(), exported.codec_id.c_str(),
      static_cast<unsigned long long>(exported.frames),
      static_cast<unsigned long long>(exported.keyframes),
      static_cast<unsigned long long>(exported.corrupt_frames),
      static_cast<unsigned long long>(unsupported_packets),
      static_cast<unsigned long long>(exported.depack_error_packets),
      exported.partial_fu_dropped ? "yes" : "no", exported.width,
      exported.height,
      static_cast<long long>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::steady_clock::now() - export_start)
              .count()));
  return new_java_string(env, root.dump());
}
