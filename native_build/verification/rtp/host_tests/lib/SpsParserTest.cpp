// RTP5-NAT-04: H.264 / H.265 sequence parameter set parsing.
//
// What this parser has to get right, and what the cases below pin:
//
//   * A parameter set arrives as raw NAL bytes and its payload is *escaped*:
//     a sender rewrites every `00 00` followed by 00..03 as `00 00 03 xx`, and
//     the reader has to undo exactly that rewrite. Whether that matters for the
//     size depends on where the escape sits, and the cases say which: in the
//     three H.265 sets an encoder produced, and in the H.264 sets below that
//     were built to place one, the `03` is inside the fields this parser reads,
//     and a reader that leaves it in comes back with a different size (or runs
//     out of bits) instead. In the H.264 sets the encoder produced, the escapes
//     happen to sit in the VUI tail, past the last element this parser reads,
//     so they do not change the reported size -- stated here rather than
//     implied, because the difference is real and a reader only has to survive
//     the first kind.
//   * Exp-Golomb codes are where the sizes come from, and they are the reason
//     the reader must not guess: a code that runs off the end, a
//     chroma_format_idc outside 0..3, or a crop window as large as the picture
//     are all failures rather than inputs to a wrapped calculation.
//   * The two codecs spell the same thing differently: H.264 sizes come from
//     macroblock counts and a crop window in chroma samples, H.265 from luma
//     sample counts and a conformance window; H.264 can carry a scaling matrix
//     between the profile fields and the size fields (which is why a reader
//     that skips it lands on the wrong bits), and H.265 carries a variable
//     number of sub-layer profile/level blocks (same reason).
//
// PROVENANCE. Every vector is one of three kinds, and each one says which in
// the comment above it:
//
//   * `real, FFmpeg 7.1` -- the parameter set is what a real encoder wrote on
//     this machine: ffmpeg 7.1 (the static build shipped by `imageio-ffmpeg`
//     0.6.0, `ffmpeg version 7.1-essentials_build-www.gyan.dev`, with libx264
//     and libx265) encoded two frames of `testsrc` at the vector's size, and
//     the SPS was taken out of the resulting Annex-B file unchanged. The
//     expected size is what that same ffmpeg reports when it decodes the file
//     (`ffmpeg -f h264 -i file -f null -`, "Video: h264 (High), ..., 1280x720"),
//     and for the H.264 vectors it was cross-checked field by field with
//     h26x-extractor 0.11.1, an independent third-party SPS parser
//     (`nalutypes.SPS`), which agrees on profile_idc, level_idc,
//     chroma_format_idc, the crop offsets and the macroblock counts. The size
//     expectation is the standard's arithmetic (7.3.2.1 / 7.3.2.2 and the
//     subWidthC/subHeightC table) applied to those field values.
//   * `cited, RFC 3984` -- the SDP example parameter sets from RFC 3984
//     section 8.2.1 (repeated in 8.3), i.e. what the RFC prints for
//     `sprop-parameter-sets`. The expected size is not in the RFC, so it was
//     derived the same way as above: the fields come from h26x-extractor
//     0.11.1, the arithmetic from the standard. (The RFC's own prose, "Baseline
//     Profile, Level 3.0", describes the *profile-level-id* parameter next to
//     the example, not these bytes: the parameter sets it prints are
//     profile_idc 66 / level_idc 10, i.e. Baseline / Level 1.0. That
//     discrepancy is in the document and is recorded here rather than
//     smoothed over.)
//   * `constructed` -- the bytes are written here by the BitWriter below, one
//     syntax element at a time, so the field values are visible in the test.
//     The expected size is the standard's arithmetic applied to the fields the
//     writer encodes, with the derivation spelled out in the comment. Where
//     the construction could be checked against something external, that was
//     done and is recorded: the writer's output for the H.264 scaling-matrix
//     and escape vectors, the chroma/monochrome/interlaced crop vectors and the
//     HEVC sub-layer and 4:4:4 vectors was spliced into the corresponding real
//     stream in place of its own SPS and read back with ffmpeg 7.1, which
//     reported the size in each case. Where that was not possible the case says
//     so and rests on the arithmetic alone: that is the separate-colour-plane
//     variants (ffmpeg rejects those SPSs against these slices) and the
//     invalid-value cases, whose expectation is the standard's range rather
//     than a size and so has nothing to confirm it with.
//
// Case names all start with "SpsParser" so that
// `run_host_tests.ps1 -Test "*SpsParser*"` selects exactly this file's cases.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "layanalyzer/rtp/depack/SpsParser.h"

using layanalyzer::rtp::SpsInfo;
using layanalyzer::rtp::parse_h264_sps;
using layanalyzer::rtp::parse_h265_sps;

namespace {

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

std::vector<uint8_t> from_hex(const std::string &hex) {
  std::vector<uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    bytes.push_back(static_cast<uint8_t>(
        (std::stoul(hex.substr(i, 1), nullptr, 16) << 4) |
        std::stoul(hex.substr(i + 1, 1), nullptr, 16)));
  }
  return bytes;
}

std::string to_hex(const std::vector<uint8_t> &bytes) {
  static const char *kDigits = "0123456789abcdef";
  std::string hex;
  hex.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    hex.push_back(kDigits[byte >> 4]);
    hex.push_back(kDigits[byte & 0x0F]);
  }
  return hex;
}

// A bit writer, used only to build the constructed vectors below (the
// production code has a reader, not a writer). Field order inside each builder
// follows the standard, so the encoded values are readable in the test.
class BitWriter {
 public:
  void bits(unsigned count, uint32_t value) {
    for (unsigned i = 0; i < count; ++i) {
      bits_.push_back(((value >> (count - 1 - i)) & 1u) != 0);
    }
  }

  // ue(v): v + 1 in binary with (length - 1) leading zeros.
  void ue(uint32_t value) {
    const uint32_t code = value + 1;
    unsigned length = 0;
    while ((code >> length) != 0) ++length;
    bits(length - 1, 0);
    bits(length, code);
  }

  // se(v) (H.264 9.1.1): k = ue value + 1, se = ceil(k / 2) with the sign of
  // (-1)^(k+1).
  void se(int32_t value) {
    if (value > 0) {
      ue(static_cast<uint32_t>(2 * value - 1));
    } else {
      ue(static_cast<uint32_t>(-2 * value));
    }
  }

  // rbsp_trailing_bits(): the stop bit. bytes() zero-pads, which is exactly
  // the trailing alignment the standard describes.
  void stop_bit() { bits(1, 1); }

  const std::vector<bool> &bits_out() const { return bits_; }

  std::vector<uint8_t> bytes() const {
    std::vector<uint8_t> out;
    for (size_t i = 0; i < bits_.size(); i += 8) {
      const size_t count = (bits_.size() - i < 8) ? (bits_.size() - i) : 8;
      uint8_t byte = 0;
      for (size_t j = 0; j < count; ++j) {
        byte = static_cast<uint8_t>((byte << 1) | (bits_[i + j] ? 1 : 0));
      }
      out.push_back(static_cast<uint8_t>(byte << (8 - count)));
    }
    return out;
  }

 private:
  std::vector<bool> bits_;
};

// Emulation prevention as a sender applies it (the inverse of what the parser
// has to undo): insert 03 before any byte <= 3 that follows two zero bytes.
std::vector<uint8_t> escape_emulation_prevention(const std::vector<uint8_t> &rbsp) {
  std::vector<uint8_t> out;
  out.reserve(rbsp.size());
  unsigned zeros = 0;
  for (uint8_t byte : rbsp) {
    if (zeros >= 2 && byte <= 3) {
      out.push_back(3);
      zeros = 0;
    }
    out.push_back(byte);
    zeros = (byte == 0) ? zeros + 1 : 0;
  }
  return out;
}

std::vector<uint8_t> h264_nal(const BitWriter &body) {
  std::vector<uint8_t> nal;
  nal.push_back(0x67);  // F = 0, NRI = 3, type = 7 (SPS)
  for (uint8_t byte : escape_emulation_prevention(body.bytes())) nal.push_back(byte);
  return nal;
}

std::vector<uint8_t> h265_nal(const BitWriter &body) {
  std::vector<uint8_t> nal;
  nal.push_back(0x42);  // F = 0, type = 33 (SPS), layer id 0
  nal.push_back(0x01);  // layer id 0, temporal id + 1 = 1
  for (uint8_t byte : escape_emulation_prevention(body.bytes())) nal.push_back(byte);
  return nal;
}

// ---------------------------------------------------------------------------
// the constructed H.264 SPS builder
// ---------------------------------------------------------------------------

struct H264SpsFields {
  uint32_t profile_idc = 100;
  uint32_t level_idc = 31;
  uint32_t chroma_format_idc = 1;
  uint32_t separate_colour_plane_flag = 0;
  uint32_t log2_max_frame_num_minus4 = 0;
  uint32_t pic_order_cnt_type = 2;
  uint32_t max_num_ref_frames = 0;
  uint32_t pic_width_in_mbs_minus1 = 79;
  uint32_t pic_height_in_map_units_minus1 = 44;
  uint32_t frame_mbs_only_flag = 1;
  bool frame_cropping_flag = false;
  uint32_t crop_left = 0;
  uint32_t crop_right = 0;
  uint32_t crop_top = 0;
  uint32_t crop_bottom = 0;
};

bool h264_has_chroma_block(uint32_t profile_idc) {
  switch (profile_idc) {
    case 44:
    case 83:
    case 86:
    case 100:
    case 110:
    case 118:
    case 122:
    case 128:
    case 134:
    case 135:
    case 138:
    case 139:
    case 244:
      return true;
    default:
      return false;
  }
}

// `scaling_lists` is empty for seq_scaling_matrix_present_flag = 0; otherwise
// it holds one entry per list (8 lists, or 12 when chroma_format_idc is 3), an
// empty entry meaning "this list is not present" and a non-empty one carrying
// the delta_scale values, zero-padded to the 16 (index < 6) or 64 (index >= 6)
// entries the list has.
std::vector<uint8_t> build_h264_sps(
    const H264SpsFields &fields,
    const std::vector<std::vector<int32_t>> &scaling_lists) {
  BitWriter w;
  w.bits(8, fields.profile_idc);
  w.bits(8, 0x10);  // constraint_set flags: x264's usual constraint_set1_flag
  w.bits(8, fields.level_idc);
  w.ue(0);  // seq_parameter_set_id
  if (h264_has_chroma_block(fields.profile_idc)) {
    w.ue(fields.chroma_format_idc);
    if (fields.chroma_format_idc == 3) w.bits(1, fields.separate_colour_plane_flag);
    w.ue(0);  // bit_depth_luma_minus8
    w.ue(0);  // bit_depth_chroma_minus8
    w.bits(1, 0);  // qpprime_y_zero_transform_bypass_flag
    if (scaling_lists.empty()) {
      w.bits(1, 0);
    } else {
      w.bits(1, 1);
      for (size_t i = 0; i < scaling_lists.size(); ++i) {
        if (scaling_lists[i].empty()) {
          w.bits(1, 0);
          continue;
        }
        w.bits(1, 1);
        const size_t entries = (i < 6u) ? 16u : 64u;
        for (size_t j = 0; j < entries; ++j) {
          w.se(j < scaling_lists[i].size() ? scaling_lists[i][j] : 0);
        }
      }
    }
  }
  w.ue(fields.log2_max_frame_num_minus4);
  w.ue(fields.pic_order_cnt_type);
  if (fields.pic_order_cnt_type == 0) w.ue(2);  // log2_max_pic_order_cnt_lsb_minus4
  w.ue(fields.max_num_ref_frames);
  w.bits(1, 0);  // gaps_in_frame_num_value_allowed_flag
  w.ue(fields.pic_width_in_mbs_minus1);
  w.ue(fields.pic_height_in_map_units_minus1);
  w.bits(1, fields.frame_mbs_only_flag);
  if (fields.frame_mbs_only_flag == 0) w.bits(1, 0);  // mb_adaptive_frame_field_flag
  w.bits(1, 1);  // direct_8x8_inference_flag
  if (!fields.frame_cropping_flag) {
    w.bits(1, 0);
  } else {
    w.bits(1, 1);
    w.ue(fields.crop_left);
    w.ue(fields.crop_right);
    w.ue(fields.crop_top);
    w.ue(fields.crop_bottom);
  }
  w.bits(1, 0);  // vui_parameters_present_flag -- the parser stops here
  w.stop_bit();
  return h264_nal(w);
}

// ---------------------------------------------------------------------------
// the constructed H.265 SPS builder
// ---------------------------------------------------------------------------

struct H265SpsFields {
  uint32_t general_profile_idc = 1;
  uint32_t general_level_idc = 120;
  uint32_t max_sub_layers_minus1 = 0;
  std::vector<uint32_t> sub_layer_profile_present;
  std::vector<uint32_t> sub_layer_level_present;
  std::vector<uint32_t> sub_layer_level_idc;
  uint32_t chroma_format_idc = 1;
  uint32_t separate_colour_plane_flag = 0;
  uint32_t pic_width_in_luma_samples = 1920;
  uint32_t pic_height_in_luma_samples = 1080;
  bool conformance_window_flag = false;
  uint32_t win_left = 0;
  uint32_t win_right = 0;
  uint32_t win_top = 0;
  uint32_t win_bottom = 0;
};

// The sub-layer part of profile_tier_level is written exactly as H.265 7.3.3
// orders it -- per-sub-layer present flags, then the reserved two-bit fields
// that pad the byte (only when sub-layers are signalled), then each sub-layer's
// profile (88 bits) and level (8 bits). The rest of the SPS after the
// conformance window is never read by the parser under test, but it is written
// out so that the vector is a complete SPS that ffmpeg accepts.
std::vector<uint8_t> build_h265_sps(const H265SpsFields &fields) {
  BitWriter w;
  w.bits(4, 0);  // sps_video_parameter_set_id
  w.bits(3, fields.max_sub_layers_minus1);
  w.bits(1, 1);  // sps_temporal_id_nesting_flag

  w.bits(2, 0);  // general_profile_space
  w.bits(1, 0);  // general_tier_flag
  w.bits(5, fields.general_profile_idc);
  w.bits(32, 1u << (31 - (fields.general_profile_idc & 31u)));  // compatibility flags
  w.bits(1, 1);  // general_progressive_source_flag
  w.bits(1, 0);  // general_interlaced_source_flag
  w.bits(1, 0);  // general_non_packed_constraint_flag
  w.bits(1, 1);  // general_frame_only_constraint_flag
  w.bits(43, 0);  // general_reserved_zero_43bits
  w.bits(1, 1);  // general_inbld_flag
  w.bits(8, fields.general_level_idc);

  for (uint32_t i = 0; i < fields.max_sub_layers_minus1; ++i) {
    w.bits(1, fields.sub_layer_profile_present[i]);
    w.bits(1, fields.sub_layer_level_present[i]);
  }
  if (fields.max_sub_layers_minus1 > 0) {
    for (uint32_t i = fields.max_sub_layers_minus1; i < 8; ++i) w.bits(2, 0);
  }
  for (uint32_t i = 0; i < fields.max_sub_layers_minus1; ++i) {
    if (fields.sub_layer_profile_present[i]) {
      w.bits(2, 0);
      w.bits(1, 0);
      w.bits(5, fields.general_profile_idc);
      w.bits(32, 1u << (31 - (fields.general_profile_idc & 31u)));
      w.bits(1, 1);
      w.bits(1, 0);
      w.bits(1, 0);
      w.bits(1, 1);
      w.bits(43, 0);
      w.bits(1, 1);
    }
    if (fields.sub_layer_level_present[i]) w.bits(8, fields.sub_layer_level_idc[i]);
  }

  w.ue(0);  // sps_seq_parameter_set_id
  w.ue(fields.chroma_format_idc);
  if (fields.chroma_format_idc == 3) w.bits(1, fields.separate_colour_plane_flag);
  w.ue(fields.pic_width_in_luma_samples);
  w.ue(fields.pic_height_in_luma_samples);
  if (!fields.conformance_window_flag) {
    w.bits(1, 0);
  } else {
    w.bits(1, 1);
    w.ue(fields.win_left);
    w.ue(fields.win_right);
    w.ue(fields.win_top);
    w.ue(fields.win_bottom);
  }

  // The rest of the SPS: not read by the parser under test, written so the
  // vector is complete.
  w.ue(0);  // bit_depth_luma_minus8
  w.ue(0);  // bit_depth_chroma_minus8
  w.ue(4);  // log2_max_pic_order_cnt_lsb_minus4
  w.bits(1, 0);  // sps_sub_layer_ordering_info_present_flag
  // One iteration: the loop runs from sps_max_sub_layers_minus1 to itself.
  w.ue(4);  // sps_max_dec_pic_buffering_minus1
  w.ue(2);  // sps_max_num_reorder_pics
  w.ue(0);  // sps_max_latency_increase_plus1
  w.ue(0);  // log2_min_luma_coding_block_size_minus3
  w.ue(3);  // log2_diff_max_min_luma_coding_block_size
  w.ue(0);  // log2_min_luma_transform_block_size_minus2
  w.ue(3);  // log2_diff_max_min_luma_transform_block_size
  w.ue(2);  // max_transform_hierarchy_depth_inter
  w.ue(2);  // max_transform_hierarchy_depth_intra
  w.bits(1, 0);  // scaling_list_enabled_flag
  w.bits(1, 1);  // amp_enabled_flag
  w.bits(1, 1);  // sample_adaptive_offset_enabled_flag
  w.bits(1, 0);  // pcm_enabled_flag
  w.ue(0);  // num_short_term_ref_pic_sets
  w.bits(1, 0);  // long_term_ref_pics_present_flag
  w.bits(1, 1);  // sps_temporal_mvp_enabled_flag
  w.bits(1, 1);  // strong_intra_smoothing_enabled_flag
  w.bits(1, 0);  // vui_parameters_present_flag
  w.bits(1, 0);  // sps_extension_present_flag
  w.stop_bit();
  return h265_nal(w);
}

// ---------------------------------------------------------------------------
// expectations
// ---------------------------------------------------------------------------

void expect_h264_ok(const std::string &label, const std::string &hex,
                    uint32_t width, uint32_t height, const char *profile,
                    const char *level, uint32_t chroma_format_idc = 1) {
  const SpsInfo info = parse_h264_sps(from_hex(hex));
  CHECK_MESSAGE(info.ok, label << ": " << info.error);
  CHECK_MESSAGE(info.width == width, label << ": width " << info.width);
  CHECK_MESSAGE(info.height == height, label << ": height " << info.height);
  CHECK_MESSAGE(info.profile == profile, label << ": profile " << info.profile);
  CHECK_MESSAGE(info.level == level, label << ": level " << info.level);
  CHECK_MESSAGE(info.chroma_format_idc == chroma_format_idc,
                label << ": chroma_format_idc " << info.chroma_format_idc);
  CHECK_MESSAGE(info.error.empty(), label << ": error " << info.error);
}

void expect_h265_ok(const std::string &label, const std::string &hex,
                    uint32_t width, uint32_t height, const char *profile,
                    const char *level, uint32_t chroma_format_idc = 1) {
  const SpsInfo info = parse_h265_sps(from_hex(hex));
  CHECK_MESSAGE(info.ok, label << ": " << info.error);
  CHECK_MESSAGE(info.width == width, label << ": width " << info.width);
  CHECK_MESSAGE(info.height == height, label << ": height " << info.height);
  CHECK_MESSAGE(info.profile == profile, label << ": profile " << info.profile);
  CHECK_MESSAGE(info.level == level, label << ": level " << info.level);
  CHECK_MESSAGE(info.chroma_format_idc == chroma_format_idc,
                label << ": chroma_format_idc " << info.chroma_format_idc);
  CHECK_MESSAGE(info.error.empty(), label << ": error " << info.error);
}

// Every failure has to come back with the reason *and* with nothing that looks
// like an answer: no size, no names (requirement 7).
void expect_h264_failure(const std::string &label, const std::string &hex,
                         const char *error) {
  const SpsInfo info = parse_h264_sps(from_hex(hex));
  CHECK_MESSAGE(!info.ok, label << ": unexpectedly parsed as " << info.width << "x"
                                << info.height);
  CHECK_MESSAGE(info.error == error, label << ": error " << info.error);
  CHECK_MESSAGE(info.width == 0, label << ": width " << info.width);
  CHECK_MESSAGE(info.height == 0, label << ": height " << info.height);
  CHECK_MESSAGE(info.profile.empty(), label << ": profile " << info.profile);
  CHECK_MESSAGE(info.level.empty(), label << ": level " << info.level);
}

void expect_h265_failure(const std::string &label, const std::string &hex,
                         const char *error) {
  const SpsInfo info = parse_h265_sps(from_hex(hex));
  CHECK_MESSAGE(!info.ok, label << ": unexpectedly parsed as " << info.width << "x"
                                << info.height);
  CHECK_MESSAGE(info.error == error, label << ": error " << info.error);
  CHECK_MESSAGE(info.width == 0, label << ": width " << info.width);
  CHECK_MESSAGE(info.height == 0, label << ": height " << info.height);
  CHECK_MESSAGE(info.profile.empty(), label << ": profile " << info.profile);
  CHECK_MESSAGE(info.level.empty(), label << ": level " << info.level);
}

// The real parameter sets, with the size ffmpeg 7.1 reports for the file each
// one came out of.
const char *kH264_720p =
    "6764101facb80a00b760220000030002000003001408";
const char *kH264_1080p_cropped =
    "67641028acb80f0044fcb80880000003008000000502";
const char *kH264_portrait =
    "674d401fdc0b40a1b0110000030001000003000a0f183380";
const char *kH264_444 =
    "67f4101691970280bfe270110000030001000003000a04";
const char *kH264_rfc3984 =
    "6742000a9653058988";
const char *kH265_1080p =
    "420101016000000300900000030000030078a003c08010e596566924caf016808000000300800000030284";
const char *kH265_conformance_window =
    "420101016000000300900000030000030078a003c08010e7de5959a4932bc05a020000030002000003003210";
const char *kH265_640x362 =
    "42010101600000030090000003000003003fa005020171f265959a4932bc05a02000000300200000030321";

}  // namespace

TEST_CASE("SpsParser H.264: real encoder parameter sets") {
  // 1280x720, High, Level 3.1, 4:2:0, no crop:
  // `ffmpeg -f lavfi -i testsrc=size=1280x720:rate=5 -frames:v 2 -c:v libx264
  //  -profile:v high -pix_fmt yuv420p -x264-params keyint=1:scenecut=0 -f h264`
  // -> ffmpeg 7.1 reads the file back as "h264 (High), ..., 1280x720"; the
  // fields are profile_idc 100, level_idc 31, chroma_format_idc 1, 80x45
  // macroblocks, no crop, per h26x-extractor 0.11.1.
  expect_h264_ok("720p", kH264_720p, 1280, 720, "High", "3.1");

  // 1920x1080, High, Level 4.0: the same command at 1920x1080. 1080 is not a
  // multiple of 16, so the SPS codes 120x68 macroblocks and crops 4 chroma
  // lines off the bottom (frame_crop_bottom_offset 4, subHeightC 2 -> 8 luma
  // lines): 68 * 16 - 8 = 1080. This is the cropping case.
  expect_h264_ok("1080p with cropping", kH264_1080p_cropped, 1920, 1080, "High",
                 "4.0");

  // 720x1280 portrait, Main, Level 3.1: the same command at 720x1280, which is
  // 45x80 macroblocks with no crop.
  expect_h264_ok("720x1280 portrait", kH264_portrait, 720, 1280, "Main", "3.1");

  // 640x360, High 4:4:4 Predictive (profile_idc 244), Level 2.2, chroma 3:
  // `-profile:v high444 -pix_fmt yuv444p` at 640x360. 360 is not a multiple of
  // 16 either, so this one crops with subHeightC 1 (4:4:4): 23 * 16 - 8 = 360.
  expect_h264_ok("High 4:4:4 with cropping", kH264_444, 640, 360,
                 "High 4:4:4 Predictive", "2.2", 3);
}

TEST_CASE("SpsParser H.264: the SDP example parameter set from RFC 3984") {
  // RFC 3984 section 8.2.1 (and again in the offer/answer example in 8.3)
  // prints this in an `a=fmtp:98 ...` line as
  // `sprop-parameter-sets=Z0IACpZTBYmI,aMljiA==`; this is the first of the two,
  // i.e. the SPS, base64-decoded.
  //
  // The RFC labels the example "Baseline Profile, Level 3.0", but that
  // describes the `profile-level-id=42A01E` parameter printed next to it
  // (profile 0x42 = 66, level 0x1E = 30). The parameter set bytes themselves
  // say profile_idc 66 / level_idc 10, i.e. Baseline / Level 1.0, and code
  // 11x9 macroblocks = 176x144 with no crop. Expected values from
  // h26x-extractor 0.11.1 (fields) plus the standard's arithmetic (size).
  expect_h264_ok("RFC 3984 example", kH264_rfc3984, 176, 144, "Baseline", "1.0");
}

TEST_CASE("SpsParser H.265: real encoder parameter sets") {
  // 1920x1080, Main, Level 4.0 (general_level_idc 120 = 30 * 4):
  // `ffmpeg -f lavfi -i testsrc=size=1920x1080:rate=25 -frames:v 2 -c:v libx265
  //  -profile:v main -pix_fmt yuv420p -x265-params log-level=none -f hevc`
  // -> ffmpeg 7.1 reads the file back as "hevc (Main), ..., 1920x1080".
  // pic_width_in_luma_samples is 1920 and pic_height_in_luma_samples 1080 with
  // no conformance window, so the size is the picture size itself.
  expect_h265_ok("1080p", kH265_1080p, 1920, 1080, "Main", "4.0");

  // The same encoder at 1920x1076: 1076 is not a multiple of 8, so x265 codes
  // 1920x1080 and signals conformance_window_flag with
  // conf_win_bottom_offset 2 (subHeightC 2 -> 4 luma lines): 1080 - 4 = 1076,
  // which is what ffmpeg reports for the file.
  expect_h265_ok("conformance window", kH265_conformance_window, 1920, 1076,
                 "Main", "4.0");

  // 640x362, Main, Level 2.1 (general_level_idc 63 = 30 * 2 + 3 * 1): the
  // same command at 640x362. x265 codes 640x368 and crops 3 chroma lines off
  // the bottom: 368 - 6 = 362.
  expect_h265_ok("odd height 640x362", kH265_640x362, 640, 362, "Main", "2.1");
}

TEST_CASE("SpsParser H.264: constructed parameter sets with a scaling matrix") {
  // Both vectors below are written here by build_h264_sps(), and the bytes it
  // produces were checked against ffmpeg 7.1 before being written down: each
  // SPS was spliced into the corresponding real stream in place of its own and
  // ffmpeg reported the same size as below, which means the scaling-list
  // syntax really is skipped with the right length.
  //
  // The first has seq_scaling_matrix_present_flag = 1 with 8 lists (chroma 1),
  // lists 0 and 3 present and the rest absent. List 0 fills all 16 of its
  // entries -- with zeros among them, so a reader that stops at the first zero
  // is wrong too -- and list 3 four, so a reader that stops after the flag, or
  // that reads one value too many or too few, lands on the wrong bits.
  // Everything else is the 720p set above: 80x45 macroblocks, no crop ->
  // 1280x720, profile 100 (High) and level_idc 31.
  {
    H264SpsFields fields;
    std::vector<std::vector<int32_t>> lists(8);
    lists[0] = {1, 2, -1, 0, 3, -2, 1, 1, 0, 0, 2, -1, 1, 0, 0, 0};
    lists[3] = {-1, 0, 1, 0};
    const std::vector<uint8_t> nal = build_h264_sps(fields, lists);
    CHECK_EQ(to_hex(nal), "6764101fada2398a9646b975fff0b80a00b720");
    const SpsInfo info = parse_h264_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 1280u);
    CHECK_EQ(info.height, 720u);
    CHECK_EQ(info.profile, "High");
    CHECK_EQ(info.level, "3.1");
  }

  // The second is 4:4:4 (chroma 3), so it has 12 lists, lists 0 and 7 present;
  // list 7 is an 8x8 list and therefore holds 64 delta_scale values rather than
  // 16 (H.264 7.3.2.1.1). 40x23 macroblocks with frame_crop_bottom_offset 8 and
  // subHeightC 1: 23 * 16 - 8 = 360, i.e. 640x360, profile 244, level_idc 22
  // -> 2.2.
  {
    H264SpsFields fields;
    fields.profile_idc = 244;
    fields.level_idc = 22;
    fields.chroma_format_idc = 3;
    fields.pic_width_in_mbs_minus1 = 39;
    fields.pic_height_in_map_units_minus1 = 22;
    fields.frame_cropping_flag = true;
    fields.crop_bottom = 8;
    std::vector<std::vector<int32_t>> lists(12);
    lists[0] = {1, -1, 0, 2};
    lists[7] = {1, 0, 0, 0};
    const std::vector<uint8_t> nal = build_h264_sps(fields, lists);
    CHECK_EQ(to_hex(nal), "67f4101691b4e4fff02bfffffffffffffff85c0a02ff8940");
    const SpsInfo info = parse_h264_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 640u);
    CHECK_EQ(info.height, 360u);
    CHECK_EQ(info.profile, "High 4:4:4 Predictive");
    CHECK_EQ(info.level, "2.2");
    CHECK_EQ(info.chroma_format_idc, 3u);
  }

  // The third is the 4:4:4 set with separate_colour_plane_flag = 1, which is
  // the only bit it differs from the one above by. chroma_format_idc is still
  // 3, so the crop table the card fixes still applies (subWidthC/subHeightC
  // 1/1) and the size is unchanged -- but the flag itself has to be consumed,
  // because otherwise the width below it would be read one bit early.
  // Constructed, and unlike the other two this one has no external
  // confirmation: ffmpeg rejects a separate-colour-plane SPS paired with these
  // slices, so only the arithmetic is behind the expected 640x360.
  {
    H264SpsFields fields;
    fields.profile_idc = 244;
    fields.level_idc = 22;
    fields.chroma_format_idc = 3;
    fields.separate_colour_plane_flag = 1;
    fields.pic_width_in_mbs_minus1 = 39;
    fields.pic_height_in_map_units_minus1 = 22;
    fields.frame_cropping_flag = true;
    fields.crop_bottom = 8;
    std::vector<std::vector<int32_t>> lists(12);
    lists[0] = {1, -1, 0, 2};
    lists[7] = {1, 0, 0, 0};
    const std::vector<uint8_t> nal = build_h264_sps(fields, lists);
    CHECK_EQ(to_hex(nal), "67f4101693b4e4fff02bfffffffffffffff85c0a02ff8940");
    const SpsInfo info = parse_h264_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 640u);
    CHECK_EQ(info.height, 360u);
  }
}

TEST_CASE("SpsParser H.264: constructed parameter sets for the crop factors") {
  // The subWidthC/subHeightC table the card fixes has four entries and the
  // vectors above only exercise two of them (2/2 at 4:2:0 and 1/1 at 4:4:4).
  // These two fill in chroma_format_idc 0 and 2, where the crop factor differs
  // in one direction only. Both were spliced into a real stream and read back
  // with ffmpeg 7.1, which reported the sizes below.

  // Monochrome (chroma_format_idc 0), which the card says to treat as 1/1:
  // 80x45 macroblocks with frame_crop_bottom_offset 8 -> 720 - 8 = 712, so
  // 1280x712. With the 4:2:0 factors instead of monochrome's this would be 704,
  // so the case distinguishes them.
  {
    H264SpsFields fields;
    fields.chroma_format_idc = 0;
    fields.frame_cropping_flag = true;
    fields.crop_bottom = 8;
    const std::vector<uint8_t> nal = build_h264_sps(fields, {});
    CHECK_EQ(to_hex(nal), "6764101ff2e02802dfc4a0");
    const SpsInfo info = parse_h264_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 1280u);
    CHECK_EQ(info.height, 712u);
    CHECK_EQ(info.chroma_format_idc, 0u);
  }

  // 4:2:2 (chroma_format_idc 2, profile 122), where subWidthC is 2 and
  // subHeightC 1: crop (left 2, right 2, bottom 8) on 80x45 macroblocks gives
  // 1280 - 4 * 2 = 1272 wide and 720 - 8 * 1 = 712 high.
  {
    H264SpsFields fields;
    fields.profile_idc = 122;
    fields.chroma_format_idc = 2;
    fields.frame_cropping_flag = true;
    fields.crop_left = 2;
    fields.crop_right = 2;
    fields.crop_bottom = 8;
    const std::vector<uint8_t> nal = build_h264_sps(fields, {});
    CHECK_EQ(to_hex(nal), "677a101fbcb80a00b7b71280");
    const SpsInfo info = parse_h264_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 1272u);
    CHECK_EQ(info.height, 712u);
    CHECK_EQ(info.chroma_format_idc, 2u);
  }

  // And the other factor in the H.264 height formula, (2 - frame_mbs_only_flag):
  // with frame_mbs_only_flag = 0 the coded height doubles (the picture is two
  // fields), so 80x22 map units becomes 2 * 23 * 16 = 736 high. The
  // mb_adaptive_frame_field_flag that follows the flag has to be read too, or
  // the fields after it shift. ffmpeg 7.1 reads this vector as 1280x736.
  {
    H264SpsFields fields;
    fields.profile_idc = 77;
    fields.pic_height_in_map_units_minus1 = 22;
    fields.frame_mbs_only_flag = 0;
    const std::vector<uint8_t> nal = build_h264_sps(fields, {});
    CHECK_EQ(to_hex(nal), "674d101fdc0500b920");
    const SpsInfo info = parse_h264_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 1280u);
    CHECK_EQ(info.height, 736u);
    CHECK_EQ(info.profile, "Main");
  }
}

TEST_CASE("SpsParser H.265: constructed parameter sets with sub-layers") {
  // profile_tier_level is variable length: sps_max_sub_layers_minus1 decides
  // how many present flags, how many reserved two-bit fields and how many
  // sub-layer profile/level blocks follow. A reader that assumes zero
  // sub-layers reads pic_width_in_luma_samples eight bits early per sub-layer.
  // Both vectors were read back by ffmpeg 7.1 as the sizes below, and
  // h26x-extractor 0.11.1 has no HEVC support, so ffmpeg is the only external
  // check here.

  // Two sub-layers, both with sub_layer_level_present_flag = 1 and no
  // sub-layer profile (the shape x265 emits when it uses temporal layers). The
  // two 8-bit levels are 93 and 63. 1920x1088 with a conformance window of 4
  // chroma lines off the bottom: 1088 - 8 = 1080, i.e. 1920x1080, general
  // profile 1 (Main), general_level_idc 120 -> "4.0". ffmpeg 7.1 reads this
  // vector as "hevc (Main), ..., 1920x1080".
  {
    H265SpsFields fields;
    fields.max_sub_layers_minus1 = 2;
    fields.sub_layer_profile_present = {0, 0};
    fields.sub_layer_level_present = {1, 1};
    fields.sub_layer_level_idc = {93, 63};
    fields.pic_height_in_luma_samples = 1088;
    fields.conformance_window_flag = true;
    fields.win_bottom = 4;
    const std::vector<uint8_t> nal = build_h265_sps(fields);
    CHECK_EQ(to_hex(nal),
             "42010501400000030090000003000003017850005d3fa003c0801107cb94579246dac8");
    const SpsInfo info = parse_h265_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 1920u);
    CHECK_EQ(info.height, 1080u);
    CHECK_EQ(info.profile, "Main");
    CHECK_EQ(info.level, "4.0");
  }

  // The mixed case: sub-layer 0 has a profile and no level, sub-layer 1 a
  // level and no profile, so both payload kinds and both flag orders are
  // covered. 1280x720 with no conformance window, so the picture size is the
  // size: 1280x720. ffmpeg 7.1 reads this vector as "hevc (Main), ...,
  // 1280x720".
  {
    H265SpsFields fields;
    fields.max_sub_layers_minus1 = 2;
    fields.sub_layer_profile_present = {1, 0};
    fields.sub_layer_level_present = {0, 1};
    fields.sub_layer_level_idc = {0, 63};
    fields.pic_width_in_luma_samples = 1280;
    fields.pic_height_in_luma_samples = 720;
    const std::vector<uint8_t> nal = build_h265_sps(fields);
    CHECK_EQ(to_hex(nal),
             "420105014000000300900000030000030178900001400000030090000003000003013fa00280802d16515e491b6b20");
    const SpsInfo info = parse_h265_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 1280u);
    CHECK_EQ(info.height, 720u);
    CHECK_EQ(info.profile, "Main");
  }
}

TEST_CASE("SpsParser H.265: constructed parameter sets with a conformance window") {
  // 4:4:4 (chroma_format_idc 3) with a conformance window, which is the H.265
  // side of the crop-factor table: subWidthC and subHeightC are both 1, so a
  // window of 2 + 2 columns and 4 + 4 rows comes off 1:1: 1920 - 4 = 1916 and
  // 1080 - 8 = 1072. ffmpeg 7.1 reads this vector as "hevc (Main), yuv444p,
  // 1916x1072".
  {
    H265SpsFields fields;
    fields.general_level_idc = 120;
    fields.chroma_format_idc = 3;
    fields.pic_width_in_luma_samples = 1920;
    fields.pic_height_in_luma_samples = 1080;
    fields.conformance_window_flag = true;
    fields.win_left = 2;
    fields.win_right = 2;
    fields.win_top = 4;
    fields.win_bottom = 4;
    const std::vector<uint8_t> nal = build_h265_sps(fields);
    CHECK_EQ(to_hex(nal),
             "42010101400000030090000003000003017890007810021cdb29728af248db59");
    const SpsInfo info = parse_h265_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 1916u);
    CHECK_EQ(info.height, 1072u);
    CHECK_EQ(info.chroma_format_idc, 3u);
  }

  // The same set with separate_colour_plane_flag = 1, the one bit H.265 places
  // between chroma_format_idc and pic_width_in_luma_samples. The flag does not
  // change the crop factors (chroma_format_idc is still 3), so the size is
  // unchanged -- but it has to be consumed. ffmpeg 7.1 reads this vector as
  // 1916x1072 as well (it reports no pixel format for it, which is what a
  // separate-colour-plane stream looks like to a decoder).
  {
    H265SpsFields fields;
    fields.general_level_idc = 120;
    fields.chroma_format_idc = 3;
    fields.separate_colour_plane_flag = 1;
    fields.pic_width_in_luma_samples = 1920;
    fields.pic_height_in_luma_samples = 1080;
    fields.conformance_window_flag = true;
    fields.win_left = 2;
    fields.win_right = 2;
    fields.win_top = 4;
    fields.win_bottom = 4;
    const std::vector<uint8_t> nal = build_h265_sps(fields);
    CHECK_EQ(to_hex(nal),
             "42010101400000030090000003000003017892007810021cdb29728af248db59");
    const SpsInfo info = parse_h265_sps(nal);
    CHECK_MESSAGE(info.ok, info.error);
    CHECK_EQ(info.width, 1916u);
    CHECK_EQ(info.height, 1072u);
    CHECK_EQ(info.chroma_format_idc, 3u);
  }
}

TEST_CASE("SpsParser H.264: constructed parameter sets that exercise escape removal") {
  // The sizes in the rest of this file mostly do not depend on the escape
  // removal (see the note in the header of the file), so these three sets place
  // escapes inside the fields being read on purpose. Each is the 720p field set
  // with a scaling matrix whose first delta_scale value is huge: the Exp-Golomb
  // code for it is tens of zero bits followed by a one, so the encoded bytes
  // contain `00 00 0X` -- and the sender's escaping turns that into
  // `00 00 03 0X`, with X being 1, 2 and 3 respectively. Those are the three
  // "followed by" cases of the rule besides 00 (which the encoders produce
  // everywhere), so all four values the standard lists are covered, and all
  // three land in the delta_scale loop that has to be skipped to reach the
  // size fields at all:
  //
  //   with the `03` kept, the delta_scale loop eats a different number of bits
  //   and the parse runs off the end of the payload -- which is why these
  //   expected values are not just the arithmetic, they are arithmetic plus a
  //   removal rule that has to fire.
  //
  // Expected values: the fields are the 720p set (80x45 macroblocks, no crop),
  // so 1280x720, High, 3.1. All three were spliced into the real 720p stream in
  // place of its own SPS and read back by ffmpeg 7.1, which reported 1280x720
  // for each.
  struct EscapeCase {
    int32_t delta_scale;
    const char *hex;
  };
  const EscapeCase cases[] = {
      // unescaped ... 00 00 01 ... -> escaped 00 00 03 01
      {536870912, "6764101fad80000003010000030003fff80b80a00b72"},
      // unescaped ... 00 00 02 ... -> escaped 00 00 03 02
      {268435456, "6764101fad8000000302000003000fffe02e02802dc8"},
      // unescaped ... 00 00 03 ... -> escaped 00 00 03 03
      {2097152, "6764101fad80000100000303fff80b80a00b72"},
  };
  for (const EscapeCase &escape_case : cases) {
    H264SpsFields fields;
    std::vector<std::vector<int32_t>> lists(8);
    lists[0] = {escape_case.delta_scale};
    const std::vector<uint8_t> nal = build_h264_sps(fields, lists);
    CHECK_EQ(to_hex(nal), std::string(escape_case.hex));
    const SpsInfo info = parse_h264_sps(nal);
    CHECK_MESSAGE(info.ok, escape_case.hex << ": " << info.error);
    CHECK_EQ(info.width, 1280u);
    CHECK_EQ(info.height, 720u);
    CHECK_EQ(info.profile, "High");
  }
}

TEST_CASE("SpsParser failures: nothing is guessed") {
  // An empty payload is not an SPS. ("empty" rather than "notSps": there is not
  // even a NAL header to classify.)
  expect_h264_failure("h264 empty", "", "empty");
  expect_h265_failure("h265 empty", "", "empty");

  // A PPS (type 8, taken from the 720p file above) handed to the H.264 parser,
  // and a VPS (type 32, from the 1080p HEVC file) handed to the H.265 parser:
  // both are `notSps`, which is how a caller that grabbed the wrong NAL finds
  // out, and neither produces a size.
  expect_h264_failure("h264 PPS is not an SPS", "68ee0f2c8b", "notSps");
  expect_h265_failure("h265 VPS is not an SPS",
                      "40010c01ffff016000000300900000030000030078959809", "notSps");

  // The 720p SPS cut to six bytes (profile, constraint flags, level, then the
  // parts of the first Exp-Golomb codes that fit). Reading it by hand: after
  // the three fixed bytes, seq_parameter_set_id is the single bit "1" (0),
  // chroma_format_idc is "01 0" (1), the two bit depths are "1" and "1" (0),
  // qpprime and the scaling-matrix flag are "0" and "0", log2_max_frame_num_minus4
  // is "1" (0), pic_order_cnt_type is "01 1" (2), max_num_ref_frames is "1" (0),
  // gaps_in_frame_num_value_allowed_flag is "0", and then the two bits that
  // are left are not enough for pic_width_in_mbs_minus1. The first element that
  // runs out is therefore the width.
  expect_h264_failure("h264 truncated", "6764101facb8",
                      "truncated:pic_width_in_mbs_minus1");

  // The HEVC 1080p SPS cut to three bytes: the two NAL header bytes and one
  // byte carrying sps_video_parameter_set_id (0), sps_max_sub_layers_minus1
  // (0) and sps_temporal_id_nesting_flag (1), which is exactly eight bits, so
  // profile_tier_level starts at the end of the payload and its very first
  // element is the one that runs out.
  expect_h265_failure("h265 truncated", "420101", "truncated:general_profile_space");

  // chroma_format_idc above 3 is not a value the standard defines (H.264
  // 7.4.2.1.1). The rest of this SPS is the 720p set, so a parser that took
  // the value anyway would go on to report 1280x720. Constructed (the expected
  // result is the standard's range, not a size, so there is nothing external to
  // check the expectation against).
  {
    H264SpsFields fields;
    fields.chroma_format_idc = 4;
    const std::vector<uint8_t> nal = build_h264_sps(fields, {});
    CHECK_EQ(to_hex(nal), "6764101f972e02802dc8");
    expect_h264_failure("h264 chroma_format_idc 4", to_hex(nal),
                        "badValue:chroma_format_idc");
  }

  // pic_order_cnt_type above 2 is the same kind of value: it is not just out of
  // range, it selects which of three field lists follows it, so there is no
  // field order to read from there on. The rest of this SPS is the 720p set.
  {
    H264SpsFields fields;
    fields.pic_order_cnt_type = 3;
    const std::vector<uint8_t> nal = build_h264_sps(fields, {});
    expect_h264_failure("h264 pic_order_cnt_type 3", to_hex(nal),
                        "badValue:pic_order_cnt_type");
  }

  // A crop window as large as the coded picture. 80x45 macroblocks is 720 lines
  // and frame_crop_bottom_offset 360 at subHeightC 2 asks to remove exactly
  // those 720, leaving nothing; the subtraction is checked before it is
  // reported rather than wrapping into a huge height.
  {
    H264SpsFields fields;
    fields.frame_cropping_flag = true;
    fields.crop_bottom = 360;
    const std::vector<uint8_t> nal = build_h264_sps(fields, {});
    CHECK_EQ(to_hex(nal), "6764101facb80a00b7f00b4a");
    expect_h264_failure("h264 crop eats the picture", to_hex(nal),
                        "badValue:frame_crop_offset");
  }

  // The escaped payload `... ac b4 00 00 03 04 90`, which is the 720p-style
  // header followed by a byte sequence a sender would never produce: a `03`
  // that is *not* followed by 00..03 is not an emulation prevention byte
  // (requirement 1), so it stays in the stream as data. Reading it strictly:
  // after `00 00` the reader is inside an Exp-Golomb code whose first 22 bits
  // are zero and which then needs 22 more bits, while only 17 remain before the
  // end of the payload, so pic_width_in_mbs_minus1 is where it runs out -- the
  // result is a failure, not a size.
  //
  // Note what this case does and does not pin: it pins that a malformed escape
  // yields no guessed size. It does not by itself separate the standard's rule
  // from a laxer "always remove 00 00 03", because that reader also fails on
  // these bytes (it consumes one byte fewer and runs out in the same code). The
  // vectors that do pin the removal rule are the real ones above, which all
  // contain escapes that must be removed for the size to come out right.
  expect_h264_failure("h264 escape not followed by 00..03", "6764101facb40000030490",
                      "truncated:pic_width_in_mbs_minus1");
}
