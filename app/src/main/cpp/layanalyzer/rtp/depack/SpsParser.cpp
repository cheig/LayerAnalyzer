// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// H.264 / H.265 sequence parameter set parsing -- RTP5-NAT-04.
// See SpsParser.h for the contract and for the decisions taken here.
//
// 纯标准库：本文件不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#include "layanalyzer/rtp/depack/SpsParser.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {
namespace {

// 允许报告的最大画面尺寸。远高于任何真实码流（8K 是 7680×4320），又小到
// 让下面的 64 位算术不会绕回一个看起来合理的 uint32 值。
constexpr uint64_t kMaxDimension = 65536u;

// H.264 中带 chroma_format_idc 等字段的 profile（H.264 7.3.2.1.1 的条件）。
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

// 去防竞争字节（要求 1）。只对 NAL 头之后的负载做，并且只在 03 后面跟着
// 00/01/02/03 时删掉 03 —— 03 是最后一个字节、或者后面跟着别的值时不删，
// 否则后面的每一个比特都会错位（头文件第 1 条）。
std::vector<uint8_t> remove_emulation_prevention(const uint8_t *data, size_t size) {
  std::vector<uint8_t> rbsp;
  rbsp.reserve(size);
  size_t i = 0;
  while (i < size) {
    if (i + 3 < size && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 3 &&
        data[i + 3] <= 3) {
      rbsp.push_back(0);
      rbsp.push_back(0);
      i += 3;
    } else {
      rbsp.push_back(data[i]);
      ++i;
    }
  }
  return rbsp;
}

class BitReader {
 public:
  enum class Failure { kNone, kTruncated, kMalformed };

  BitReader(const uint8_t *data, size_t size)
      : data_(data), size_bits_(size * 8) {}

  // 越界 → 失败，不猜测（要求 2）。count > 32 不是越界，是这个读取器不接受
  // 的长度，所以算 malformed。
  bool read_bits(unsigned count, uint32_t *out) {
    if (count > 32) {
      fail(Failure::kMalformed);
      return false;
    }
    if (bit_pos_ + count > size_bits_) {
      fail(Failure::kTruncated);
      return false;
    }
    uint32_t value = 0;
    for (unsigned i = 0; i < count; ++i) {
      const size_t at = bit_pos_ + i;
      value = (value << 1) | ((data_[at / 8] >> (7 - (at % 8))) & 1u);
    }
    bit_pos_ += count;
    *out = value;
    return true;
  }

  bool read_ue(uint32_t *out) {
    unsigned zeros = 0;
    uint32_t bit = 0;
    while (true) {
      if (!read_bits(1, &bit)) return false;
      if (bit != 0) break;
      if (++zeros > 31) {  // 前导零超过 31 个，值装不进 uint32
        fail(Failure::kMalformed);
        return false;
      }
    }
    uint32_t rest = 0;
    if (zeros > 0 && !read_bits(zeros, &rest)) return false;
    *out = (zeros == 0 ? 0u : ((1u << zeros) - 1u)) + rest;
    return true;
  }

  // se(v) = (-1)^(k+1) * ceil(k / 2)，k = ue 值 + 1（H.264 9.1）。
  bool read_se(int32_t *out) {
    uint32_t code = 0;
    if (!read_ue(&code)) return false;
    if (code > 0x7FFFFFFFu) {  // 同样是为了不溢出 int32
      fail(Failure::kMalformed);
      return false;
    }
    const int32_t k = static_cast<int32_t>(code) + 1;
    *out = (k % 2 == 0) ? -(k / 2) : ((k + 1) / 2);
    return true;
  }

  // 跳过已经读过、但内容用不到的比特（保留位）。越界同样是失败。
  bool skip_bits(unsigned count) {
    if (bit_pos_ + count > size_bits_) {
      fail(Failure::kTruncated);
      return false;
    }
    bit_pos_ += count;
    return true;
  }

  Failure failure() const { return failure_; }
  void fail(Failure failure) {
    if (failure_ == Failure::kNone) failure_ = failure;
  }

 private:
  const uint8_t *data_;
  size_t size_bits_;
  size_t bit_pos_ = 0;
  Failure failure_ = Failure::kNone;
};

// 每个语法元素都带名字读，失败时错误信息里就有是哪一步（要求 7）。
class Reader {
 public:
  explicit Reader(const std::vector<uint8_t> &rbsp)
      : bits_(rbsp.empty() ? nullptr : rbsp.data(), rbsp.size()) {}

  uint32_t u(unsigned count, const char *name) {
    uint32_t value = 0;
    if (!bits_.read_bits(count, &value)) fail(name);
    return value;
  }

  uint32_t ue(const char *name) {
    uint32_t value = 0;
    if (!bits_.read_ue(&value)) fail(name);
    return value;
  }

  int32_t se(const char *name) {
    int32_t value = 0;
    if (!bits_.read_se(&value)) fail(name);
    return value;
  }

  // 保留位只关心长度，不关心内容（43 位一次读不完一个 uint32）。
  void skip(unsigned count, const char *name) {
    if (!bits_.skip_bits(count)) fail(name);
  }

  bool failed() const { return !error_.empty(); }
  const std::string &error() const { return error_; }

 private:
  // 第一个错误优先：后面的读取失败不会覆盖它是哪一步。
  void fail(const char *name) {
    if (!error_.empty()) return;
    error_ = std::string(bits_.failure() == BitReader::Failure::kTruncated
                             ? "truncated:"
                             : "badValue:") +
             name;
  }

  BitReader bits_;
  std::string error_;
};

// subWidthC / subHeightC（要求 4 的表；0 是单色，按 1/1 裁剪）。
void chroma_sampling_factors(uint32_t chroma_format_idc, uint64_t *sub_width_c,
                             uint64_t *sub_height_c) {
  switch (chroma_format_idc) {
    case 1:
      *sub_width_c = 2;
      *sub_height_c = 2;
      return;
    case 2:
      *sub_width_c = 2;
      *sub_height_c = 1;
      return;
    case 3:
      *sub_width_c = 1;
      *sub_height_c = 1;
      return;
    default:  // 0（单色），以及任何不该出现的值
      *sub_width_c = 1;
      *sub_height_c = 1;
      return;
  }
}

std::string h264_profile_name(uint32_t profile_idc) {
  switch (profile_idc) {
    case 44:
      return "CAVLC 4:4:4 Intra";
    case 66:
      return "Baseline";
    case 77:
      return "Main";
    case 83:
      return "Scalable Baseline";
    case 86:
      return "Scalable High";
    case 88:
      return "Extended";
    case 100:
      return "High";
    case 110:
      return "High 10";
    case 118:
      return "Multiview High";
    case 122:
      return "High 4:2:2";
    case 128:
      return "Stereo High";
    case 134:
      return "MFC High";
    case 135:
      return "MFC Depth High";
    case 138:
      return "Multiview Depth High";
    case 139:
      return "Enhanced Multiview Depth High";
    case 244:
      return "High 4:4:4 Predictive";
    default:
      return "Unknown";
  }
}

std::string h265_profile_name(uint32_t general_profile_idc) {
  switch (general_profile_idc) {
    case 1:
      return "Main";
    case 2:
      return "Main 10";
    case 3:
      return "Main Still Picture";
    case 4:
      return "Range Extensions";
    default:
      return "Unknown";
  }
}

// level_idc / 10 加 "." 加 level_idc % 10；level_idc == 0 时不带小数（要求 6）。
// level 1b（level_idc 9）因此会写成 "0.9"，这是卡片冻结的公式的结果。
std::string h264_level_name(uint32_t level_idc) {
  if (level_idc == 0) return "0";
  return std::to_string(level_idc / 10) + "." + std::to_string(level_idc % 10);
}

// H.265 的 general_level_idc = 30 * 主版本 + 3 * 次版本（H.265 附录 A.4），
// 所以余数要再除以 3：120 → "4.0"，123 → "4.1"，63 → "2.1"。
std::string h265_level_name(uint32_t general_level_idc) {
  if (general_level_idc == 0) return "0";
  return std::to_string(general_level_idc / 30) + "." +
         std::to_string((general_level_idc % 30) / 3);
}

// 尺寸算术（要求 4）：64 位算完再检查，检查不过就报错，绝不给出猜测值。
SpsInfo finish_dimensions(SpsInfo info, uint64_t coded_width, uint64_t coded_height,
                          uint64_t crop_width, uint64_t crop_height,
                          const char *crop_error) {
  if (coded_width <= crop_width || coded_height <= crop_height) {
    info.error = crop_error;
    return info;
  }
  const uint64_t width = coded_width - crop_width;
  const uint64_t height = coded_height - crop_height;
  if (width > kMaxDimension || height > kMaxDimension) {
    info.error = "badValue:dimensions";
    return info;
  }
  info.width = static_cast<uint32_t>(width);
  info.height = static_cast<uint32_t>(height);
  info.ok = true;
  return info;
}

// H.265 profile_tier_level（H.265 7.3.3），profilePresentFlag 恒为 1。
// 子层信息按 sps_max_sub_layers_minus1 循环：先是每层的 present 标志，然后是
// 补齐字节的 reserved_zero_2bits，最后才是各层自己的 profile（88 位）和
// level（8 位）。少读一层，后面的 pic_width_in_luma_samples 就会读到错误的
// 位置 —— 这正是 requirement 5 要钉住的行为。
void read_h265_profile_tier_level(Reader *r, uint32_t max_sub_layers_minus1,
                                  uint32_t *general_profile_idc,
                                  uint32_t *general_level_idc) {
  r->u(2, "general_profile_space");
  r->u(1, "general_tier_flag");
  *general_profile_idc = r->u(5, "general_profile_idc");
  r->u(32, "general_profile_compatibility_flag");
  r->u(4, "general_source_constraint_flags");
  r->skip(43, "general_reserved_zero_43bits");
  r->u(1, "general_inbld_flag");
  *general_level_idc = r->u(8, "general_level_idc");

  std::vector<uint32_t> sub_layer_profile_present(max_sub_layers_minus1, 0);
  std::vector<uint32_t> sub_layer_level_present(max_sub_layers_minus1, 0);
  for (uint32_t i = 0; i < max_sub_layers_minus1; ++i) {
    sub_layer_profile_present[i] = r->u(1, "sub_layer_profile_present_flag");
    sub_layer_level_present[i] = r->u(1, "sub_layer_level_present_flag");
  }
  // reserved_zero_2bits 只在前面的计数大于 0 时才存在（H.265 7.3.3）：
  // sps_max_sub_layers_minus1 为 0 时这 16 位根本不在码流里，多读一次就会让
  // 后面的 pic_width_in_luma_samples 整体错位。
  if (max_sub_layers_minus1 > 0) {
    for (uint32_t i = max_sub_layers_minus1; i < 8; ++i)
      r->u(2, "reserved_zero_2bits");
  }
  for (uint32_t i = 0; i < max_sub_layers_minus1; ++i) {
    if (sub_layer_profile_present[i]) {
      r->u(2, "sub_layer_profile_space");
      r->u(1, "sub_layer_tier_flag");
      r->u(5, "sub_layer_profile_idc");
      r->u(32, "sub_layer_profile_compatibility_flag");
      r->u(4, "sub_layer_source_constraint_flags");
      r->skip(43, "sub_layer_reserved_zero_43bits");
      r->u(1, "sub_layer_inbld_flag");
    }
    if (sub_layer_level_present[i]) r->u(8, "sub_layer_level_idc");
  }
}

}  // namespace

SpsInfo parse_h264_sps(const std::vector<uint8_t> &nal_without_start_code) {
  SpsInfo info;
  if (nal_without_start_code.empty()) {
    info.error = "empty";
    return info;
  }
  if ((nal_without_start_code[0] & 0x1Fu) != 7u) {
    info.error = "notSps";
    return info;
  }

  const std::vector<uint8_t> rbsp = remove_emulation_prevention(
      nal_without_start_code.data() + 1, nal_without_start_code.size() - 1);
  Reader r(rbsp);

  const uint32_t profile_idc = r.u(8, "profile_idc");
  r.u(8, "constraint_set_flags");
  const uint32_t level_idc = r.u(8, "level_idc");
  r.ue("seq_parameter_set_id");

  uint32_t chroma_format_idc = 1;
  if (h264_has_chroma_block(profile_idc)) {
    chroma_format_idc = r.ue("chroma_format_idc");
    if (!r.failed() && chroma_format_idc > 3) {
      info.error = "badValue:chroma_format_idc";
      return info;
    }
    if (chroma_format_idc == 3) r.u(1, "separate_colour_plane_flag");
    r.ue("bit_depth_luma_minus8");
    r.ue("bit_depth_chroma_minus8");
    r.u(1, "qpprime_y_zero_transform_bypass_flag");
    if (r.u(1, "seq_scaling_matrix_present_flag") != 0) {
      // 8 组（chroma_format_idc != 3）或 12 组；第 i 组 16 项（i < 6），
      // 其余 64 项（H.264 7.3.2.1.1）。
      const uint32_t list_count = (chroma_format_idc == 3) ? 12u : 8u;
      for (uint32_t i = 0; i < list_count; ++i) {
        if (r.u(1, "seq_scaling_list_present_flag") == 0) continue;
        const uint32_t entry_count = (i < 6) ? 16u : 64u;
        for (uint32_t j = 0; j < entry_count; ++j) r.se("delta_scale");
      }
    }
  }

  r.ue("log2_max_frame_num_minus4");
  const uint32_t pic_order_cnt_type = r.ue("pic_order_cnt_type");
  // pic_order_cnt_type 只定义了 0、1、2，而且它决定后面还有没有额外字段：别的值
  // 没有可依据的语法，接着读下去就是猜（要求 7）。
  if (!r.failed() && pic_order_cnt_type > 2) {
    info.error = "badValue:pic_order_cnt_type";
    return info;
  }
  if (pic_order_cnt_type == 0) {
    r.ue("log2_max_pic_order_cnt_lsb_minus4");
  } else if (pic_order_cnt_type == 1) {
    r.u(1, "delta_pic_order_always_zero_flag");
    r.se("offset_for_non_ref_pic");
    r.se("offset_for_top_to_bottom_field");
    const uint32_t cycle = r.ue("num_ref_frames_in_pic_order_cnt_cycle");
    if (!r.failed() && cycle > 255) {
      info.error = "badValue:num_ref_frames_in_pic_order_cnt_cycle";
      return info;
    }
    for (uint32_t i = 0; i < cycle; ++i) r.se("offset_for_ref_frame");
  }

  r.ue("max_num_ref_frames");
  r.u(1, "gaps_in_frame_num_value_allowed_flag");
  const uint32_t pic_width_in_mbs_minus1 = r.ue("pic_width_in_mbs_minus1");
  const uint32_t pic_height_in_map_units_minus1 =
      r.ue("pic_height_in_map_units_minus1");
  const uint32_t frame_mbs_only_flag = r.u(1, "frame_mbs_only_flag");
  if (frame_mbs_only_flag == 0) r.u(1, "mb_adaptive_frame_field_flag");
  r.u(1, "direct_8x8_inference_flag");

  uint32_t crop_left = 0, crop_right = 0, crop_top = 0, crop_bottom = 0;
  if (r.u(1, "frame_cropping_flag") != 0) {
    crop_left = r.ue("frame_crop_left_offset");
    crop_right = r.ue("frame_crop_right_offset");
    crop_top = r.ue("frame_crop_top_offset");
    crop_bottom = r.ue("frame_crop_bottom_offset");
  }
  r.u(1, "vui_parameters_present_flag");

  if (r.failed()) {
    info.error = r.error();
    return info;
  }

  uint64_t sub_width_c = 1;
  uint64_t sub_height_c = 1;
  chroma_sampling_factors(chroma_format_idc, &sub_width_c, &sub_height_c);

  const uint64_t frame_mbs_only = frame_mbs_only_flag;
  const uint64_t coded_width = (static_cast<uint64_t>(pic_width_in_mbs_minus1) + 1) * 16;
  const uint64_t coded_height = (2 - frame_mbs_only) *
                                (static_cast<uint64_t>(pic_height_in_map_units_minus1) + 1) * 16;
  const uint64_t crop_width =
      (static_cast<uint64_t>(crop_left) + crop_right) * sub_width_c;
  const uint64_t crop_height = (static_cast<uint64_t>(crop_top) + crop_bottom) *
                               sub_height_c * (2 - frame_mbs_only);

  info = finish_dimensions(info, coded_width, coded_height, crop_width, crop_height,
                           "badValue:frame_crop_offset");
  if (!info.ok) return info;
  info.chroma_format_idc = chroma_format_idc;
  info.profile = h264_profile_name(profile_idc);
  info.level = h264_level_name(level_idc);
  return info;
}

SpsInfo parse_h265_sps(const std::vector<uint8_t> &nal_without_start_code) {
  SpsInfo info;
  if (nal_without_start_code.size() < 2) {
    info.error = nal_without_start_code.empty() ? "empty" : "truncated:nal_header";
    return info;
  }
  // H.265 的 NAL 头是两字节，类型在第一个字节的 bit 1..6。
  if (((nal_without_start_code[0] >> 1) & 0x3Fu) != 33u) {
    info.error = "notSps";
    return info;
  }

  const std::vector<uint8_t> rbsp = remove_emulation_prevention(
      nal_without_start_code.data() + 2, nal_without_start_code.size() - 2);
  Reader r(rbsp);

  r.u(4, "sps_video_parameter_set_id");
  const uint32_t max_sub_layers_minus1 = r.u(3, "sps_max_sub_layers_minus1");
  r.u(1, "sps_temporal_id_nesting_flag");
  uint32_t general_profile_idc = 0;
  uint32_t general_level_idc = 0;
  read_h265_profile_tier_level(&r, max_sub_layers_minus1, &general_profile_idc,
                               &general_level_idc);

  r.ue("sps_seq_parameter_set_id");
  const uint32_t chroma_format_idc = r.ue("chroma_format_idc");
  if (!r.failed() && chroma_format_idc > 3) {
    info.error = "badValue:chroma_format_idc";
    return info;
  }
  if (chroma_format_idc == 3) r.u(1, "separate_colour_plane_flag");
  const uint32_t pic_width_in_luma_samples = r.ue("pic_width_in_luma_samples");
  const uint32_t pic_height_in_luma_samples = r.ue("pic_height_in_luma_samples");

  uint32_t win_left = 0, win_right = 0, win_top = 0, win_bottom = 0;
  if (r.u(1, "conformance_window_flag") != 0) {
    win_left = r.ue("conf_win_left_offset");
    win_right = r.ue("conf_win_right_offset");
    win_top = r.ue("conf_win_top_offset");
    win_bottom = r.ue("conf_win_bottom_offset");
  }

  if (r.failed()) {
    info.error = r.error();
    return info;
  }

  uint64_t sub_width_c = 1;
  uint64_t sub_height_c = 1;
  chroma_sampling_factors(chroma_format_idc, &sub_width_c, &sub_height_c);
  const uint64_t crop_width =
      (static_cast<uint64_t>(win_left) + win_right) * sub_width_c;
  const uint64_t crop_height =
      (static_cast<uint64_t>(win_top) + win_bottom) * sub_height_c;

  info = finish_dimensions(info, pic_width_in_luma_samples,
                           pic_height_in_luma_samples, crop_width, crop_height,
                           "badValue:conformance_window");
  if (!info.ok) return info;
  info.chroma_format_idc = chroma_format_idc;
  info.profile = h265_profile_name(general_profile_idc);
  info.level = h265_level_name(general_level_idc);
  return info;
}

}  // namespace layanalyzer::rtp
