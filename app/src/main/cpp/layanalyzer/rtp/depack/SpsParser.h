// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// H.264 / H.265 sequence parameter set parsing -- RTP5-NAT-04.
//
// Input: one parameter set NAL unit as the de-packetizers above hand it up --
// raw bytes, no start code, still carrying the NAL header (NAT-01/NAT-02 strip
// the packetization and nothing else). Output: the picture size and a couple of
// labels for the M5 export result (`width`/`height`/`profile`/`level` of
// task_rtp_m5_video.md section 3.1).
//
// This is deliberately *not* a validator and not a full SPS reader. It reads
// exactly the syntax elements the task card lists, in the order the standard
// defines them, and it stops after the last one it needs:
//
//   H.264 (7.3.2.1): profile_idc, the constraint flags, level_idc, the
//     High-profile block (chroma_format_idc ... seq_scaling_matrix_present_flag
//     and the scaling lists it guards), log2_max_frame_num_minus4,
//     pic_order_cnt_type and its three branches, max_num_ref_frames,
//     gaps_in_frame_num_value_allowed_flag, pic_width_in_mbs_minus1,
//     pic_height_in_map_units_minus1, frame_mbs_only_flag (with
//     mb_adaptive_frame_field_flag), direct_8x8_inference_flag,
//     frame_cropping_flag and its four offsets, vui_parameters_present_flag.
//   H.265 (7.3.2.2): sps_video_parameter_set_id, sps_max_sub_layers_minus1,
//     sps_temporal_id_nesting_flag, profile_tier_level, then
//     sps_seq_parameter_set_id, chroma_format_idc, pic_width_in_luma_samples,
//     pic_height_in_luma_samples and the conformance window.
//
// Everything after those points (the VUI, the DPB and reorder fields, the HEVC
// coding-block geometry, extensions) is left unread, so a stream whose tail is
// missing still parses here: this function answers "what size does this SPS
// describe?", not "is this SPS complete?".
//
// Decisions the task card left open, resolved here (RTP5-NAT-04):
//
// 1. Emulation prevention (requirement 1) is applied to the payload *after* the
//    NAL header, and only where the standard says it applies: a `00 00 03`
//    sequence is removed when the byte after the `03` is 00, 01, 02 or 03. A
//    `03` that is followed by anything else -- or by nothing, i.e. it is the
//    last byte of the NAL -- is kept as data, because removing it there would
//    silently shift every following bit. A stream that ends in `00 00 03` is
//    therefore malformed for this reader and ends in a truncation failure
//    rather than in a guessed size.
// 2. The reader never reads past the end and never pads: a read that does not
//    fit fails (requirement 2) and is reported as `truncated:<element>`, so the
//    error names the syntax element that ran out. `badValue:<element>` is the
//    other failure kind: the element was read, but the value is outside the
//    range the standard allows, or -- for the two elements that decide the rest
//    of the syntax, `chroma_format_idc` and `pic_order_cnt_type` -- a value the
//    standard does not define at all, so that there is no field order to follow
//    from there. The elements that can appear in a `badValue` are
//    `chroma_format_idc`, `pic_order_cnt_type`,
//    `num_ref_frames_in_pic_order_cnt_cycle`,
//    `frame_crop_offset` (H.264) / `conformance_window` (H.265), and
//    `dimensions` for the size cap in decision 4. The full error vocabulary is:
//    `empty`, `notSps`, `truncated:<element>`, `badValue:<element>`. The first
//    failure wins, so the reported element is always the earliest one in
//    decoding order.
// 3. `width` and `height` are assigned only once every element above has been
//    read and the arithmetic has been checked (requirements 4, 7). A failed
//    parse leaves both at zero: there is no partial or guessed size, and the
//    `profile`/`level` strings are dropped along with it (they are only filled
//    in on the success path).
// 4. The size arithmetic runs in 64 bits and the result is capped at
//    kMaxDimension (65536), which is far above any real picture and keeps a
//    malformed `pic_width_in_mbs_minus1` from wrapping into a plausible-looking
//    32-bit value on the way into `uint32_t width`. A crop window that is not
//    strictly smaller than the coded size is `badValue:frame_crop_offset`
//    (H.264) or `badValue:conformance_window` (H.265) rather than a wrapped
//    (huge) dimension, and a size past the cap is `badValue:dimensions`.
// 5. `subWidthC`/`subHeightC` come from `chroma_format_idc` exactly as the card
//    spells them out: 1 -> 2/2, 2 -> 2/1, 3 -> 1/1, and 0 (monochrome) -> 1/1.
//    For H.264 the field only exists in the High-family profiles, and when it
//    is absent `chroma_format_idc` stays at its documented default of 1, which
//    is what those profiles imply (4:2:0).
// 6. The scaling-list count follows the standard, not a fixed 8: 12 lists when
//    chroma_format_idc is 3, otherwise 8, and the list at index i holds 16
//    entries below index 6 and 64 from index 6 up (H.264 7.3.2.1.1). Each
//    present list is skipped as `sizeOfScalingList` `delta_scale` exp-Golomb
//    codes -- exactly that many, with no terminator. The card's "8 or 12" is
//    this rule.
// 7. `separate_colour_plane_flag` is read when H.265's chroma_format_idc is 3.
//    The card lists the flag for H.264 only, but H.265 places it in the same
//    spot for the same reason, and a 4:4:4 HEVC stream would misalign by one
//    bit without it. It is read and not used: the card defines the crop
//    factors from chroma_format_idc, and the flag does not change that table.
// 8. HEVC's profile_tier_level loops the sub-layer information exactly as
//    H.265 7.3.3 defines it: the per-sub-layer present flags, the two reserved
//    bits that fill the byte when sub-layers are signalled, and then each
//    present sub-layer profile block (88 bits) and level (8 bits). Skipping
//    that loop would leave the reader eight bits short per sub-layer and
//    produce a wrong `pic_width_in_luma_samples` -- which is the failure this
//    task's tests pin.
// 9. Names (requirement 6): the H.264 profile table carries the card's entries
//    plus the rest of Table A-1, and the H.265 table the card's three plus
//    Range Extensions (Table A.2); an idc outside the table is named
//    `Unknown`, never guessed. The H.264 level string is the card's formula,
//    `level_idc / 10` and `level_idc % 10`, with no decimal part when
//    level_idc is 0 -- so level 1b (level_idc 9, the one level whose idc is not
//    ten times its number) prints as "0.9", which is a known consequence of
//    the frozen formula. The H.265 string uses general_level_idc = 30 * major
//    + 3 * minor (H.265 Annex A.4), so the remainder is divided by 3:
//    120 -> "4.0", 123 -> "4.1", 63 -> "2.1", and 0 prints as "0".
// 10. The classification of the failure cases is part of the contract: a
//    payload whose NAL header does not carry the SPS type is `notSps`, which
//    is how a caller that grabbed the wrong NAL finds out. For H.264 that is
//    type 7 (`nal[0] & 0x1F`), for H.265 type 33 (`(nal[0] >> 1) & 0x3F`).
//
// 纯标准库：本文件及其 .cpp 不得包含任何 Wireshark/GLib/JNI/nlohmann 头文件，
// 以便 host 单测（native_build/verification/rtp/host_tests）直接编译。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace layanalyzer::rtp {

struct SpsInfo {
  uint32_t width = 0, height = 0;
  std::string profile, level;
  uint32_t chroma_format_idc = 1;
  bool ok = false;
  std::string error;
};

// Both take the parameter set NAL unit *with* its NAL header and without a
// start code, exactly as H264Depack/H265Depack produce it (RFC 6184 and
// RFC 7798 never put a start code in a payload). Anything else -- a slice, a
// PPS, an empty vector -- comes back as `ok = false` with the reason in
// `error`.
SpsInfo parse_h264_sps(const std::vector<uint8_t> &nal_without_start_code);
SpsInfo parse_h265_sps(const std::vector<uint8_t> &nal_without_start_code);

}  // namespace layanalyzer::rtp
