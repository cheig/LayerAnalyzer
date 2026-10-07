cmake_minimum_required(VERSION 3.22.1)

project("layanalyzer")
enable_language(ASM)

# Define paths
set(LIB_DIR ${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI})
set(INC_DIR ${CMAKE_SOURCE_DIR}/include)
set(CMAKE_CXX_FLAGS   "-g")

# --- Imported Static Libraries ---
add_library(z STATIC IMPORTED)
set_target_properties(z PROPERTIES IMPORTED_LOCATION "${LIB_DIR}/libz.a")

add_library(pcre2-8 STATIC IMPORTED)
set_target_properties(pcre2-8 PROPERTIES IMPORTED_LOCATION "${LIB_DIR}/libpcre2-8.a")

add_library(ffi STATIC IMPORTED)
set_target_properties(ffi PROPERTIES IMPORTED_LOCATION "${LIB_DIR}/libffi.a")

add_library(iconv STATIC IMPORTED)
set_target_properties(iconv PROPERTIES IMPORTED_LOCATION "${LIB_DIR}/libiconv.a")

# --- Imported Shared Libraries ---
# Helper macro to add shared libs
macro(add_shared_lib name)
    add_library(${name} SHARED IMPORTED)
    set_target_properties(${name} PROPERTIES IMPORTED_LOCATION "${LIB_DIR}/lib${name}.so")
endmacro()

add_shared_lib(gpg-error)
add_shared_lib(gcrypt)
add_shared_lib(cares)

add_shared_lib(glib-2.0)
add_shared_lib(gmodule-2.0)
add_shared_lib(gobject-2.0)
add_shared_lib(gthread-2.0)

add_shared_lib(wsutil)
add_shared_lib(wiretap)
add_shared_lib(wireshark)

# --- Vendored spandsp subset (RTP4-BLD-01) ---
# G.722 / G.726 and the bitstream + allocator + vector helpers they link
# against. Third-party C sources, copied verbatim from freeswitch/spandsp at
# the commit recorded in THIRD_PARTY_NOTICES.md; see that file for
# the trimmed file list and the licence. STATIC + POSITION_INDEPENDENT_CODE so
# it folds into the main shared library (same ABI count and 16 KB alignment as
# before).
#
# alloc.c (span_alloc/span_free) and vector_int.c (vec_circular_dot_prodi16)
# are not optional: g722.c/g726.c/bitstream.c reference those symbols, so the
# three "codec" sources alone fail to link.
#
# HAVE_CONFIG_H=1 (not 0) on purpose: the sources test `#if defined(HAVE_CONFIG_H)`,
# which is true for any value, so a config.h is required either way. The one we
# ship is hand-written and minimal (third_party/spandsp-lite/include/config.h).
add_library(spandsp_lite STATIC
    third_party/spandsp-lite/src/g722.c
    third_party/spandsp-lite/src/g726.c
    third_party/spandsp-lite/src/bitstream.c
    third_party/spandsp-lite/src/alloc.c
    third_party/spandsp-lite/src/vector_int.c)
target_include_directories(spandsp_lite PUBLIC third_party/spandsp-lite/include)
target_compile_definitions(spandsp_lite PRIVATE HAVE_CONFIG_H=1)
set_target_properties(spandsp_lite PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99
    C_STANDARD_REQUIRED ON)
# Vendored code: warnings are not actionable here, and upstream sources must
# stay unmodified. Errors still fail the build.
if(MSVC)
    target_compile_options(spandsp_lite PRIVATE /W0)
else()
    target_compile_options(spandsp_lite PRIVATE -w)
endif()

# --- Main JNI Library ---
# The JNI bridge is split into independently compiled modules. Each JNI
# endpoint file only performs parameter conversion and result marshalling;
# shared state and cross-module declarations live in internal/EngineState.h
# and the per-module headers. Explicit sources keep incremental builds and
# ABI review predictable (no GLOB).
set(LAYANALYZER_SOURCES
    native-lib.cpp
    layanalyzer/internal/EngineState.cpp
    layanalyzer/jni/EngineLifecycle.cpp
    layanalyzer/session/WiresharkSession.cpp
    layanalyzer/projection/TreeFieldReader.cpp
    layanalyzer/projection/ProtocolProjection.cpp
    layanalyzer/jni/PacketListJni.cpp
    layanalyzer/jni/QueryJni.cpp
    layanalyzer/jni/AnalysisJni.cpp
    layanalyzer/jni/CommunicationJni.cpp
    layanalyzer/jni/ExportJni.cpp
    layanalyzer/jni/StreamHttpJni.cpp
    layanalyzer/jni/ConfigurationJni.cpp
    layanalyzer/jni/DetailJni.cpp
    layanalyzer/jni/PerfExportJni.cpp
    layanalyzer/jni/RtpJni.cpp
    layanalyzer/rtp/core/RtpStreamKey.cpp
    layanalyzer/rtp/core/RtpStreamAnalysis.cpp
    layanalyzer/rtp/core/RtpCodecNames.cpp
    layanalyzer/rtp/core/RtpDecodability.cpp
    layanalyzer/rtp/core/DtmfParser.cpp
    layanalyzer/rtp/core/RtppFile.cpp
    layanalyzer/rtp/core/RtppIndex.cpp
    layanalyzer/rtp/core/RtpMediaDecoder.cpp
    layanalyzer/rtp/core/RtpAudioRenderer.cpp
    layanalyzer/rtp/core/WavWriter.cpp
    layanalyzer/rtp/core/PeaksBuilder.cpp
    layanalyzer/rtp/core/FrameMapWriter.cpp
    layanalyzer/rtp/RtpDecodeRequest.cpp
    layanalyzer/rtp/codecs/G711.cpp
    layanalyzer/rtp/codecs/L16.cpp
    layanalyzer/rtp/codecs/G722.cpp
    # RTP4-NAT-02
    layanalyzer/rtp/codecs/G726.cpp
    # RTP4-NAT-03（G.729；整体在 #ifdef LAYANALYZER_ENABLE_G729 里，开关关闭时是空文件，
    # 但**必须**继续留在列表里，才能证明 OFF 配置也编得过）
    layanalyzer/rtp/codecs/G729.cpp
    # RTP4-NAT-08（iLBC；不设开关时是空翻译单元。与 G729.cpp 同理，**无条件**列出，
    # 这样默认的 OFF 构建也会编译到它，OFF 配置编得过本身就是证据）
    layanalyzer/rtp/codecs/ILBC.cpp
    # RTP4-NAT-04（AMR / AMR-WB 解包，纯标准库；消费方是 RTP4-NAT-06 的
    # extractRtpCodecFrames）
    layanalyzer/rtp/depack/AmrDepack.cpp
    # RTP5-NAT-01（H.264 解包，RFC 6184，纯标准库；消费方是 M5 的 exportRtpVideo）
    layanalyzer/rtp/depack/H264Depack.cpp
    # RTP5-NAT-02（H.265 解包，RFC 7798，纯标准库；与 H264Depack 同构，消费方同上）
    layanalyzer/rtp/depack/H265Depack.cpp
    # RTP5-NAT-03（访问单元组装 + Annex-B 输出，纯标准库；消费方是 M5 的
    # exportRtpVideo，输入是上面两个解包器给出的 NAL）
    layanalyzer/rtp/depack/VideoAccessUnitBuilder.cpp
    # RTP5-NAT-04（H.264/H.265 的 SPS 解析，纯标准库；消费方是 RTP5-NAT-05 的
    # exportRtpVideo，用它给出的 width/height/profile/level）
    layanalyzer/rtp/depack/SpsParser.cpp
    # RTP5-NAT-06（GB28181 的 PS 解复用，纯标准库；先把 RTP 负载重组成 PS 包，再把
    # 视频 ES 按 NAL 交给上面的 NAT-03。本卡只建模块，**不接线** jni/RtpJni.cpp，
    # 所以这一行是它目前唯一的消费方登记）
    layanalyzer/rtp/depack/PsDemux.cpp
    # RTP4-NAT-05（Ogg Opus 写出，纯标准库，不链接任何 Ogg/Opus 库；消费方是
    # RTP4-NAT-06 的 exportRtpContainer format="opus"）
    layanalyzer/rtp/io/OggOpusWriter.cpp
    # RTP4-NAT-06（`.fidx` 帧索引读写，纯标准库；消费方是同文件的
    # extractRtpCodecFrames / exportRtpContainer）
    layanalyzer/rtp/core/FidxFile.cpp
    # RTP5-NAT-03（`.vidx` 访问单元索引读写，纯标准库；消费方是 M5 的
    # exportRtpVideo，格式见 core/VidxFile.h）
    layanalyzer/rtp/core/VidxFile.cpp
    layanalyzer/rtp/codecs/RtpDecoderFactory.cpp
    layanalyzer/rtp/RtpStreamKeyEpan.cpp
    layanalyzer/rtp/RtpStreamCollector.cpp
    layanalyzer/rtp/RtpPayloadExtractor.cpp
    layanalyzer/rtp/RtpSetupInfo.cpp
    layanalyzer/projection/ByteFormatter.cpp
    layanalyzer/export/PcapWriter.cpp
)
add_library(${CMAKE_PROJECT_NAME} SHARED ${LAYANALYZER_SOURCES})

target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE cxx_std_17)

# [PERF-scan] 打点仅在 Debug 构建启用（native-lib.cpp 内的宏展开为空则无开销）
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE LA_PERF_SCAN=1)
endif()

# Include directories
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${INC_DIR}
    ${INC_DIR}/glib-2.0
    ${INC_DIR}/wireshark
)

find_library(log-lib log)

# Link libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
    ${log-lib}

    # Vendored spandsp subset (RTP4-BLD-01): G.722 / G.726
    spandsp_lite

    # Wireshark & Core
    wireshark
    wiretap
    wsutil
    
    # GLib
    gthread-2.0
    gobject-2.0
    gmodule-2.0
    glib-2.0
    
    # Dependencies
    cares
    gcrypt
    gpg-error
    pcre2-8
    ffi
    z
    iconv
)

# --- Vendored bcg729 (RTP4-BLD-02): G.729 / G.729A / G.729B ---
# GPL-3.0. Building it flips the conveyed licence of this library to GPL-3.0;
# see THIRD_PARTY_NOTICES.md and task_rtp_m4_codecs.md appendix A
# (RTP4-ARCH-01). LAYANALYZER_ENABLE_G729 therefore defaults to ON by decision,
# not by accident, and can be turned off with -PlayanalyzerEnableG729=false.
#
# The option is declared before the if() that reads it. The block itself sits
# after the main target's link list because it appends to that target.
#
# Both directories are required and they serve different consumers:
#   include/  the two public headers (bcg729/decoder.h, bcg729/encoder.h),
#             which consumers and src/typedef.h include as "bcg729/...".
#   src/      upstream keeps its 30 internal headers flat here and the sources
#             include them by bare name (#include "typedef.h"), so src/ must be
#             on the include path of bcg729's own translation units.
#
# BCG729_STATIC is PUBLIC on purpose, not PRIVATE: include/bcg729/decoder.h
# expands BCG729_VISIBILITY to __declspec(dllimport) on _WIN32 unless it is
# defined, and G729.cpp (RTP4-NAT-03) includes that header too, so the define
# has to reach consumers to keep the MSVC host build linkable. On Android/
# clang the non-Windows branch applies and it is a no-op. This differs from
# spandsp (RTP4-BLD-01), which has no static switch and had to overload
# LIBSPANDSP_EXPORTS instead.
#
# No config.h: src/typedef.h:24 is a plain `#ifdef HAVE_CONFIG_H` and nothing in
# src/ reads config.h.cmake's package metadata, so simply not defining
# HAVE_CONFIG_H skips it. See THIRD_PARTY_NOTICES.md
option(LAYANALYZER_ENABLE_G729 "Build the G.729 decoder (GPL-3.0)" ON)
if(LAYANALYZER_ENABLE_G729)
    add_library(bcg729 STATIC
        third_party/bcg729/src/LP2LSPConversion.c
        third_party/bcg729/src/LPSynthesisFilter.c
        third_party/bcg729/src/LSPQuantization.c
        third_party/bcg729/src/adaptativeCodebookSearch.c
        third_party/bcg729/src/cng.c
        third_party/bcg729/src/codebooks.c
        third_party/bcg729/src/computeAdaptativeCodebookGain.c
        third_party/bcg729/src/computeLP.c
        third_party/bcg729/src/computeWeightedSpeech.c
        third_party/bcg729/src/decodeAdaptativeCodeVector.c
        third_party/bcg729/src/decodeFixedCodeVector.c
        third_party/bcg729/src/decodeGains.c
        third_party/bcg729/src/decodeLSP.c
        third_party/bcg729/src/decoder.c
        third_party/bcg729/src/dtx.c
        third_party/bcg729/src/encoder.c
        third_party/bcg729/src/findOpenLoopPitchDelay.c
        third_party/bcg729/src/fixedCodebookSearch.c
        third_party/bcg729/src/gainQuantization.c
        third_party/bcg729/src/interpolateqLSP.c
        third_party/bcg729/src/postFilter.c
        third_party/bcg729/src/postProcessing.c
        third_party/bcg729/src/preProcessing.c
        third_party/bcg729/src/qLSP2LP.c
        third_party/bcg729/src/utils.c
        third_party/bcg729/src/vad.c)
    target_include_directories(bcg729
        PUBLIC third_party/bcg729/include
        PRIVATE third_party/bcg729/src)
    target_compile_definitions(bcg729 PUBLIC BCG729_STATIC)
    set_target_properties(bcg729 PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99
        C_STANDARD_REQUIRED ON)
    # Vendored code: warnings are not actionable here, and upstream sources
    # must stay unmodified. Errors still fail the build.
    if(MSVC)
        target_compile_options(bcg729 PRIVATE /W0)
    else()
        target_compile_options(bcg729 PRIVATE -w)
    endif()
    # Plain signature, not "PRIVATE bcg729": the main target's link list above
    # uses the plain signature throughout, and CMake rejects mixing the plain
    # and keyword forms on one target. Linking a SHARED library statically is
    # PUBLIC-equivalent either way, and this target has no further consumers.
    target_link_libraries(${CMAKE_PROJECT_NAME} bcg729)
    # Main-library translation units (G729.cpp, RTP4-NAT-03) #ifdef on this.
    # It must be absent, not 0, when the option is OFF.
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE LAYANALYZER_ENABLE_G729=1)
endif()

# --- Vendored libilbc subset (RTP4-NAT-08): iLBC ---
# WebRTC's libilbc (BSD-3; see third_party/libilbc/COPYING), a trimmed copy of
# the three upstream trees modules/audio_coding/codecs/ilbc/,
# common_audio/signal_processing/ and common_audio/third_party/spl_sqrt_floor/
# at the commit recorded in THIRD_PARTY_NOTICES.md. The CMake source lists specify
# every file that was kept and every one that was dropped, and the six shim
# headers written in place of the rtc_base/ and absl/ headers upstream expects.
#
# LAYANALYZER_ENABLE_ILBC defaults to **OFF**, unlike LAYANALYZER_ENABLE_G729.
# This card is optional, and OFF is deliberately the state that cannot affect
# anything else: with the option off the target is not created, no libilbc
# source is compiled, third_party/libilbc is not on any include path, and
# LAYANALYZER_ENABLE_ILBC is not defined -- so ILBC.cpp is an empty translation
# unit and RtpDecoderFactory.cpp never mentions "iLBC". The name then answers
# "unsupported" in a default build. Turn it on with
# -PlayanalyzerEnableIlbc=true.
#
# Licence: BSD-3-Clause, which is GPL-compatible in both directions, so enabling
# this option does NOT change the conveyed licence of the library the way
# bcg729 does (RTP4-ARCH-01). See THIRD_PARTY_NOTICES.md.
#
# The include root is third_party/libilbc itself, because the upstream sources
# include each other by repository-relative paths ("modules/audio_coding/
# codecs/ilbc/defines.h", "common_audio/signal_processing/include/
# signal_processing_library.h") and not one of them is edited to accommodate
# this build.
#
# rtc_base/system/arch.h is hand-written and defines nothing on purpose: with
# WEBRTC_HAS_NEON, WEBRTC_ARCH_ARM_V7/ARM64 and the x86 SSE2 selection all left
# undefined, common_audio/signal_processing takes its portable C paths on both
# Android ABIs and on the MSVC/clang/g++ host build. That removes the whole
# inline-assembly/SIMD surface -- the same trade the spandsp subset made
# (RTP4-BLD-01). See THIRD_PARTY_NOTICES.md
option(LAYANALYZER_ENABLE_ILBC "Build the iLBC decoder (BSD-3)" OFF)
if(LAYANALYZER_ENABLE_ILBC)
    # Every plain .c of modules/audio_coding/codecs/ilbc/, plus the
    # common_audio files the decoder actually reaches. The list is explicit, no
    # GLOB. dot_product_with_scale.cc is C++ upstream and is compiled as C++.
    add_library(ilibc STATIC
        third_party/libilbc/modules/audio_coding/codecs/ilbc/abs_quant.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/abs_quant_loop.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/augmented_cb_corr.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/bw_expand.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/cb_construct.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/cb_mem_energy.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/cb_mem_energy_augmentation.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/cb_mem_energy_calc.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/cb_search.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/cb_search_core.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/cb_update_best_index.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/chebyshev.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/comp_corr.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/constants.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/create_augmented_vec.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/decode.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/decode_residual.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/decoder_interpolate_lsf.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/do_plc.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/encode.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/energy_inverse.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/enh_upsample.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/enhancer.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/enhancer_interface.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/filtered_cb_vecs.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/frame_classify.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/gain_dequant.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/gain_quant.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/get_cd_vec.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/get_lsp_poly.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/get_sync_seq.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/hp_input.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/hp_output.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/ilbc.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/index_conv_dec.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/index_conv_enc.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/init_decode.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/init_encode.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/interpolate.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/interpolate_samples.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/lpc_encode.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/lsf_check.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/lsf_interpolate_to_poly_dec.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/lsf_interpolate_to_poly_enc.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/lsf_to_lsp.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/lsf_to_poly.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/lsp_to_lsf.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/my_corr.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/nearest_neighbor.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/pack_bits.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/poly_to_lsf.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/poly_to_lsp.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/refiner.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/simple_interpolate_lsf.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/simple_lpc_analysis.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/simple_lsf_dequant.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/simple_lsf_quant.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/smooth.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/smooth_out_data.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/sort_sq.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/split_vq.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/state_construct.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/state_search.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/swap_bytes.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/unpack_bits.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/vq3.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/vq4.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/window32_w32.c
        third_party/libilbc/modules/audio_coding/codecs/ilbc/xcorr_coef.c
        third_party/libilbc/common_audio/signal_processing/auto_correlation.c
        third_party/libilbc/common_audio/signal_processing/copy_set_operations.c
        third_party/libilbc/common_audio/signal_processing/cross_correlation.c
        third_party/libilbc/common_audio/signal_processing/division_operations.c
        third_party/libilbc/common_audio/signal_processing/dot_product_with_scale.cc
        third_party/libilbc/common_audio/signal_processing/downsample_fast.c
        third_party/libilbc/common_audio/signal_processing/filter_ar_fast_q12.c
        third_party/libilbc/common_audio/signal_processing/filter_ma_fast_q12.c
        third_party/libilbc/common_audio/signal_processing/ilbc_specific_functions.c
        third_party/libilbc/common_audio/signal_processing/levinson_durbin.c
        third_party/libilbc/common_audio/signal_processing/min_max_operations.c
        third_party/libilbc/common_audio/signal_processing/spl_inl.c
        third_party/libilbc/common_audio/signal_processing/spl_init.c
        third_party/libilbc/common_audio/signal_processing/vector_scaling_operations.c
        third_party/libilbc/common_audio/third_party/spl_sqrt_floor/spl_sqrt_floor.c)
    target_include_directories(ilibc PUBLIC third_party/libilbc)
    set_target_properties(ilibc PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
        CXX_STANDARD 14
        CXX_STANDARD_REQUIRED ON)
    # Vendored code: warnings are not actionable here, and upstream sources must
    # stay unmodified. Errors still fail the build.
    if(MSVC)
        target_compile_options(ilibc PRIVATE /W0)
    else()
        target_compile_options(ilibc PRIVATE -w)
    endif()
    # Plain signature, not "PRIVATE ilibc": the main target's link list above
    # uses the plain signature throughout, and CMake rejects mixing the plain
    # and keyword forms on one target (same reason as the bcg729 block).
    target_link_libraries(${CMAKE_PROJECT_NAME} ilibc)
    # Main-library translation units (ILBC.cpp, RtpDecoderFactory.cpp) #ifdef on
    # this. It must be absent, not 0, when the option is OFF.
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE LAYANALYZER_ENABLE_ILBC=1)
endif()

# 16KB page alignment for Android 15+
# 注意：为了通过 AGP 的兼容性检查，我们将 16KB 对齐恢复为始终开启
message(STATUS "Enabling 16KB page alignment")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,common-page-size=16384 -Wl,-z,max-page-size=16384")
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
        "-Wl,-z,common-page-size=16384"
        "-Wl,-z,max-page-size=16384"
)

# --- Live capture forwarding ---
# The forwarding stack is deliberately a separate shared library. It must not
# inherit the lifetime or global locks of the Wireshark JNI bridge above.
set(HEV_TUNNEL_DIR "${CMAKE_SOURCE_DIR}/third_party/hev-socks5-tunnel")
if(NOT EXISTS "${HEV_TUNNEL_DIR}/src/hev-main.h" OR
   NOT EXISTS "${HEV_TUNNEL_DIR}/third-part/lwip/src/include/lwip/init.h")
    message(FATAL_ERROR
        "hev-socks5-tunnel sources are missing. Obtain a complete LayerAnalyzer source archive.")
endif()

set(HEV_TASK_DIR "${HEV_TUNNEL_DIR}/third-part/hev-task-system")
set(HEV_LWIP_DIR "${HEV_TUNNEL_DIR}/third-part/lwip")
set(HEV_YAML_DIR "${HEV_TUNNEL_DIR}/third-part/yaml")

# Public headers are vendored as regular files. Put their wrappers first on
# the include path to avoid resolving a same-named private header.
set(HEV_TASK_PUBLIC_SOURCE_DIR "${HEV_TASK_DIR}/include")
set(HEV_TASK_PUBLIC_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/hev-task-public")
file(MAKE_DIRECTORY "${HEV_TASK_PUBLIC_INCLUDE_DIR}")
file(GLOB HEV_TASK_PUBLIC_HEADERS "${HEV_TASK_PUBLIC_SOURCE_DIR}/*.h")
foreach(HEV_TASK_PUBLIC_HEADER IN LISTS HEV_TASK_PUBLIC_HEADERS)
    get_filename_component(HEV_TASK_PUBLIC_NAME "${HEV_TASK_PUBLIC_HEADER}" NAME)
    get_filename_component(
        HEV_TASK_PUBLIC_TARGET_ABS
        "${HEV_TASK_PUBLIC_HEADER}"
        REALPATH
    )
    file(TO_CMAKE_PATH "${HEV_TASK_PUBLIC_TARGET_ABS}" HEV_TASK_PUBLIC_TARGET_ABS)
    file(WRITE
        "${HEV_TASK_PUBLIC_INCLUDE_DIR}/${HEV_TASK_PUBLIC_NAME}"
        "#include \"${HEV_TASK_PUBLIC_TARGET_ABS}\"\n"
    )
endforeach()

# HEV's public include directories are Git symlinks. On a standard Windows
# checkout they become text files containing relative paths, so use the real
# source header directories for every target instead.
file(GLOB_RECURSE HEV_TASK_HEADERS CONFIGURE_DEPENDS
    "${HEV_TASK_DIR}/src/*.h"
)
set(HEV_TASK_INCLUDE_DIRS "${HEV_TASK_DIR}/src")
foreach(HEV_TASK_HEADER IN LISTS HEV_TASK_HEADERS)
    get_filename_component(HEV_TASK_HEADER_DIR "${HEV_TASK_HEADER}" DIRECTORY)
    list(APPEND HEV_TASK_INCLUDE_DIRS "${HEV_TASK_HEADER_DIR}")
endforeach()
list(REMOVE_DUPLICATES HEV_TASK_INCLUDE_DIRS)

file(GLOB_RECURSE HEV_CORE_HEADERS CONFIGURE_DEPENDS
    "${HEV_TUNNEL_DIR}/src/core/src/*.h"
)
set(HEV_CORE_INCLUDE_DIRS "${HEV_TUNNEL_DIR}/src/core/src")
foreach(HEV_CORE_HEADER IN LISTS HEV_CORE_HEADERS)
    get_filename_component(HEV_CORE_HEADER_DIR "${HEV_CORE_HEADER}" DIRECTORY)
    list(APPEND HEV_CORE_INCLUDE_DIRS "${HEV_CORE_HEADER_DIR}")
endforeach()
list(REMOVE_DUPLICATES HEV_CORE_INCLUDE_DIRS)

file(GLOB_RECURSE HEV_TASK_SOURCES CONFIGURE_DEPENDS
    "${HEV_TASK_DIR}/src/*.c"
)
# The upstream build selects this preprocessed dispatcher rather than every
# architecture-specific lowercase .s file.
list(APPEND HEV_TASK_SOURCES "${HEV_TASK_DIR}/src/kern/task/hev-task-execute.S")

add_library(hev_task_system STATIC ${HEV_TASK_SOURCES})
set_target_properties(hev_task_system PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(hev_task_system PRIVATE
    ${HEV_TASK_INCLUDE_DIRS}
)
target_compile_definitions(hev_task_system PRIVATE
    ENABLE_STACK_OVERFLOW_DETECTION
    ENABLE_MEMALLOC_SLICE
    ENABLE_IO_SPLICE_SYSCALL
    CONFIG_STACK_BACKEND=STACK_MMAP
    CONFIG_STACK_OVERFLOW_DETECTION=1
    CONFIG_MEMALLOC_SLICE_ALIGN=64
    CONFIG_MEMALLOC_SLICE_MAX_SIZE=4096
    CONFIG_MEMALLOC_SLICE_MAX_COUNT=1000
    CONFIG_SCHED_CLOCK=CLOCK_NONE
)
target_compile_options(hev_task_system PRIVATE -fvisibility=hidden)

file(GLOB_RECURSE HEV_LWIP_SOURCES CONFIGURE_DEPENDS
    "${HEV_LWIP_DIR}/src/*.c"
)
add_library(hev_lwip STATIC ${HEV_LWIP_SOURCES})
set_target_properties(hev_lwip PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(hev_lwip PRIVATE
    "${HEV_LWIP_DIR}/src/include"
    "${HEV_LWIP_DIR}/src/ports/include"
)
target_compile_definitions(hev_lwip PRIVATE FD_SET_DEFINED SOCKLEN_T_DEFINED)

file(GLOB_RECURSE HEV_YAML_SOURCES CONFIGURE_DEPENDS
    "${HEV_YAML_DIR}/src/*.c"
)
add_library(hev_yaml STATIC ${HEV_YAML_SOURCES})
set_target_properties(hev_yaml PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(hev_yaml PRIVATE "${HEV_YAML_DIR}/src")
target_compile_definitions(hev_yaml PRIVATE
    YAML_VERSION_MAJOR=0
    YAML_VERSION_MINOR=2
    YAML_VERSION_PATCH=5
    YAML_VERSION_STRING="0.2.5"
)

file(GLOB_RECURSE HEV_TUNNEL_SOURCES CONFIGURE_DEPENDS
    "${HEV_TUNNEL_DIR}/src/*.c"
)
# The upstream JNI target has its own JNI_OnLoad and service contract. The app
# uses tunnel-jni.cpp instead, so keep the engine library free of that bridge.
list(FILTER HEV_TUNNEL_SOURCES EXCLUDE REGEX ".*/hev-jni\\.c$")

# HEV 2.15.0 leaves the lwIP netif MTU at zero when an external Android TUN fd
# is supplied. Generate a patched build copy so lwIP fragments responses to the
# MTU declared by VpnService.Builder instead of emitting multi-kilobyte packets.
set(HEV_TUNNEL_ENGINE_SOURCE "${HEV_TUNNEL_DIR}/src/hev-socks5-tunnel.c")
set(HEV_TUNNEL_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-hev")
set(HEV_TUNNEL_PATCHED_SOURCE "${HEV_TUNNEL_GENERATED_DIR}/hev-socks5-tunnel.c")
file(READ "${HEV_TUNNEL_ENGINE_SOURCE}" HEV_TUNNEL_SOURCE_BEFORE)
# file(READ) preserves the checkout's line endings. Normalize the build-local
# copy so this patch also works with Git's default CRLF checkout on Windows.
string(REPLACE "\r\n" "\n" HEV_TUNNEL_SOURCE_BEFORE "${HEV_TUNNEL_SOURCE_BEFORE}")
set(HEV_NETIF_INIT_ORIGINAL [=[static err_t
netif_init_handler (struct netif *netif)
{
    netif->output = netif_output_v4_handler;]=])
set(HEV_NETIF_INIT_PATCHED [=[static err_t
netif_init_handler (struct netif *netif)
{
    netif->mtu = (u16_t)hev_config_get_tunnel_mtu ();
    netif->output = netif_output_v4_handler;]=])
string(REPLACE
    "${HEV_NETIF_INIT_ORIGINAL}"
    "${HEV_NETIF_INIT_PATCHED}"
    HEV_TUNNEL_SOURCE_AFTER
    "${HEV_TUNNEL_SOURCE_BEFORE}"
)
if(HEV_TUNNEL_SOURCE_AFTER STREQUAL HEV_TUNNEL_SOURCE_BEFORE)
    message(FATAL_ERROR "Unable to apply the HEV 2.15.0 Android MTU patch.")
endif()
file(MAKE_DIRECTORY "${HEV_TUNNEL_GENERATED_DIR}")
file(WRITE "${HEV_TUNNEL_PATCHED_SOURCE}" "${HEV_TUNNEL_SOURCE_AFTER}")
list(REMOVE_ITEM HEV_TUNNEL_SOURCES "${HEV_TUNNEL_ENGINE_SOURCE}")
list(APPEND HEV_TUNNEL_SOURCES "${HEV_TUNNEL_PATCHED_SOURCE}")

add_library(hev_socks5_tunnel STATIC ${HEV_TUNNEL_SOURCES})
set_target_properties(hev_socks5_tunnel PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(hev_socks5_tunnel PRIVATE
    "${HEV_TASK_PUBLIC_INCLUDE_DIR}"
    "${HEV_TUNNEL_DIR}/src"
    "${HEV_TUNNEL_DIR}/src/misc"
    ${HEV_CORE_INCLUDE_DIRS}
    "${HEV_YAML_DIR}/src"
    "${HEV_LWIP_DIR}/src/include"
    "${HEV_LWIP_DIR}/src/ports/include"
    ${HEV_TASK_INCLUDE_DIRS}
)
target_compile_definitions(hev_socks5_tunnel PRIVATE
    ENABLE_LIBRARY
    FD_SET_DEFINED
    SOCKLEN_T_DEFINED
    COMMIT_ID="2.15.0"
)
target_link_libraries(hev_socks5_tunnel PUBLIC
    hev_yaml
    hev_lwip
    hev_task_system
)

add_library(layanalyzer_tunnel SHARED
    tunnel-jni.cpp
)
target_compile_features(layanalyzer_tunnel PRIVATE cxx_std_17)
target_include_directories(layanalyzer_tunnel PRIVATE
    "${HEV_TASK_PUBLIC_INCLUDE_DIR}"
)
target_link_libraries(layanalyzer_tunnel PRIVATE
    ${log-lib}
    hev_socks5_tunnel
)
target_link_options(layanalyzer_tunnel PRIVATE
    "-Wl,-z,common-page-size=16384"
    "-Wl,-z,max-page-size=16384"
)
