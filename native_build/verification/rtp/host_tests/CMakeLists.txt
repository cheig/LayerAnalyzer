# RTP host 单测工程（RTP1-ARCH-03）
#
# 目的：让 app/src/main/cpp/layanalyzer/rtp/ 下**不依赖 epan** 的纯算法代码（core/、codecs/、
# depack/、io/）能在开发机上直接编译并跑单测 —— 不需要 Android 设备、NDK 或 Gradle。
#
# 用法：..\run_host_tests.ps1 [-Test "RtpStreamKey*"] [-Clean]
# 说明：..\..\README.md 的「RTP 纯算法 host 单测」一节

cmake_minimum_required(VERSION 3.22)

# C 也是必需的：RTP4-BLD-01 引入的 spandsp 子集是 C 源码。
project(rtp_host_tests LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 与 Android 构建相同的头文件根：源码里写成 #include "layanalyzer/rtp/core/xxx.h"。
get_filename_component(RTP_CPP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../app/src/main/cpp" ABSOLUTE)

# RTP4-BLD-01：spandsp 子集（G.722 / G.726 / bitstream）。第三方 C 源码，
# 与 app/src/main/cpp/CMakeLists.txt 里的 spandsp_lite 是同一份文件。
# RTP4-NAT-01 / RTP4-NAT-02 的解码器把它链进 host 测试可执行文件。
set(SPANDSP_LITE_ROOT "${RTP_CPP_ROOT}/third_party/spandsp-lite")

# RTP4-BLD-02：bcg729（G.729 / G.729A / G.729B）。同样是第三方 C 源码，与
# app/src/main/cpp/CMakeLists.txt 里的 bcg729 静态库是同一份文件。
# RTP4-NAT-03 的解码器把它链进 host 测试可执行文件。
set(BCG729_ROOT "${RTP_CPP_ROOT}/third_party/bcg729")

# RTP4-NAT-08：WebRTC 的 libilbc 子集（iLBC）。第三方 C/C++ 源码，与
# app/src/main/cpp/CMakeLists.txt 里的 ilibc 静态库是同一份文件。
# RTP4-NAT-08 的解码器把它链进 host 测试可执行文件。
# 包含根就是它自己：上游源码按仓库相对路径互相引用（"modules/audio_coding/
# codecs/ilbc/defines.h"、"common_audio/signal_processing/include/
# signal_processing_library.h"），这样一行上游代码都不用改。
set(LIBILBC_ROOT "${RTP_CPP_ROOT}/third_party/libilbc")

# RTP4-BLD-02：G.729 的编译开关。默认值由 RTP4-ARCH-01 决定（ON），与 Android
# 构建的 option(LAYANALYZER_ENABLE_G729 ...) 保持一致；不要改成 OFF。
# 关闭时 G.729 的解码器不参与编译，RTP4-NAT-03 的 host 用例按卡片用 #ifdef 跳过
# 并打印一条 doctest 的 WARN —— 所以这个宏必须是**目标级**定义，不能只加在
# bcg729 的那 26 个 .c 上（那些文件根本不看它，看它的是 G729.cpp / G729Test.cpp）。
option(LAYANALYZER_ENABLE_G729 "Build the G.729 decoder (GPL-3.0)" ON)

# RTP4-NAT-08：iLBC 的编译开关，**默认 OFF**（与 G.729 不同，因为这张卡是可选的，
# 而且 OFF 必须是「不会影响其它任何东西」的那一侧）。与 Android 构建的
# option(LAYANALYZER_ENABLE_ILBC ... OFF) 保持一致，不要改成 ON。
# 打开：-DLAYANALYZER_ENABLE_ILBC=ON。关闭时 ILBC.cpp 变成一个空翻译单元，
# RtpDecoderFactory.cpp 里 "iLBC" 这个名字完全不存在，ILBCTest.cpp 按 #ifdef 跳过
# 并打印 WARN —— 同样必须是**目标级**定义。
option(LAYANALYZER_ENABLE_ILBC "Build the iLBC decoder (BSD-3)" OFF)

# ---------------------------------------------------------------------------
# 源文件列表 —— 显式列出，不用 GLOB；后续任务按卡片往列表里加一行。
# ---------------------------------------------------------------------------

# 被测的生产代码。只允许 layanalyzer/rtp/ 下的纯算法文件：core/、codecs/、depack/、io/，
# 以及明确保持纯标准库的请求解析器 RtpDecodeRequest.cpp。
# 下面这些**不能**进来（依赖 epan / GLib / JNI，host 上编不过）：
#   layanalyzer/jni/、layanalyzer/session/、
#   layanalyzer/rtp/RtpStreamCollector.cpp、layanalyzer/rtp/RtpStreamKeyEpan.cpp
# 唯一的例外是列表末尾 RTP4-BLD-01 的第三方 C 文件（spandsp 子集），
# 它们同样不依赖 epan / GLib / JNI。
set(RTP_HOST_SOURCES
    # RTP1-NAT-01
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/RtpStreamKey.cpp
    # RTP1-NAT-02
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/RtpStreamAnalysis.cpp
    # RTP1-NAT-06（RtpPayloadOverrides.h 是 header-only，没有 .cpp 要加）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/RtpCodecNames.cpp
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/RtpDecodability.cpp
    # RTP3-NAT-03
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/DtmfParser.cpp
    # RTP2-NAT-03
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/RtpMediaDecoder.cpp
    # RTP2-NAT-04
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/RtpAudioRenderer.cpp
    # RTP2-NAT-05
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/WavWriter.cpp
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/PeaksBuilder.cpp
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/FrameMapWriter.cpp
    # RTP2-NAT-06
    ${RTP_CPP_ROOT}/layanalyzer/rtp/RtpDecodeRequest.cpp
    # RTP2-NAT-01
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/RtppFile.cpp
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/RtppIndex.cpp
    # RTP2-NAT-02
    ${RTP_CPP_ROOT}/layanalyzer/rtp/codecs/G711.cpp
    ${RTP_CPP_ROOT}/layanalyzer/rtp/codecs/L16.cpp
    ${RTP_CPP_ROOT}/layanalyzer/rtp/codecs/RtpDecoderFactory.cpp
    # RTP4-NAT-01（G.722 的算法来自下面的 spandsp 子集）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/codecs/G722.cpp
    # RTP4-NAT-02（G.726；同样链接下面的 spandsp 子集）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/codecs/G726.cpp
    # RTP4-NAT-03（G.729；链接下面 if(LAYANALYZER_ENABLE_G729) 里的 bcg729）。
    # 本文件无条件参与编译：开关关闭时它的全部内容都在 #ifdef 里，变成一个空
    # 翻译单元 —— 这正是「OFF 配置也编得过」的证据，所以不要把它挪进 if() 里。
    ${RTP_CPP_ROOT}/layanalyzer/rtp/codecs/G729.cpp
    # RTP4-NAT-08（iLBC；链接下面 if(LAYANALYZER_ENABLE_ILBC) 里的 ilibc 源码）。
    # 同样无条件参与编译：开关关闭时它的全部内容都在 #ifdef 里，变成一个空翻译
    # 单元 —— OFF 构建因此也会编译到它。
    ${RTP_CPP_ROOT}/layanalyzer/rtp/codecs/ILBC.cpp
    # RTP4-NAT-04（AMR / AMR-WB 解包；纯 bit 操作，不链接任何编解码库）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/depack/AmrDepack.cpp
    # RTP5-NAT-01（H.264 解包，RFC 6184；同样纯标准库，不链接任何编解码库）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/depack/H264Depack.cpp
    # RTP5-NAT-02（H.265 解包，RFC 7798；同样纯标准库，不链接任何编解码库）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/depack/H265Depack.cpp
    # RTP5-NAT-03（访问单元组装 / Annex-B 输出；同样纯标准库，NAT-01/NAT-02 的输出
    # 是它的输入）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/depack/VideoAccessUnitBuilder.cpp
    # RTP5-NAT-04（SPS 解析；同样纯标准库，位读取器 + exp-Golomb，不链接任何库）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/depack/SpsParser.cpp
    # RTP5-NAT-06（GB28181 的 PS 解复用：PS 包重组 + pack/system header + PSM + PES
    # → NAL，同样纯标准库，不链接任何库）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/depack/PsDemux.cpp
    # RTP4-NAT-05（Ogg Opus 写出；纯标准库，不链接任何 Ogg/Opus 库）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/io/OggOpusWriter.cpp
    # RTP4-NAT-06（`.fidx` 帧索引读写；纯标准库，消费方是 jni/RtpJni.cpp 的两个入口）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/FidxFile.cpp
    # RTP5-NAT-03（`.vidx` 访问单元索引读写；纯标准库，与 FidxFile 同一套「逐字段
    # 小端读写 + 失败即删」的写法，消费方是 M5 的 exportRtpVideo / KT-01 / KT-03）
    ${RTP_CPP_ROOT}/layanalyzer/rtp/core/VidxFile.cpp
    # RTP4-BLD-01（第三方 C 源码，见上面 SPANDSP_LITE_ROOT 的说明）
    ${SPANDSP_LITE_ROOT}/src/g722.c
    ${SPANDSP_LITE_ROOT}/src/g726.c
    ${SPANDSP_LITE_ROOT}/src/bitstream.c
    # g722/g726/bitstream 引用 span_alloc()/span_free()/vec_circular_dot_prodi16()，
    # 只编那三个 .c 会在链接期报 undefined reference。
    ${SPANDSP_LITE_ROOT}/src/alloc.c
    ${SPANDSP_LITE_ROOT}/src/vector_int.c
)

# RTP4-BLD-02：bcg729 的全部 26 个 .c（显式列出，不用 GLOB）。开关关闭时
# 这个列表为空，一个都不编，与 Android 构建一致地"没有 G.729"。
# RTP4-NAT-03 的 G729.cpp / G729Test.cpp 不在这个列表里：它们无条件编进目标，
# 用 #ifdef LAYANALYZER_ENABLE_G729 把自己变成空翻译单元（见上面 RTP_HOST_SOURCES
# 与下面 RTP_HOST_TEST_SOURCES 的登记处），OFF 构建因此也会编译到它们。
# 列表在下面 set_source_files_properties 处还要用一次，所以放进具名变量而不是
# 直接写进 APPEND（if() 不引入作用域，变量在文件后段仍然可见）。
if(LAYANALYZER_ENABLE_G729)
    set(RTP_HOST_BCG729_SOURCES
        ${BCG729_ROOT}/src/LP2LSPConversion.c
        ${BCG729_ROOT}/src/LPSynthesisFilter.c
        ${BCG729_ROOT}/src/LSPQuantization.c
        ${BCG729_ROOT}/src/adaptativeCodebookSearch.c
        ${BCG729_ROOT}/src/cng.c
        ${BCG729_ROOT}/src/codebooks.c
        ${BCG729_ROOT}/src/computeAdaptativeCodebookGain.c
        ${BCG729_ROOT}/src/computeLP.c
        ${BCG729_ROOT}/src/computeWeightedSpeech.c
        ${BCG729_ROOT}/src/decodeAdaptativeCodeVector.c
        ${BCG729_ROOT}/src/decodeFixedCodeVector.c
        ${BCG729_ROOT}/src/decodeGains.c
        ${BCG729_ROOT}/src/decodeLSP.c
        ${BCG729_ROOT}/src/decoder.c
        ${BCG729_ROOT}/src/dtx.c
        ${BCG729_ROOT}/src/encoder.c
        ${BCG729_ROOT}/src/findOpenLoopPitchDelay.c
        ${BCG729_ROOT}/src/fixedCodebookSearch.c
        ${BCG729_ROOT}/src/gainQuantization.c
        ${BCG729_ROOT}/src/interpolateqLSP.c
        ${BCG729_ROOT}/src/postFilter.c
        ${BCG729_ROOT}/src/postProcessing.c
        ${BCG729_ROOT}/src/preProcessing.c
        ${BCG729_ROOT}/src/qLSP2LP.c
        ${BCG729_ROOT}/src/utils.c
        ${BCG729_ROOT}/src/vad.c
    )
    list(APPEND RTP_HOST_SOURCES ${RTP_HOST_BCG729_SOURCES})
endif()

# RTP4-NAT-08：libilbc 的全部 84 个源文件（显式列出，不用 GLOB）。开关关闭时
# 这个列表为空，一个都不编，与 Android 构建一致地「没有 iLBC」。
# ILBC.cpp / ILBCTest.cpp 不在这个列表里：它们无条件编进目标，用
# #ifdef LAYANALYZER_ENABLE_ILBC 把自己变成空翻译单元。
# 列表在下面 set_source_files_properties 处还要用一次，所以放进具名变量。
#
# 其中 dot_product_with_scale.cc 是 C++（上游如此），其余是 C；host 工程的
# project(... LANGUAGES C CXX) 已经两种都启用，CMake 会按扩展名挑编译器。
if(LAYANALYZER_ENABLE_ILBC)
    set(RTP_HOST_ILBC_SOURCES
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/abs_quant.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/abs_quant_loop.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/augmented_cb_corr.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/bw_expand.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/cb_construct.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/cb_mem_energy.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/cb_mem_energy_augmentation.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/cb_mem_energy_calc.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/cb_search.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/cb_search_core.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/cb_update_best_index.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/chebyshev.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/comp_corr.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/constants.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/create_augmented_vec.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/decode.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/decode_residual.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/decoder_interpolate_lsf.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/do_plc.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/encode.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/energy_inverse.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/enh_upsample.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/enhancer.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/enhancer_interface.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/filtered_cb_vecs.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/frame_classify.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/gain_dequant.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/gain_quant.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/get_cd_vec.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/get_lsp_poly.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/get_sync_seq.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/hp_input.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/hp_output.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/ilbc.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/index_conv_dec.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/index_conv_enc.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/init_decode.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/init_encode.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/interpolate.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/interpolate_samples.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/lpc_encode.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/lsf_check.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/lsf_interpolate_to_poly_dec.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/lsf_interpolate_to_poly_enc.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/lsf_to_lsp.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/lsf_to_poly.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/lsp_to_lsf.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/my_corr.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/nearest_neighbor.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/pack_bits.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/poly_to_lsf.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/poly_to_lsp.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/refiner.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/simple_interpolate_lsf.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/simple_lpc_analysis.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/simple_lsf_dequant.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/simple_lsf_quant.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/smooth.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/smooth_out_data.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/sort_sq.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/split_vq.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/state_construct.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/state_search.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/swap_bytes.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/unpack_bits.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/vq3.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/vq4.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/window32_w32.c
        ${LIBILBC_ROOT}/modules/audio_coding/codecs/ilbc/xcorr_coef.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/auto_correlation.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/copy_set_operations.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/cross_correlation.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/division_operations.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/dot_product_with_scale.cc
        ${LIBILBC_ROOT}/common_audio/signal_processing/downsample_fast.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/filter_ar_fast_q12.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/filter_ma_fast_q12.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/ilbc_specific_functions.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/levinson_durbin.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/min_max_operations.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/spl_inl.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/spl_init.c
        ${LIBILBC_ROOT}/common_audio/signal_processing/vector_scaling_operations.c
        ${LIBILBC_ROOT}/common_audio/third_party/spl_sqrt_floor/spl_sqrt_floor.c
    )
    list(APPEND RTP_HOST_SOURCES ${RTP_HOST_ILBC_SOURCES})
endif()

# 测试源文件：各任务的用例放 lib/ 下。
set(RTP_HOST_TEST_SOURCES
    # doctest 的 main() + 工程冒烟用例，勿删。
    ${CMAKE_CURRENT_SOURCE_DIR}/test_main.cpp
    # RTP1-NAT-01
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpStreamKeyTest.cpp
    # RTP1-NAT-02
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpStreamAnalysisTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpStreamPayloadEvidenceTest.cpp
    # RTP1-NAT-06
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpCodecNamesTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpDecodabilityTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpPayloadOverridesTest.cpp
    # RTP2-NAT-01
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtppFileTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtppIndexTest.cpp
    # RTP2-NAT-02
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/G711Test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/L16Test.cpp
    # RTP2-NAT-03
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpMediaDecoderTest.cpp
    # RTP4-NAT-01
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/G722Test.cpp
    # RTP4-NAT-02
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/G726Test.cpp
    # RTP4-NAT-03（OFF 构建里用例按 #ifdef 跳过并打印 doctest 的 WARN）
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/G729Test.cpp
    # RTP4-NAT-08（同上；OFF 是默认值，所以这条路径才是常见的那条）
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/ILBCTest.cpp
    # RTP4-NAT-04
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/AmrDepackTest.cpp
    # RTP5-NAT-01
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/H264DepackTest.cpp
    # RTP5-NAT-02
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/H265DepackTest.cpp
    # RTP5-NAT-03
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/VideoAccessUnitBuilderTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/VidxFileTest.cpp
    # RTP5-NAT-04
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/SpsParserTest.cpp
    # RTP5-NAT-06
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/PsDemuxTest.cpp
    # RTP4-NAT-05
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/OggOpusWriterTest.cpp
    # RTP4-NAT-06
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/FidxFileTest.cpp
    # RTP2-NAT-04
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpAudioRendererTest.cpp
    # RTP3-NAT-02
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/StereoMixTest.cpp
    # RTP3-NAT-03
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/DtmfParserTest.cpp
    # RTP2-NAT-05
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/OutputFilesTest.cpp
    # RTP2-NAT-06
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/RtpDecodeRequestTest.cpp
)

if(NOT RTP_HOST_SOURCES)
    # 保持 ASCII：CMake 的输出编码与 Windows 控制台代码页不一致时会乱码。
    message(STATUS "RTP_HOST_SOURCES is empty: only test sources are compiled (RTP1-ARCH-03)")
endif()

add_executable(rtp_host_tests ${RTP_HOST_TEST_SOURCES} ${RTP_HOST_SOURCES})

# doctest 是第三方头文件，用 SYSTEM 引入，避免它的告警污染我们自己的 -Wall -Wextra。
target_include_directories(rtp_host_tests SYSTEM PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(rtp_host_tests PRIVATE "${RTP_CPP_ROOT}")
# RTP4-BLD-01：spandsp 子集的 include 根。include/ 下同时放着 spandsp/、
# spandsp/private/ 和 floating_fudge.h，源文件按 "spandsp/private/g722.h"、
# "floating_fudge.h" 引用它们。
target_include_directories(rtp_host_tests PRIVATE "${SPANDSP_LITE_ROOT}/include")

# RTP4-BLD-01：宏与告警抑制只作用于 spandsp 的那几个第三方源文件，不污染本仓库自己的源码。
#   HAVE_CONFIG_H=1     源文件里是 #if defined(HAVE_CONFIG_H)（只判断宏是否存在），
#                       所以必须同时提供 include/config.h；与 Android 构建保持一致。
#   __inline__=__inline 上游用的是 GCC 的拼写，MSVC 只认识 __inline。
#   LIBSPANDSP_EXPORTS  否则 telephony.h 在 Windows 上把 SPAN_DECLARE 展开成
#                       __declspec(dllimport)，定义这些函数时报 C2491。
set(RTP_HOST_SPANDSP_DEFINITIONS HAVE_CONFIG_H=1)
set(RTP_HOST_SPANDSP_OPTIONS -w)
if(MSVC)
    list(APPEND RTP_HOST_SPANDSP_DEFINITIONS __inline__=__inline LIBSPANDSP_EXPORTS)
    set(RTP_HOST_SPANDSP_OPTIONS /W0)
    # MSVC 没有 <sys/time.h>：alloc.c 无条件包含它，却一行都没用到。像上面
    # hev 的符号链接头一样，在构建目录里生成一个只包含 <time.h> 的兼容头，
    # 并且只加给 spandsp 的源文件（加在 include/ 里会遮蔽真正的系统头）。
    set(SPANDSP_LITE_MSVC_SHIM_DIR "${CMAKE_CURRENT_BINARY_DIR}/spandsp-msvc-shim")
    file(MAKE_DIRECTORY "${SPANDSP_LITE_MSVC_SHIM_DIR}/sys")
    file(WRITE "${SPANDSP_LITE_MSVC_SHIM_DIR}/sys/time.h"
"/* Generated by host_tests/CMakeLists.txt (RTP4-BLD-01).
   MSVC has no <sys/time.h>; spandsp's alloc.c includes it unconditionally
   but uses nothing from it. */
#ifndef SPANDSP_LITE_MSVC_SYS_TIME_H
#define SPANDSP_LITE_MSVC_SYS_TIME_H
#include <time.h>
#endif
")
    list(APPEND RTP_HOST_SPANDSP_OPTIONS "-I${SPANDSP_LITE_MSVC_SHIM_DIR}")
endif()
set(RTP_HOST_SPANDSP_SOURCES
    "${SPANDSP_LITE_ROOT}/src/g722.c"
    "${SPANDSP_LITE_ROOT}/src/g726.c"
    "${SPANDSP_LITE_ROOT}/src/bitstream.c"
    "${SPANDSP_LITE_ROOT}/src/alloc.c"
    "${SPANDSP_LITE_ROOT}/src/vector_int.c")
set_source_files_properties(${RTP_HOST_SPANDSP_SOURCES} PROPERTIES
    COMPILE_DEFINITIONS "${RTP_HOST_SPANDSP_DEFINITIONS}"
    COMPILE_OPTIONS "${RTP_HOST_SPANDSP_OPTIONS}")

# RTP4-BLD-02：bcg729 的包含路径、宏与告警抑制。
#
# 作用域是刻意分开的：
#   include/  放在**目标级**，和上面 spandsp 的 include/ 一样。RTP4-NAT-03 的
#             G729.cpp（生产代码）和 G729Test.cpp 都要 #include "bcg729/decoder.h"，
#             它们属于这个 target，只加在第三方源文件上它们就找不到头文件。
#   src/      只加给 bcg729 自己的 26 个 .c。上游把内部头文件平铺在 src/ 下并用
#             裸文件名引用（#include "typedef.h"），而 typedef.h / utils.h 这类名字
#             太通用，放进目标级的包含路径会平白增加遮蔽风险。
#   宏        BCG729_STATIC 和 LAYANALYZER_ENABLE_G729=1 都是**目标级**，原因同上：
#             前者给消费方（decoder.h 在 _WIN32 上不定义它就展开成
#             __declspec(dllimport)，G729.cpp 也会包含这个头文件），后者给
#             G729.cpp / G729Test.cpp 的 #ifdef。加在 26 个 .c 上是无效的 ——
#             那些文件根本不看这两个宏。
#   config.h  不需要：只有 src/typedef.h 有一处 `#ifdef HAVE_CONFIG_H`，不定义
#             这个宏即可跳过；src/ 里没有任何文件读 config.h.cmake 的包元数据。
#             与 Android 构建保持一致。详见 THIRD_PARTY_NOTICES.md。
if(LAYANALYZER_ENABLE_G729)
    target_include_directories(rtp_host_tests PRIVATE "${BCG729_ROOT}/include")
    target_compile_definitions(rtp_host_tests PRIVATE
        BCG729_STATIC
        LAYANALYZER_ENABLE_G729=1)

    if(MSVC)
        set(RTP_HOST_BCG729_OPTIONS /W0)
    else()
        set(RTP_HOST_BCG729_OPTIONS -w)
    endif()
    # -I 而不是 INCLUDE_DIRECTORIES：与上面 spandsp 的 shim 写法一致，cl 也认 -I。
    list(APPEND RTP_HOST_BCG729_OPTIONS "-I${BCG729_ROOT}/src")
    set_source_files_properties(${RTP_HOST_BCG729_SOURCES} PROPERTIES
        COMPILE_OPTIONS "${RTP_HOST_BCG729_OPTIONS}")
endif()

# RTP4-NAT-08：libilbc 的包含路径、宏与告警抑制。
#
# 作用域与上面 bcg729 的理由相同，只有包含根这一处不同：
#   third_party/libilbc  放在**目标级**，因为上游源码按仓库相对路径互相引用，而且
#                        ILBC.cpp（生产代码）要 #include
#                        "modules/audio_coding/codecs/ilbc/ilbc.h"。这里没有 bcg729
#                        那种「内部头文件平铺、按裸名引用」的问题（libilbc 的头文件
#                        都带完整相对路径），所以只需要这一个包含根。
#   LAYANALYZER_ENABLE_ILBC=1 是**目标级**，给 ILBC.cpp / RtpDecoderFactory.cpp /
#                        ILBCTest.cpp 的 #ifdef 用；加在那 84 个源文件上是无效的。
#   告警抑制              只作用于这 84 个第三方文件（-w / MSVC 的 /W0），不放宽
#                        整个 target。
if(LAYANALYZER_ENABLE_ILBC)
    target_include_directories(rtp_host_tests PRIVATE "${LIBILBC_ROOT}")
    target_compile_definitions(rtp_host_tests PRIVATE LAYANALYZER_ENABLE_ILBC=1)

    if(MSVC)
        set(RTP_HOST_ILBC_OPTIONS /W0)
    else()
        set(RTP_HOST_ILBC_OPTIONS -w)
    endif()
    set_source_files_properties(${RTP_HOST_ILBC_SOURCES} PROPERTIES
        COMPILE_OPTIONS "${RTP_HOST_ILBC_OPTIONS}")
endif()

if(MSVC)
    # /utf-8：用例注释里有中文，MSVC 默认按系统代码页（936）解析源码会乱码。
    target_compile_options(rtp_host_tests PRIVATE /W4 /utf-8)
else()
    target_compile_options(rtp_host_tests PRIVATE -Wall -Wextra)
endif()

# 产物固定放在构建目录根，脚本按 rtp_host_tests[.exe] 找它。
set_target_properties(rtp_host_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
