// Shim for upstream rtc_base/system/arch.h.
//
// Upstream selects the SIMD/architecture path here (WEBRTC_HAS_NEON,
// WEBRTC_ARCH_ARM_V7/ARM64, the x86 SSE2 build flag, WEBRTC_ARCH_BIG_ENDIAN,
// ...) from RTC_ARCH_* / RTC_TARGET_* values the WebRTC build system defines.
// LayerAnalyzer deliberately defines none of them, which forces the portable C
// paths in common_audio/signal_processing on both the Android ABIs and the
// MSVC/clang/g++ host build. The file exists only so that upstream sources
// which include it keep resolving; it intentionally defines nothing.
#ifndef RTC_BASE_SYSTEM_ARCH_H_
#define RTC_BASE_SYSTEM_ARCH_H_
#endif  // RTC_BASE_SYSTEM_ARCH_H_
