// Shim for upstream rtc_base/sanitizer.h.
//
// Upstream defines RTC_NO_SANITIZE plus the ASan/MSan memory-range helpers
// (rtc_AsanPoison, rtc_AsanUnpoison, rtc_MsanMarkUninitialized,
// rtc_MsanCheckInitialized). Only RTC_NO_SANITIZE and rtc_MsanCheckInitialized
// are referenced by the vendored sources. This shim reproduces upstream's
// non-sanitizer branch: the helpers exist and do nothing, exactly as they do
// upstream when neither ASan nor MSan is enabled (which is the case for both
// the Android build and the host test build).
#ifndef RTC_BASE_SANITIZER_H_
#define RTC_BASE_SANITIZER_H_

#include <stddef.h>

#ifdef __has_attribute
#if __has_attribute(no_sanitize)
#define RTC_NO_SANITIZE(what) __attribute__((no_sanitize(what)))
#endif
#endif
#ifndef RTC_NO_SANITIZE
#define RTC_NO_SANITIZE(what)
#endif

static inline void rtc_AsanPoison(const volatile void* ptr,
                                  size_t element_size,
                                  size_t num_elements) {
  (void)ptr;
  (void)element_size;
  (void)num_elements;
}

static inline void rtc_AsanUnpoison(const volatile void* ptr,
                                    size_t element_size,
                                    size_t num_elements) {
  (void)ptr;
  (void)element_size;
  (void)num_elements;
}

static inline void rtc_MsanMarkUninitialized(const volatile void* ptr,
                                             size_t element_size,
                                             size_t num_elements) {
  (void)ptr;
  (void)element_size;
  (void)num_elements;
}

static inline void rtc_MsanCheckInitialized(const volatile void* ptr,
                                            size_t element_size,
                                            size_t num_elements) {
  (void)ptr;
  (void)element_size;
  (void)num_elements;
}

#endif  // RTC_BASE_SANITIZER_H_
