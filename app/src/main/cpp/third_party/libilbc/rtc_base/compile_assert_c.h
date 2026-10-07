// Shim for upstream rtc_base/compile_assert_c.h.
//
// Provides RTC_COMPILE_ASSERT(expr) for C translation units (spl_inl.h uses it,
// and spl_inl.h is included from .c files). The typedef name is built from
// __LINE__ because spl_inl.h uses the macro twice in one translation unit.
#ifndef RTC_BASE_COMPILE_ASSERT_C_H_
#define RTC_BASE_COMPILE_ASSERT_C_H_

#define RTC_SHIM_CAT_(a, b) a##b
#define RTC_SHIM_CAT(a, b) RTC_SHIM_CAT_(a, b)

#define RTC_COMPILE_ASSERT(expr) \
  typedef char RTC_SHIM_CAT(rtc_compile_assert_, __LINE__)[(expr) ? 1 : -1]

#endif  // RTC_BASE_COMPILE_ASSERT_C_H_
