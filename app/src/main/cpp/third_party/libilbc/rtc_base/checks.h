// Shim for upstream rtc_base/checks.h.
//
// Only the two macro families that the vendored sources use are provided.
// Upstream's real header builds on rtc_base/logging.h and rtc_base/strings;
// none of that is reachable from the code we compile.
//
// Semantics follow upstream: RTC_CHECK is always live, RTC_DCHECK is compiled
// out under NDEBUG (a release build) and live otherwise. Both abort on failure;
// there is no logging facility to report through here.
#ifndef RTC_BASE_CHECKS_H_
#define RTC_BASE_CHECKS_H_

#include <stdlib.h>

#define RTC_SHIM_CHECK_IMPL(condition)  \
  do {                                  \
    if (!(condition)) {                 \
      abort();                          \
    }                                   \
  } while (0)

#define RTC_CHECK(condition) RTC_SHIM_CHECK_IMPL(condition)
#define RTC_CHECK_EQ(a, b) RTC_SHIM_CHECK_IMPL((a) == (b))
#define RTC_CHECK_NE(a, b) RTC_SHIM_CHECK_IMPL((a) != (b))
#define RTC_CHECK_LT(a, b) RTC_SHIM_CHECK_IMPL((a) < (b))
#define RTC_CHECK_LE(a, b) RTC_SHIM_CHECK_IMPL((a) <= (b))
#define RTC_CHECK_GT(a, b) RTC_SHIM_CHECK_IMPL((a) > (b))
#define RTC_CHECK_GE(a, b) RTC_SHIM_CHECK_IMPL((a) >= (b))

#ifdef NDEBUG
#define RTC_DCHECK(condition) ((void)0)
#define RTC_DCHECK_EQ(a, b) ((void)0)
#define RTC_DCHECK_NE(a, b) ((void)0)
#define RTC_DCHECK_LT(a, b) ((void)0)
#define RTC_DCHECK_LE(a, b) ((void)0)
#define RTC_DCHECK_GT(a, b) ((void)0)
#define RTC_DCHECK_GE(a, b) ((void)0)
#else
#define RTC_DCHECK(condition) RTC_SHIM_CHECK_IMPL(condition)
#define RTC_DCHECK_EQ(a, b) RTC_SHIM_CHECK_IMPL((a) == (b))
#define RTC_DCHECK_NE(a, b) RTC_SHIM_CHECK_IMPL((a) != (b))
#define RTC_DCHECK_LT(a, b) RTC_SHIM_CHECK_IMPL((a) < (b))
#define RTC_DCHECK_LE(a, b) RTC_SHIM_CHECK_IMPL((a) <= (b))
#define RTC_DCHECK_GT(a, b) RTC_SHIM_CHECK_IMPL((a) > (b))
#define RTC_DCHECK_GE(a, b) RTC_SHIM_CHECK_IMPL((a) >= (b))
#endif  // NDEBUG

#endif  // RTC_BASE_CHECKS_H_
