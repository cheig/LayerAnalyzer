// Shim for upstream rtc_base/numerics/safe_conversions.h.
//
// The only symbol taken from this header by the vendored tree is
// rtc::saturated_cast<T>(value), used by dot_product_with_scale.cc to clamp the
// 64-bit dot-product accumulator into an int32_t. Upstream's header is a large
// template set (checked_cast, dchecked_cast, IsValueInRangeForNumericType, ...)
// built on Abseil; none of that is reachable here.
//
// Semantics match upstream's saturated_cast: the result is clamped to the
// destination type's range rather than wrapping.
#ifndef RTC_BASE_NUMERICS_SAFE_CONVERSIONS_H_
#define RTC_BASE_NUMERICS_SAFE_CONVERSIONS_H_

#include <limits>

namespace rtc {

template <typename T, typename U>
inline T saturated_cast(U value) {
  if (value > static_cast<U>(std::numeric_limits<T>::max())) {
    return std::numeric_limits<T>::max();
  }
  if (value < static_cast<U>(std::numeric_limits<T>::min())) {
    return std::numeric_limits<T>::min();
  }
  return static_cast<T>(value);
}

}  // namespace rtc

#endif  // RTC_BASE_NUMERICS_SAFE_CONVERSIONS_H_
