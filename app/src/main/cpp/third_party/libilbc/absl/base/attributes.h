// Shim for upstream absl/base/attributes.h (Abseil).
//
// The vendored iLBC tree pulls this in from four headers (cb_construct.h,
// decode.h, decode_residual.h, get_cd_vec.h), and the only symbol any of them
// uses is ABSL_MUST_USE_RESULT, on the declarations whose return value must not
// be ignored. Upstream's file is a large portability header; this one provides
// just that one attribute plus the two synonyms that appear alongside it in
// Abseil, so the include resolves without vendoring Abseil.
#ifndef ABSL_BASE_ATTRIBUTES_H_
#define ABSL_BASE_ATTRIBUTES_H_

#if defined(__clang__) || defined(__GNUC__)
#define ABSL_MUST_USE_RESULT __attribute__((warn_unused_result))
#define ABSL_ATTRIBUTE_UNUSED __attribute__((unused))
#define ABSL_ATTRIBUTE_ALWAYS_INLINE __attribute__((always_inline))
#else
#define ABSL_MUST_USE_RESULT
#define ABSL_ATTRIBUTE_UNUSED
#define ABSL_ATTRIBUTE_ALWAYS_INLINE
#endif

#endif  // ABSL_BASE_ATTRIBUTES_H_
