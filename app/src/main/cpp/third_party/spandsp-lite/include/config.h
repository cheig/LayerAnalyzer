/*
 * Minimal hand-written build configuration for the vendored spandsp subset.
 *
 * spandsp is normally built with autotools, which generates config.h from
 * autoconf probes. This subset does not ship autotools, so this file replaces
 * the generated header with a fixed configuration that is valid for every
 * target this project builds for: Android arm64-v8a / x86_64 (bionic libc,
 * NDK r27 clang) and the Windows MSVC host test build.
 *
 * The three vendored sources include this header only because they test
 * `#if defined(HAVE_CONFIG_H)`; the library is compiled with
 * `HAVE_CONFIG_H=1` so the include is active. Do NOT import upstream's
 * `config.h.in` -- it contains hundreds of unrelated probes.
 *
 * Only C99/C++11 features that both bionic and the MSVC CRT provide are
 * enabled here. In particular HAVE_TGMATH_H is deliberately NOT defined:
 * bionic has no <tgmath.h>, and defining it breaks g722.c at compile time.
 */
#ifndef SPANDSP_LITE_CONFIG_H
#define SPANDSP_LITE_CONFIG_H

/* C99 <stdbool.h>. Provided by bionic and by MSVC 2013 and later. */
#define HAVE_STDBOOL_H 1

/* <math.h> and the float variants of the C99 math functions. All of these are
 * provided by bionic and by the MSVC CRT. Defining them keeps spandsp's
 * floating_fudge.h shims out of the build; those shims are `static __inline__`
 * redefinitions of the libm float functions and would clash with the real
 * prototypes from <math.h>. */
#define HAVE_MATH_H 1
#define HAVE_SINF 1
#define HAVE_COSF 1
#define HAVE_TANF 1
#define HAVE_ASINF 1
#define HAVE_ACOSF 1
#define HAVE_ATANF 1
#define HAVE_ATAN2F 1
#define HAVE_CEILF 1
#define HAVE_FLOORF 1
#define HAVE_POWF 1
#define HAVE_EXPF 1
#define HAVE_LOGF 1
#define HAVE_LOG10F 1

#endif /* SPANDSP_LITE_CONFIG_H */
