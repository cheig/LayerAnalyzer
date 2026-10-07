// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#pragma once

// Debug-only perf capture/export service.  Kept in a dedicated translation
// unit and compiled out of Release builds; it must only compose the real
// services, never re-implement their algorithms.

#include "layanalyzer/internal/Common.h"

#ifndef NDEBUG
// Debug-only perf capture/export service.  Kept in a dedicated translation
// unit and compiled out of Release builds; it must only compose the real
// services, never re-implement their algorithms.
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_exportPerfResults(JNIEnv *env,
                                                            jobject thiz,
                                                            jlong sessionPtr,
                                                            jstring jOutputDir);
#endif
