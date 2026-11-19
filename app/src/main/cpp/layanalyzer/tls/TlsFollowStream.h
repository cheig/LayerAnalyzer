// Copyright (c) 2026 cheig; GPL-3.0.
#pragma once
#include <jni.h>

namespace layanalyzer::tls {
jstring followStream(JNIEnv* env, jlong session, jint packetIndex,
                     jlong expectedGeneration, jint maxBytes);
// TLS-308: stream the complete connection's plaintext to `outputPath` in bounded chunks. Returns a
// digest envelope; a partial file is removed on failure/cancellation and never reported as success.
jstring exportStream(JNIEnv* env, jlong session, jint packetIndex,
                     jlong expectedGeneration, jstring outputPath, jint maxBytes);
}
