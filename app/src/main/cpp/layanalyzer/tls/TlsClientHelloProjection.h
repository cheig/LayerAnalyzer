// Copyright (c) 2026 cheig; GPL-3.0.
#pragma once
#include <jni.h>

namespace layanalyzer::tls {

// Projects, for each frame whose TLS ClientHello is present, the client_random, the
// destination address/port, the frame timestamp and the real 1-based frame number
// (TLS-303). No secrets cross this boundary: only the public ClientHello random and
// the frame's own addressing. Returns the shared envelope and is generation-checked
// like the other TLS JNI entries.
jstring projectClientHellos(JNIEnv* env, jlong session, jlong expectedGeneration, jint maxFrames);
}
