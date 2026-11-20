#pragma once
#include <jni.h>

namespace layanalyzer::tls {
// P0 only. Requires the application-owned engine and one already-open capture.
jstring probeDissection(JNIEnv* env, jlong session, jstring keyLogPath,
                        jint serverPort, jboolean http2, jboolean withTaps);
}
