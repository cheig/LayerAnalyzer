#pragma once

#include <jni.h>

namespace layanalyzer::tls {
jstring capabilities(JNIEnv* env);
jstring start(JNIEnv* env, jstring config, jbyteArray certificate, jbyteArray privateKey, jobject callbacks);
jstring stop(JNIEnv* env, jlong handle, jint timeoutMillis);
jstring poll(JNIEnv* env, jlong handle, jint maxEvents);
jstring stats(JNIEnv* env, jlong handle);

// TLS-215: the running run's gateway token as 43 ASCII bytes, or a pending
// IllegalStateException carrying one fixed code name. A dedicated buffer, for
// the SOCKS hop's LAT1 frame only — never a JSON field and never logged.
jbyteArray gatewayToken(JNIEnv* env, jlong handle);

// Exactly [certificateDER, privateKeyPKCS8] of one fresh install CA, or a
// pending TlsCertificateException. Never returns null arrays as success and
// never puts key material in a message.
jobjectArray generateCaMaterial(JNIEnv* env);

// P0 remains isolated by LAYANALYZER_TLS_PROBE.
jstring probeState(JNIEnv* env);
jstring probeLoad(JNIEnv* env, jboolean missingLibrary, jint expectedAbiVersion);
jstring probeStart(JNIEnv* env, jobject callback);
jstring probeStop(JNIEnv* env, jlong handle);
jstring probeSocket(JNIEnv* env, jstring ip, jint port, jlong generation,
                    jint timeoutMillis, jobject callback);
jobjectArray probeTlsPair(JNIEnv* env, jint protocol, jboolean rejectRoot, jobject callback, bool tun = false);
}
