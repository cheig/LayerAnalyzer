// Copyright (c) 2026 cheig; GPL-3.0.
#pragma once
#include <jni.h>

namespace layanalyzer::tls {
jstring configureSecrets(JNIEnv* env, jlong sessionHandle, jstring keyLogPath,
                         jlong secretsGeneration);

// Called only while creating/destroying the sole file-scope owner, with an
// engine activity / final SessionLease (or the exclusive registry) held.
// Does not tear down epan: the owner does so immediately after this call.
bool clearSecretsPreference() noexcept;
}
