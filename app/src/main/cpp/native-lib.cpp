// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// LayerAnalyzer native bridge composition root.
//
// Existing JNI symbols live in independently compiled modules under layanalyzer/.
// TLS experiments below use thin forwards only:
//
//   jni/EngineLifecycle.cpp    JNI_OnLoad/Unload, init/cleanup, provider funcs
//   jni/PacketListJni.cpp      openFile, paging, cancel, error, close
//   jni/QueryJni.cpp           scoped queries, display filter, search
//   jni/AnalysisJni.cpp        Expert Info and statistics
//   jni/CommunicationJni.cpp   SIP/SDP, RTP/RTCP, core network analysis
//   jni/ExportJni.cpp          visible-capture pcap export
//   jni/StreamHttpJni.cpp      follow stream, HTTP objects
//   jni/ConfigurationJni.cpp   name resolution, Decode As
//   jni/DetailJni.cpp          packet details, packet bytes
//   jni/PerfExportJni.cpp      debug-only G4 对拍导出 (NDEBUG-gated)
//
// Shared state and cross-module declarations live in internal/EngineState.h,
// internal/TextUtils.h and the per-module headers next to each implementation.
// Do not add business logic here.

#include "layanalyzer/tls/TlsDecryptionConfig.h"
#include "layanalyzer/tls/TlsDataSources.h"
#include "layanalyzer/tls/TlsClientHelloProjection.h"
#include "layanalyzer/tls/TlsFollowStream.h"
#include "layanalyzer/tls/TlsProxyAdapter.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getTlsProxyCapabilities(JNIEnv* env, jobject) {
    return layanalyzer::tls::capabilities(env);
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_startTlsProxy(JNIEnv* env, jobject, jstring config,
    jbyteArray certificate, jbyteArray privateKey, jobject callbacks) {
    return layanalyzer::tls::start(env, config, certificate, privateKey, callbacks);
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_stopTlsProxy(JNIEnv* env, jobject, jlong handle, jint timeout) {
    return layanalyzer::tls::stop(env, handle, timeout);
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_pollTlsProxyEvents(JNIEnv* env, jobject, jlong handle, jint maxEvents) {
    return layanalyzer::tls::poll(env, handle, maxEvents);
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getTlsProxyStats(JNIEnv* env, jobject, jlong handle) {
    return layanalyzer::tls::stats(env, handle);
}
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_layanalyzer_NativeEngine_getTlsProxyToken(JNIEnv* env, jobject, jlong handle) {
    return layanalyzer::tls::gatewayToken(env, handle);
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_example_layanalyzer_NativeEngine_generateTlsCaMaterial(JNIEnv* env, jobject) {
    return layanalyzer::tls::generateCaMaterial(env);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_followTlsStream(
        JNIEnv* env, jobject, jlong session, jint packetIndex, jlong expectedGeneration, jint maxBytes) {
    return layanalyzer::tls::followStream(env, session, packetIndex, expectedGeneration, maxBytes);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_exportTlsFollowStream(
        JNIEnv* env, jobject, jlong session, jint packetIndex, jlong expectedGeneration,
        jstring outputPath, jint maxBytes) {
    return layanalyzer::tls::exportStream(env, session, packetIndex, expectedGeneration, outputPath, maxBytes);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getPacketDataSources(
        JNIEnv* env, jobject, jlong session, jstring snapshotId, jlong expectedGeneration) {
    return layanalyzer::tls::describeDataSources(env, session, snapshotId, expectedGeneration);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_readPacketDataSource(
        JNIEnv* env, jobject, jlong session, jstring snapshotId, jstring sourceId,
        jint offset, jint length, jlong expectedGeneration) {
    return layanalyzer::tls::readDataSource(env, session, snapshotId, sourceId,
                                           offset, length, expectedGeneration);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_configureTlsSecrets(
        JNIEnv* env, jobject, jlong session, jstring keyLogPath, jlong secretsGeneration) {
    return layanalyzer::tls::configureSecrets(env, session, keyLogPath, secretsGeneration);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_projectTlsClientHellos(
        JNIEnv* env, jobject, jlong session, jlong expectedGeneration, jint maxFrames) {
    return layanalyzer::tls::projectClientHellos(env, session, expectedGeneration, maxFrames);
}

#ifdef LAYANALYZER_TLS_PROBE
#include "layanalyzer/tls/TlsProxyAdapter.h"
#include "layanalyzer/tls/TlsDissectionProbe.h"

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_example_layanalyzer_NativeEngine_runTlsTunProbe(
        JNIEnv* env, jobject, jint protocol, jobject callback) {
    return layanalyzer::tls::probeTlsPair(env, protocol, false, callback, true);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_runTlsDissectionProbe(
        JNIEnv* env, jobject, jlong session, jstring keyLogPath,
        jint serverPort, jboolean http2, jboolean withTaps) {
    return layanalyzer::tls::probeDissection(env, session, keyLogPath, serverPort, http2, withTaps);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_getTlsBridgeProbeState(JNIEnv* env, jobject) {
    return layanalyzer::tls::probeState(env);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_loadTlsBridgeProbe(
        JNIEnv* env, jobject, jboolean missingLibrary, jint expectedAbiVersion) {
    return layanalyzer::tls::probeLoad(env, missingLibrary, expectedAbiVersion);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_startTlsBridgeProbe(
        JNIEnv* env, jobject, jobject callback) {
    return layanalyzer::tls::probeStart(env, callback);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_stopTlsBridgeProbe(JNIEnv* env, jobject, jlong handle) {
    return layanalyzer::tls::probeStop(env, handle);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_layanalyzer_NativeEngine_runTlsSocketProbe(
        JNIEnv* env, jobject, jstring ip, jint port, jlong generation,
        jint timeoutMillis, jobject callback) {
    return layanalyzer::tls::probeSocket(env, ip, port, generation, timeoutMillis, callback);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_example_layanalyzer_NativeEngine_runTlsKeyLogProbe(
        JNIEnv* env, jobject, jint protocol, jboolean rejectRoot, jobject callback) {
    return layanalyzer::tls::probeTlsPair(env, protocol, rejectRoot, callback);
}
#endif
