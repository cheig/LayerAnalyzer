// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// LayerAnalyzer native bridge composition root.
//
// Every Java_com_example_layanalyzer_NativeEngine_* symbol now lives in an
// independently compiled module under layanalyzer/:
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
