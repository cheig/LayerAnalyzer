// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

// Session handle registry: opaque handle allocation, lease-based lifetime
// accounting and the runtime-exclusive guard implementation.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/runtime/SessionRegistry.h"

std::shared_mutex g_native_mutex;
std::mutex g_lease_mutex;
std::condition_variable g_lease_cv;
std::mutex g_runtime_exclusive_mutex;
size_t g_active_session_leases = 0;
bool g_engine_shutting_down = false;
std::map<jlong, std::shared_ptr<WiresharkSession>> g_sessions;
static jlong g_next_session_handle = 1;

static void advance_session_handle_locked() {
  g_next_session_handle =
      g_next_session_handle == std::numeric_limits<jlong>::max()
          ? 1
          : g_next_session_handle + 1;
}

void SessionLease::release() {
  if (!counted_) return;
  counted_ = false;
  {
    std::lock_guard<std::mutex> lock(g_lease_mutex);
    if (g_active_session_leases > 0) --g_active_session_leases;
  }
  g_lease_cv.notify_all();
}

SessionLease acquire_session(jlong handle) {
  if (handle == 0) return {};
  std::shared_lock<std::shared_mutex> registry_lock(g_native_mutex);
  auto found = g_sessions.find(handle);
  if (found == g_sessions.end()) return {};
  std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
  if (g_engine_shutting_down) return {};
  ++g_active_session_leases;
  SessionLease lease(found->second);
  lease.mark_counted();
  return lease;
}

SessionLease acquire_engine_activity() {
  std::shared_lock<std::shared_mutex> registry_lock(g_native_mutex);
  std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
  if (g_engine_shutting_down) return {};
  ++g_active_session_leases;
  SessionLease lease;
  lease.mark_counted();
  return lease;
}

jlong publish_session(WiresharkSession *session) {
  if (!session) return 0;
  while (g_next_session_handle == 0 ||
         g_sessions.find(g_next_session_handle) != g_sessions.end()) {
    advance_session_handle_locked();
  }
  jlong handle = g_next_session_handle;
  advance_session_handle_locked();
  g_sessions.emplace(handle, std::shared_ptr<WiresharkSession>(session));
  return handle;
}

WiresharkSession *find_session_locked(jlong handle) {
  if (handle == 0) return nullptr;
  auto found = g_sessions.find(handle);
  return found == g_sessions.end() ? nullptr : found->second.get();
}

std::shared_ptr<WiresharkSession> detach_session(jlong handle) {
  auto found = g_sessions.find(handle);
  if (found == g_sessions.end()) return nullptr;
  std::shared_ptr<WiresharkSession> session = std::move(found->second);
  g_sessions.erase(found);
  return session;
}

void visit_all_sessions(const std::function<void(WiresharkSession *)> &visit) {
  for (auto &entry : g_sessions) {
    visit(entry.second.get());
  }
}

void close_all_sessions_locked() {
  g_sessions.clear();
}
