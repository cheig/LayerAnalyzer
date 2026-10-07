// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

#pragma once

// Session handle registry and lease-based lifetime management.
//
// The registry owns sessions behind opaque jlong handles.  JNI calls acquire
// a SessionLease (a shared_ptr plus an activity count) instead of holding the
// global lifetime lock for the duration of a call, so closeFile can detach a
// handle immediately while an in-flight operation drains safely.

#include <jni.h>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>

struct WiresharkSession;

// Protects engine lifetime and opaque session handles. Session work takes a
// shared lifetime lock; open/close/cleanup update the handle registry under
// the exclusive lock so a queued call can reject a handle closed before it
// acquired the lock.
extern std::shared_mutex g_native_mutex;
// Session leases are counted separately from the registry lock.  This lets
// closeFile detach a handle without waiting for a background scan, while
// cleanup can still quiesce all Wireshark users before epan_cleanup().
extern std::mutex g_lease_mutex;
extern std::condition_variable g_lease_cv;
// Serializes process-wide Wireshark configuration transitions (Decode As,
// name resolution and cleanup-adjacent guards).
extern std::mutex g_runtime_exclusive_mutex;
extern size_t g_active_session_leases;
extern bool g_engine_shutting_down;
// The registry owns sessions. JNI calls still acquire the lifetime lock before
// obtaining a raw pointer for the duration of the call, while shared_ptr keeps
// the ownership model explicit and makes the next lease-based migration safe.
extern std::map<jlong, std::shared_ptr<WiresharkSession>> g_sessions;

// A lease keeps a session alive after it has been removed from g_sessions.
// Long-running JNI calls must not hold g_native_mutex for their entire scan:
// closeFile() should be able to detach a handle immediately while the active
// operation drains safely.  Engine cleanup uses the same counter to wait for
// all leases before calling epan_cleanup().
class SessionLease {
 public:
  SessionLease() = default;
  explicit SessionLease(std::shared_ptr<WiresharkSession> session)
      : session_(std::move(session)) {}
  SessionLease(const SessionLease &) = delete;
  SessionLease &operator=(const SessionLease &) = delete;
  SessionLease(SessionLease &&other) noexcept
      : session_(std::move(other.session_)), counted_(other.counted_) {
    other.counted_ = false;
  }
  SessionLease &operator=(SessionLease &&other) noexcept {
    if (this == &other) return *this;
    release();
    session_ = std::move(other.session_);
    counted_ = other.counted_;
    other.counted_ = false;
    return *this;
  }
  ~SessionLease() { release(); }

  WiresharkSession *get() const { return session_.get(); }
  WiresharkSession *operator->() const { return session_.get(); }
  explicit operator bool() const { return session_ != nullptr; }
  bool active() const { return counted_; }
  operator WiresharkSession *() const { return session_.get(); }
  void mark_counted() { counted_ = true; }

 private:
  void release();

  std::shared_ptr<WiresharkSession> session_;
  bool counted_ = false;
};

// Acquires a session lease for an opaque handle; returns an inactive lease if
// the handle is unknown or the engine is shutting down.
SessionLease acquire_session(jlong handle);

// Acquires an engine-wide activity lease without a session.  openFile uses it
// so cleanup cannot run epan_cleanup() while a capture is being indexed.
SessionLease acquire_engine_activity();

// Publishes a fully indexed session under the exclusive registry lock.
// Returns 0 if engine shutdown began during indexing; the caller then owns
// and must delete the session.
jlong publish_session(WiresharkSession *session);

// Looks up a session without affecting its lifetime.  The caller must hold
// the registry exclusively, i.e. inside a RuntimeExclusiveGuard scope.
WiresharkSession *find_session_locked(jlong handle);

// Detaches a handle from the registry and returns the owned session so the
// last lease can drain safely.  Takes the exclusive registry lock itself.
std::shared_ptr<WiresharkSession> detach_session(jlong handle);

// Invokes `visit` for every registered session.  The caller must hold the
// registry exclusively, i.e. inside a RuntimeExclusiveGuard scope.
void visit_all_sessions(const std::function<void(WiresharkSession *)> &visit);

// Drops every registered session.  The caller must hold the exclusive
// registry lock (cleanup does, before waiting for leases to drain).
void close_all_sessions_locked();

// Process-wide Wireshark settings (name resolution and Decode As) cannot be
// changed while any session is dissecting.  This guard blocks new leases,
// waits for existing ones to finish, and serializes the update with the
// registry.  It is intentionally short-lived and must never wrap a full scan.
class RuntimeExclusiveGuard {
 public:
  RuntimeExclusiveGuard()
      : runtime_lock_(g_runtime_exclusive_mutex) {
    {
      std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
      g_engine_shutting_down = true;
    }
    std::unique_lock<std::mutex> lease_lock(g_lease_mutex);
    g_lease_cv.wait(lease_lock,
                    [] { return g_active_session_leases == 0; });
    // Acquire the registry only after all activities have drained. Taking it
    // first would deadlock with openFile's final publication step: openFile
    // still owns an activity lease while waiting to publish its Session.
    registry_lock_ = std::unique_lock<std::shared_mutex>(g_native_mutex);
  }

  RuntimeExclusiveGuard(const RuntimeExclusiveGuard &) = delete;
  RuntimeExclusiveGuard &operator=(const RuntimeExclusiveGuard &) = delete;

  ~RuntimeExclusiveGuard() {
    {
      std::lock_guard<std::mutex> lease_lock(g_lease_mutex);
      g_engine_shutting_down = false;
    }
    registry_lock_.unlock();
  }

 private:
  std::unique_lock<std::mutex> runtime_lock_;
  std::unique_lock<std::shared_mutex> registry_lock_;
};
