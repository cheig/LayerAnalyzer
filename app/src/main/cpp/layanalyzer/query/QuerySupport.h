#pragma once

// Shared visibility snapshot helpers and scoped Wireshark dfilter RAII.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/session/CaptureSession.h"

int visible_frame_count(WiresharkSession *session);
std::vector<int> snapshot_visible_frames(WiresharkSession *session);

// Return one visible frame without materialising the complete visible set.
// This is the hot path for PagingSource requests: an unfiltered capture can
// contain millions of frames while a page usually contains fewer than 100.
int visible_frame_at(WiresharkSession *session, int visibleIndex);

class ScopedDFilter {
 public:
  explicit ScopedDFilter(WiresharkSession *session);
  ~ScopedDFilter();
  ScopedDFilter(const ScopedDFilter &) = delete;
  ScopedDFilter &operator=(const ScopedDFilter &) = delete;

  void reset(dfilter_t *filter);
  dfilter_t *get() const;

 private:
  WiresharkSession *session_;
  dfilter_t *filter_ = nullptr;
};

struct ScopedGFree {
  gchar *value = nullptr;
  ScopedGFree() = default;
  ~ScopedGFree() { g_free(value); }
  ScopedGFree(const ScopedGFree &) = delete;
  ScopedGFree &operator=(const ScopedGFree &) = delete;
};
