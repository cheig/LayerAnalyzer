// Shared visibility snapshot helpers.  Every service scans the same "visible
// frame set" (all frames, or the committed display-filter matches); these
// helpers keep that contract in one place.

#include "layanalyzer/internal/Common.h"
#include "layanalyzer/session/CaptureSession.h"

int visible_frame_count(WiresharkSession *session) {
  if (!session) {
    return 0;
  }
  std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
  return session->active_filter.empty()
             ? static_cast<int>(session->frame_offsets.size())
             : static_cast<int>(session->filtered_frames.size());
}

// Return one visible frame without materialising the complete visible set.
// This is the hot path for PagingSource requests: an unfiltered capture can
// contain millions of frames while a page usually contains fewer than 100.
int visible_frame_at(WiresharkSession *session, int visibleIndex) {
  if (!session || visibleIndex < 0) return -1;
  std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
  if (session->active_filter.empty()) {
    return visibleIndex < static_cast<int>(session->frame_offsets.size())
               ? visibleIndex
               : -1;
  }
  return visibleIndex < static_cast<int>(session->filtered_frames.size())
             ? session->filtered_frames[visibleIndex]
             : -1;
}

std::vector<int> snapshot_visible_frames(WiresharkSession *session) {
  std::vector<int> frames;
  if (!session) return frames;
  std::shared_lock<std::shared_mutex> state_lock(session->state_mutex);
  if (!session->active_filter.empty()) return session->filtered_frames;
  frames.reserve(session->frame_offsets.size());
  for (int i = 0; i < static_cast<int>(session->frame_offsets.size()); ++i) {
    frames.push_back(i);
  }
  return frames;
}

// ScopedRAII helpers for Wireshark display filters.
ScopedDFilter::ScopedDFilter(WiresharkSession *session) : session_(session) {}
ScopedDFilter::~ScopedDFilter() {
  if (!filter_) return;
  std::unique_lock<std::mutex> dissect_lock(session_->dissect_mutex);
  dfilter_free(filter_);
}
void ScopedDFilter::reset(dfilter_t *filter) { filter_ = filter; }
dfilter_t *ScopedDFilter::get() const { return filter_; }
