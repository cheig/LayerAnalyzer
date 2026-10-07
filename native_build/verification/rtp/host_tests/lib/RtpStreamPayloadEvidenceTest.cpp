#include "doctest.h"

#include <initializer_list>

#include "layanalyzer/rtp/core/RtpStreamPayloadEvidence.h"

using layanalyzer::rtp::RtpStreamPayloadEvidence;

TEST_CASE("RtpStreamPayloadEvidence hides repeated header-only probes") {
  // Capture regression: 80 14 00 00 00 00 00 00 00 00 00 00,
  // repeated 6/3/3/3 times on four video endpoint pairs.
  for (const int count : {3, 6}) {
    RtpStreamPayloadEvidence evidence;
    for (int i = 0; i < count; ++i) {
      evidence.observe(0, true, false, false, 0);
    }
    CHECK_FALSE(evidence.shouldKeep());
  }
}

TEST_CASE("RtpStreamPayloadEvidence retains a single payload and mixed streams") {
  RtpStreamPayloadEvidence evidence;
  evidence.observe(0, true, false, false, 0);
  evidence.observe(1, true, false, false, 0);
  evidence.observe(0, true, false, false, 0);
  CHECK(evidence.shouldKeep());
}

TEST_CASE("RtpStreamPayloadEvidence excludes padding from media length") {
  RtpStreamPayloadEvidence evidence;
  evidence.observe(8, true, false, true, 8);
  CHECK_FALSE(evidence.shouldKeep());
  evidence.observe(9, true, false, true, 8);
  CHECK(evidence.shouldKeep());
}

TEST_CASE("RtpStreamPayloadEvidence preserves incomplete or encrypted streams") {
  RtpStreamPayloadEvidence evidence;
  SUBCASE("capture truncated") { evidence.observe(0, false, false, false, 0); }
  SUBCASE("SRTP") { evidence.observe(0, true, true, false, 0); }
  SUBCASE("padding unknown") { evidence.observe(8, true, false, true, 0); }
  SUBCASE("padding malformed") { evidence.observe(8, true, false, true, 9); }
  CHECK(evidence.shouldKeep());
  evidence.observe(0, true, false, false, 0);
  CHECK(evidence.shouldKeep());
}
