// RTP4-NAT-05: Ogg Opus encapsulation (RFC 7845).
//
// The codec is not the risk here -- there is none, this only frames Opus
// packets -- it is the container, and two of its rules fail silently:
//
//   * Lacing (RFC 3533 section 6). A packet of L octets is described by
//     L / 255 values of 255 followed by one value of L % 255, and that final
//     value is emitted *even when it is zero*. Drop it for L = 255 and the
//     reader sees a segment chain that never terminates, so it swallows the
//     next page's header as packet data. The card's shorthand for this rule
//     reads as if the terminator could be omitted; the two lacing cases below
//     (255 -> [255, 0] and 260 -> [255, 5]) are what pin it down.
//   * The CRC (RFC 3533 section 6). Ogg uses polynomial 0x04C11DB7 with no
//     input or output reflection and no final XOR, which is *not* zlib's
//     CRC-32 and not CRC-32/POSIX. A wrong CRC still produces a file that
//     looks perfectly structured, and every player then refuses it.
//
// So the CRC is checked here with a second, deliberately different
// implementation: the production code shifts a register byte by byte, while
// crc32_by_long_division() below does explicit MSB-first polynomial long
// division over the whole page as a bit string. Two formulations written the
// same way would prove nothing; these two cannot agree by accident on a wrong
// polynomial. No external golden CRC vector is available offline (no
// opusinfo/oggz on the development machine is required anyway), so the
// evidence for the CRC is that agreement plus the RFC 3533 parameters written
// out in crc32_by_long_division().
//
// Everything here writes under std::filesystem::temp_directory_path() with a
// per-case name and removes it again; the repository tree is never touched.
#include "doctest.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "layanalyzer/rtp/io/OggOpusWriter.h"

using layanalyzer::rtp::OggOpusOptions;
using layanalyzer::rtp::OggOpusWriter;

namespace {

// The 27-octet fixed page header (RFC 3533 section 6) and the page itself.
constexpr size_t kPageHeaderSize = 27;
constexpr uint8_t kHeaderBos = 0x02;
constexpr uint8_t kHeaderEos = 0x04;
constexpr uint32_t kExpectedSerial = 0x4C41594Cu;  // "LAYL", fixed by the writer

// A file under the system temp directory, removed on construction and on
// destruction, so a rerun never reads a stale artifact from the last one.
class TempFile {
 public:
  explicit TempFile(const std::string &name) {
    path_ = (std::filesystem::temp_directory_path() / name).string();
    std::remove(path_.c_str());
  }
  ~TempFile() { std::remove(path_.c_str()); }

  TempFile(const TempFile &) = delete;
  TempFile &operator=(const TempFile &) = delete;

  const std::string &path() const { return path_; }

 private:
  std::string path_;
};

bool read_file(const std::string &path, std::vector<uint8_t> &out) {
  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (!file) {
    return false;
  }
  uint8_t buffer[4096];
  size_t count = 0;
  while ((count = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
    out.insert(out.end(), buffer, buffer + count);
  }
  std::fclose(file);
  return true;
}

struct Page {
  size_t offset = 0;
  uint8_t header_type = 0;
  uint64_t granule = 0;
  uint32_t serial = 0;
  uint32_t sequence = 0;
  uint32_t stored_crc = 0;
  std::vector<uint8_t> lacing;
  std::vector<uint8_t> body;
  size_t total_size = 0;
};

uint32_t read_le32(const std::vector<uint8_t> &bytes, size_t offset) {
  return static_cast<uint32_t>(bytes[offset]) |
         (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
         (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

uint64_t read_le64(const std::vector<uint8_t> &bytes, size_t offset) {
  uint64_t value = 0;
  for (int i = 7; i >= 0; --i) {
    value = (value << 8) | bytes[offset + static_cast<size_t>(i)];
  }
  return value;
}

// Walks the pages the way a reader must: each page's size follows from its own
// segment table, so the next header starts where the body ended. Scanning for
// "OggS" instead would find the magic inside a payload sooner or later, so
// the scan is only used to count page starts in count_magic() below, on
// payloads chosen not to contain it.
bool parse_pages(const std::vector<uint8_t> &bytes, std::vector<Page> &pages) {
  size_t offset = 0;
  while (offset < bytes.size()) {
    if (bytes.size() - offset < kPageHeaderSize) {
      return false;
    }
    if (bytes[offset] != 'O' || bytes[offset + 1] != 'g' ||
        bytes[offset + 2] != 'g' || bytes[offset + 3] != 'S') {
      return false;
    }
    Page page;
    page.offset = offset;
    page.header_type = bytes[offset + 5];
    page.granule = read_le64(bytes, offset + 6);
    page.serial = read_le32(bytes, offset + 14);
    page.sequence = read_le32(bytes, offset + 18);
    page.stored_crc = read_le32(bytes, offset + 22);
    const size_t segment_count = bytes[offset + 26];
    if (bytes.size() - offset < kPageHeaderSize + segment_count) {
      return false;
    }
    size_t body_size = 0;
    for (size_t i = 0; i < segment_count; ++i) {
      const uint8_t lacing = bytes[offset + kPageHeaderSize + i];
      page.lacing.push_back(lacing);
      body_size += lacing;
    }
    const size_t total = kPageHeaderSize + segment_count + body_size;
    if (bytes.size() - offset < total) {
      return false;
    }
    page.body.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset + kPageHeaderSize + segment_count),
                     bytes.begin() + static_cast<std::ptrdiff_t>(offset + total));
    page.total_size = total;
    pages.push_back(page);
    offset += total;
  }
  return true;
}

size_t count_magic(const std::vector<uint8_t> &bytes) {
  size_t count = 0;
  for (size_t i = 0; i + 4 <= bytes.size(); ++i) {
    if (bytes[i] == 'O' && bytes[i + 1] == 'g' && bytes[i + 2] == 'g' &&
        bytes[i + 3] == 'S') {
      ++count;
    }
  }
  return count;
}

// Independent CRC-32 for Ogg, written as explicit MSB-first polynomial long
// division rather than as a register loop:
//
//   generator  x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8
//              + x^7 + x^5 + x^4 + x^2 + x + 1, i.e. 0x04C11DB7 with the
//              leading x^32 term implied (RFC 3533 section 6)
//   initial    0        input reflection  none
//   final xor  none     output reflection none
//
// The message is taken as a bit string with 32 zero bits appended, then the
// generator is cancelled against every leading 1 in turn; what remains in the
// last 32 bits is the remainder.
uint32_t crc32_by_long_division(const std::vector<uint8_t> &page) {
  std::vector<uint8_t> bits;
  bits.reserve(page.size() * 8 + 32);
  for (const uint8_t octet : page) {
    for (int i = 7; i >= 0; --i) {
      bits.push_back(static_cast<uint8_t>((octet >> i) & 0x01u));
    }
  }
  const size_t message_bits = bits.size();
  bits.resize(message_bits + 32, 0);

  constexpr uint32_t kPolynomial = 0x04C11DB7u;  // leading x^32 term implicit
  for (size_t i = 0; i < message_bits; ++i) {
    if (bits[i] == 0) {
      continue;
    }
    for (int j = 0; j <= 32; ++j) {
      const uint8_t generator =
          (j == 0) ? 1u : static_cast<uint8_t>((kPolynomial >> (32 - j)) & 0x01u);
      bits[i + static_cast<size_t>(j)] ^= generator;
    }
  }

  uint32_t remainder = 0;
  for (size_t i = message_bits; i < bits.size(); ++i) {
    remainder = (remainder << 1) | bits[i];
  }
  return remainder;
}

// CRC over the page with the CRC field itself zeroed, which is the field the
// writer stores the result into.
uint32_t recomputed_crc(const std::vector<uint8_t> &bytes, const Page &page) {
  std::vector<uint8_t> copy(bytes.begin() + static_cast<std::ptrdiff_t>(page.offset),
                            bytes.begin() + static_cast<std::ptrdiff_t>(page.offset + page.total_size));
  for (size_t i = 0; i < 4; ++i) {
    copy[22 + i] = 0;
  }
  return crc32_by_long_division(copy);
}

// doctest prints std::vector<uint8_t> as "{?}", so a failing CHECK_EQ on two
// byte strings would say nothing usable. These report the first octet that
// differs instead.
bool bytes_equal(const std::vector<uint8_t> &actual,
                 const std::vector<uint8_t> &expected, size_t &first_difference) {
  const size_t common =
      actual.size() < expected.size() ? actual.size() : expected.size();
  for (size_t i = 0; i < common; ++i) {
    if (actual[i] != expected[i]) {
      first_difference = i;
      return false;
    }
  }
  first_difference = common;
  return actual.size() == expected.size();
}

#define OGG_CHECK_BYTES(actual, expected)                                    \
  do {                                                                       \
    size_t ogg_difference = 0;                                               \
    CHECK_MESSAGE(                                                           \
        bytes_equal((actual), (expected), ogg_difference),                   \
        "first difference at octet " << ogg_difference << " (got "           \
                                      << (actual).size() << " octets, want " \
                                      << (expected).size() << ")");          \
  } while (false)

// Writes one packet of `length` octets, finalizes, and parses the result. The
// audio page is pages[2]: OpusHead, OpusTags, the packet, the EOS page.
bool write_one_packet(const std::string &path, size_t length,
                      std::vector<uint8_t> &bytes, std::vector<Page> &pages) {
  OggOpusWriter writer;
  std::string error;
  if (!writer.open(path, OggOpusOptions(), error)) {
    return false;
  }
  const std::vector<uint8_t> packet(length, 0xA5);
  if (!writer.writePacket(packet.data(), packet.size(), 960, error)) {
    return false;
  }
  if (!writer.finalize(error)) {
    return false;
  }
  return read_file(path, bytes) && parse_pages(bytes, pages) && pages.size() == 4;
}

}  // namespace

TEST_CASE("OggOpusWriter writes OpusHead, OpusTags, three audio pages and one EOS page") {
  TempFile file("layanalyzer_oggopus_three_packets.opus");
  OggOpusWriter writer;
  std::string error;
  REQUIRE(writer.open(file.path(), OggOpusOptions(), error));

  // The payloads are constant fills, so none of them contains the "OggS"
  // magic and the naive magic count below is meaningful.
  const std::vector<uint8_t> first(4, 0xA1);
  const std::vector<uint8_t> second(5, 0xB2);
  const std::vector<uint8_t> third(6, 0xC3);
  REQUIRE(writer.writePacket(first.data(), first.size(), 960, error));
  REQUIRE(writer.writePacket(second.data(), second.size(), 1920, error));
  REQUIRE(writer.writePacket(third.data(), third.size(), 2880, error));
  REQUIRE(writer.finalize(error));

  std::vector<uint8_t> bytes;
  REQUIRE(read_file(file.path(), bytes));
  std::vector<Page> pages;
  REQUIRE(parse_pages(bytes, pages));

  // The card's `grep -c "OggS"` cross-check: the sequential parse and the
  // naive count have to agree on how many pages there are.
  CHECK_EQ(count_magic(bytes), 6u);
  REQUIRE_EQ(pages.size(), 6u);

  // Page order and header type bits: BOS on the identification page, EOS on
  // the last one, plain pages in between.
  CHECK_EQ(pages[0].header_type, kHeaderBos);
  CHECK_EQ(pages[1].header_type, 0u);
  CHECK_EQ(pages[2].header_type, 0u);
  CHECK_EQ(pages[3].header_type, 0u);
  CHECK_EQ(pages[4].header_type, 0u);
  CHECK_EQ(pages[5].header_type, kHeaderEos);

  // Granules: both header pages are 0 (RFC 7845 section 4), each audio page
  // carries the RTP timestamp it was written with, and the packetless EOS page
  // carries the last granule written.
  CHECK_EQ(pages[0].granule, 0u);
  CHECK_EQ(pages[1].granule, 0u);
  CHECK_EQ(pages[2].granule, 960u);
  CHECK_EQ(pages[3].granule, 1920u);
  CHECK_EQ(pages[4].granule, 2880u);
  CHECK_EQ(pages[5].granule, 2880u);

  // Page sequence numbers run 0..5 with no gaps.
  for (size_t i = 0; i < pages.size(); ++i) {
    CHECK_EQ(pages[i].sequence, static_cast<uint32_t>(i));
    CHECK_EQ(pages[i].serial, kExpectedSerial);
    CHECK_EQ(bytes[pages[i].offset + 4], 0u);  // stream structure version
    // Every page's CRC, from the independent long-division implementation.
    CHECK_EQ(pages[i].stored_crc, recomputed_crc(bytes, pages[i]));
  }

  // The bodies are the packets, unchanged, and the EOS page holds none at all:
  // a zero-length Opus packet would be invalid (RFC 6716 section 3.2), so the
  // page announces nothing rather than announcing an empty packet.
  OGG_CHECK_BYTES(pages[2].body, first);
  OGG_CHECK_BYTES(pages[3].body, second);
  OGG_CHECK_BYTES(pages[4].body, third);
  CHECK(pages[5].lacing.empty());
  CHECK(pages[5].body.empty());
  CHECK_EQ(pages[0].body.size(), 19u);
  CHECK_EQ(pages[1].body.size(), 29u);
  // One lacing value per short packet.
  REQUIRE_EQ(pages[2].lacing.size(), 1u);
  CHECK_EQ(pages[2].lacing[0], 4u);
  REQUIRE_EQ(pages[3].lacing.size(), 1u);
  CHECK_EQ(pages[3].lacing[0], 5u);
  REQUIRE_EQ(pages[4].lacing.size(), 1u);
  CHECK_EQ(pages[4].lacing[0], 6u);
}

TEST_CASE("OggOpusWriter laces a 260-octet packet as [255, 5]") {
  TempFile file("layanalyzer_oggopus_lacing_260.opus");
  std::vector<uint8_t> bytes;
  std::vector<Page> pages;
  REQUIRE(write_one_packet(file.path(), 260, bytes, pages));

  const Page &audio = pages[2];
  REQUIRE_EQ(audio.lacing.size(), 2u);
  CHECK_EQ(audio.lacing[0], 255u);
  CHECK_EQ(audio.lacing[1], 5u);
  CHECK_EQ(audio.body.size(), 260u);
  CHECK_EQ(audio.stored_crc, recomputed_crc(bytes, audio));
  CHECK_EQ(pages[3].header_type, kHeaderEos);
}

TEST_CASE("OggOpusWriter laces a 255-octet packet as [255, 0]") {
  // The case the card's shorthand loses: 255 is 255 / 255 = 1 whole segment
  // with a zero remainder, and the zero lacing value is what terminates the
  // packet. Without it the reader keeps reading 255-octet segments and walks
  // straight through the following page header.
  TempFile file("layanalyzer_oggopus_lacing_255.opus");
  std::vector<uint8_t> bytes;
  std::vector<Page> pages;
  REQUIRE(write_one_packet(file.path(), 255, bytes, pages));

  const Page &audio = pages[2];
  REQUIRE_EQ(audio.lacing.size(), 2u);
  CHECK_EQ(audio.lacing[0], 255u);
  CHECK_EQ(audio.lacing[1], 0u);
  CHECK_EQ(audio.body.size(), 255u);
  // The packet after it is still parsed as its own page, i.e. the segment
  // chain really did end where the writer said it did.
  CHECK_EQ(audio.stored_crc, recomputed_crc(bytes, audio));
  CHECK_EQ(pages.size(), 4u);
  CHECK_EQ(pages[3].sequence, 3u);
  CHECK_EQ(pages[3].header_type, kHeaderEos);
}

TEST_CASE("OggOpusWriter OpusHead for two channels is byte exact") {
  TempFile file("layanalyzer_oggopus_head_headers.opus");
  OggOpusOptions options;
  options.channels = 2;
  options.pre_skip = 312;

  OggOpusWriter writer;
  std::string error;
  REQUIRE(writer.open(file.path(), options, error));
  REQUIRE(writer.finalize(error));

  std::vector<uint8_t> bytes;
  REQUIRE(read_file(file.path(), bytes));
  std::vector<Page> pages;
  REQUIRE(parse_pages(bytes, pages));
  REQUIRE_EQ(pages.size(), 3u);
  REQUIRE_EQ(pages[0].body.size(), 19u);

  // Field by field first, so a failure says which field moved.
  const std::vector<uint8_t> &head = pages[0].body;
  CHECK_EQ(std::string(reinterpret_cast<const char *>(head.data()), 8), "OpusHead");
  CHECK_EQ(head[8], 1u);   // OpusHead version
  CHECK_EQ(head[9], 2u);   // channel count
  CHECK_EQ(static_cast<uint32_t>(head[10]) | (static_cast<uint32_t>(head[11]) << 8), 312u);
  CHECK_EQ(read_le32(head, 12), 48000u);   // original sample rate
  // Output gain is a signed 16-bit Q7.8 field at offset 16; read it as two
  // octets rather than with read_le32(), which would run past the packet.
  CHECK_EQ(static_cast<int16_t>(static_cast<uint16_t>(head[16]) |
                                (static_cast<uint16_t>(head[17]) << 8)),
           0);
  CHECK_EQ(head[18], 0u);  // channel mapping family

  // ...and then against the whole packet, written out by hand from RFC 7845
  // section 5.1: magic, version 1, two channels, pre-skip 0x0138, rate
  // 48000 = 0x0000BB80, gain 0, mapping family 0.
  const std::vector<uint8_t> expected = {
      0x4F, 0x70, 0x75, 0x73, 0x48, 0x65, 0x61, 0x64,  // "OpusHead"
      0x01,                                            // version
      0x02,                                            // channel count
      0x38, 0x01,                                      // pre-skip 312
      0x80, 0xBB, 0x00, 0x00,                          // input sample rate 48000
      0x00, 0x00,                                      // output gain
      0x00,                                            // channel mapping family
  };
  REQUIRE_EQ(expected.size(), 19u);
  OGG_CHECK_BYTES(head, expected);
}

TEST_CASE("OggOpusWriter refuses a non-48 kHz input sample rate") {
  // RFC 7845 fixes the granule on the 48 kHz clock, and OpusHead's own
  // sample-rate field is informational, so a 16 kHz input would build a
  // granule timeline off by a factor of three and still look well formed. The
  // frozen writePacket() signature takes a bare uint64_t, which carries no
  // sample rate, so open() is the only place this can be caught -- and a
  // caller that ignored the failed open() still cannot write, because there is
  // no open writer to write to.
  TempFile file("layanalyzer_oggopus_non_48k.opus");
  OggOpusOptions options;
  options.input_sample_rate = 16000;  // e.g. an AMR-WB or G.722 source

  OggOpusWriter writer;
  std::string error;
  CHECK_FALSE(writer.open(file.path(), options, error));
  CHECK_FALSE(error.empty());

  const std::vector<uint8_t> packet(4, 0x11);
  std::string write_error;
  CHECK_FALSE(writer.writePacket(packet.data(), packet.size(), 960, write_error));
  CHECK_FALSE(write_error.empty());

  // Fail-closed: no file was created at all, rather than an empty one that a
  // caller might mistake for a successful write.
  CHECK_FALSE(std::filesystem::exists(file.path()));

  // The refusal left the writer usable: a second open() with a supported rate
  // succeeds and produces a real file.
  options.input_sample_rate = 48000;
  CHECK(writer.open(file.path(), options, error));
  CHECK(writer.finalize(error));
  CHECK(std::filesystem::exists(file.path()));
}

TEST_CASE("OggOpusWriter rejects an empty packet") {
  // An Opus packet is never zero octets (RFC 6716 section 3.2), so this is a
  // caller bug rather than a stream to write. The EOS page is the only page
  // with an empty segment table, and it is not a packet.
  TempFile file("layanalyzer_oggopus_empty_packet.opus");
  OggOpusWriter writer;
  std::string error;
  REQUIRE(writer.open(file.path(), OggOpusOptions(), error));

  const std::vector<uint8_t> packet(1, 0x00);
  std::string empty_error;
  CHECK_FALSE(writer.writePacket(packet.data(), 0, 960, empty_error));
  CHECK_FALSE(empty_error.empty());

  std::string null_error;
  CHECK_FALSE(writer.writePacket(nullptr, 4, 960, null_error));
  CHECK_FALSE(null_error.empty());

  // The writer survived both refusals and still takes a real packet; if the
  // refusals had poisoned the stream this finalize() would fail.
  CHECK(writer.writePacket(packet.data(), packet.size(), 960, error));
  CHECK(writer.finalize(error));
}

TEST_CASE("OggOpusWriter guards its state machine") {
  TempFile file("layanalyzer_oggopus_guards.opus");
  TempFile other("layanalyzer_oggopus_guards_second.opus");
  OggOpusWriter writer;
  std::string error;

  // Not open yet: neither the packet writer nor finalize() may pretend.
  const std::vector<uint8_t> packet(4, 0x5A);
  CHECK_FALSE(writer.writePacket(packet.data(), packet.size(), 960, error));
  CHECK_FALSE(error.empty());
  CHECK_FALSE(writer.finalize(error));
  CHECK_FALSE(error.empty());
  CHECK_FALSE(std::filesystem::exists(file.path()));

  // An empty path is refused before anything is created.
  CHECK_FALSE(writer.open("", OggOpusOptions(), error));
  CHECK_FALSE(error.empty());

  REQUIRE(writer.open(file.path(), OggOpusOptions(), error));

  // Opening twice is refused, and the refusal must leave the first stream
  // usable rather than closing it behind the caller's back.
  std::string second_error;
  CHECK_FALSE(writer.open(other.path(), OggOpusOptions(), second_error));
  CHECK_FALSE(second_error.empty());
  CHECK(writer.writePacket(packet.data(), packet.size(), 960, error));

  REQUIRE(writer.finalize(error));

  // finalize() is idempotent: the second call writes no page and still says
  // the stream is complete.
  CHECK(writer.finalize(error));

  // A packet after finalize() is an error, not a silently dropped write.
  std::string late_error;
  CHECK_FALSE(writer.writePacket(packet.data(), packet.size(), 1920, late_error));
  CHECK_FALSE(late_error.empty());

  std::vector<uint8_t> bytes;
  REQUIRE(read_file(file.path(), bytes));
  std::vector<Page> pages;
  REQUIRE(parse_pages(bytes, pages));
  // OpusHead, OpusTags, the one packet that was accepted, the EOS page: the
  // second finalize() added nothing.
  REQUIRE_EQ(pages.size(), 4u);
  CHECK_EQ(pages[3].sequence, 3u);
  CHECK_EQ(pages[3].header_type, kHeaderEos);
  CHECK_FALSE(std::filesystem::exists(other.path()));

  // A packet longer than a page can describe is refused rather than truncated.
  // A page holds at most 255 lacing values, so with the terminator counted the
  // largest single-packet page is 65024 octets -- 254 whole segments of 255
  // plus a final segment of 254. 65025 is 255 * 255, which would need 256.
  TempFile big("layanalyzer_oggopus_too_large.opus");
  OggOpusWriter large_writer;
  REQUIRE(large_writer.open(big.path(), OggOpusOptions(), error));
  std::vector<uint8_t> oversized(65025, 0x7E);
  std::string large_error;
  CHECK_FALSE(large_writer.writePacket(oversized.data(), oversized.size(), 960, large_error));
  CHECK_FALSE(large_error.empty());
  std::vector<uint8_t> boundary(65024, 0x7E);
  CHECK(large_writer.writePacket(boundary.data(), boundary.size(), 960, error));
  CHECK(large_writer.finalize(error));

  std::vector<uint8_t> large_bytes;
  REQUIRE(read_file(big.path(), large_bytes));
  std::vector<Page> large_pages;
  REQUIRE(parse_pages(large_bytes, large_pages));
  REQUIRE_EQ(large_pages.size(), 4u);
  REQUIRE_EQ(large_pages[2].lacing.size(), 255u);
  CHECK_EQ(large_pages[2].lacing[0], 255u);
  CHECK_EQ(large_pages[2].lacing[253], 255u);
  CHECK_EQ(large_pages[2].lacing[254], 254u);   // 65024 = 254 * 255 + 254
  CHECK_EQ(large_pages[2].body.size(), 65024u);
  CHECK_EQ(large_pages[2].stored_crc, recomputed_crc(large_bytes, large_pages[2]));
}

TEST_CASE("OggOpusWriter golden bytes for a fixed input") {
  // The section 5.2 acceptance item: a fixed input has to produce a
  // byte-identical file. This input is the smallest one that still exercises
  // every page the writer emits -- open with fixed options, write no packets,
  // finalize -- so the golden is the OpusHead page, the OpusTags page and the
  // EOS page.
  //
  // kGoldenOpus was produced by running this writer once, then decoding the
  // result page by page and checking every header field by hand against
  // RFC 3533 / RFC 7845 and recomputing all three CRCs with the independent
  // long-division implementation above; it is not hand-written, and it is not
  // copied from an external tool. The field assertions after the byte
  // comparison repeat that reading so the array is not an opaque blob whose
  // only evidence is that it matches itself.
  static const uint8_t kGoldenOpus[] = {
      0x4F, 0x67, 0x67, 0x53, 0x00, 0x02, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x59,
      0x41, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x5A, 0x29,
      0x31, 0xF7, 0x01, 0x13, 0x4F, 0x70, 0x75, 0x73,
      0x48, 0x65, 0x61, 0x64, 0x01, 0x01, 0x38, 0x01,
      0x80, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4F,
      0x67, 0x67, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x59, 0x41,
      0x4C, 0x01, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x53,
      0x1D, 0x01, 0x1D, 0x4F, 0x70, 0x75, 0x73, 0x54,
      0x61, 0x67, 0x73, 0x0D, 0x00, 0x00, 0x00, 0x4C,
      0x61, 0x79, 0x65, 0x72, 0x41, 0x6E, 0x61, 0x6C,
      0x79, 0x7A, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00,
      0x4F, 0x67, 0x67, 0x53, 0x00, 0x04, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x59,
      0x41, 0x4C, 0x02, 0x00, 0x00, 0x00, 0x3E, 0x77,
      0x1F, 0xFF, 0x00,
  };
  const std::vector<uint8_t> expected(kGoldenOpus,
                                      kGoldenOpus + sizeof(kGoldenOpus));

  TempFile file("layanalyzer_oggopus_golden.opus");
  OggOpusWriter writer;
  std::string error;
  REQUIRE(writer.open(file.path(), OggOpusOptions(), error));
  REQUIRE(writer.finalize(error));

  std::vector<uint8_t> bytes;
  REQUIRE(read_file(file.path(), bytes));
  REQUIRE_EQ(bytes.size(), 131u);
  OGG_CHECK_BYTES(bytes, expected);

  // The same bytes read back as pages, so the fields the acceptance item names
  // are asserted individually as well.
  std::vector<Page> pages;
  REQUIRE(parse_pages(bytes, pages));
  REQUIRE_EQ(pages.size(), 3u);

  CHECK_EQ(pages[0].header_type, kHeaderBos);
  CHECK_EQ(pages[0].granule, 0u);
  CHECK_EQ(pages[0].sequence, 0u);
  CHECK_EQ(pages[0].serial, kExpectedSerial);
  CHECK_EQ(pages[0].stored_crc, 0xF731295Au);
  CHECK_EQ(pages[0].stored_crc, recomputed_crc(bytes, pages[0]));

  CHECK_EQ(pages[1].header_type, 0u);
  CHECK_EQ(pages[1].granule, 0u);
  CHECK_EQ(pages[1].sequence, 1u);
  CHECK_EQ(pages[1].stored_crc, 0x1D53D233u);
  CHECK_EQ(pages[1].stored_crc, recomputed_crc(bytes, pages[1]));

  CHECK_EQ(pages[2].header_type, kHeaderEos);
  CHECK_EQ(pages[2].granule, 0u);   // no packet was written, so the granule is 0
  CHECK_EQ(pages[2].sequence, 2u);
  CHECK_EQ(pages[2].stored_crc, 0xFF1F773Eu);
  CHECK_EQ(pages[2].stored_crc, recomputed_crc(bytes, pages[2]));
  CHECK(pages[2].lacing.empty());
  CHECK(pages[2].body.empty());

  // OpusHead: magic, version, channels, pre-skip, input sample rate, output
  // gain, channel mapping family.
  const std::vector<uint8_t> &head = pages[0].body;
  REQUIRE_EQ(head.size(), 19u);
  CHECK_EQ(std::string(reinterpret_cast<const char *>(head.data()), 8), "OpusHead");
  CHECK_EQ(head[8], 1u);
  CHECK_EQ(head[9], 1u);
  CHECK_EQ(static_cast<uint32_t>(head[10]) | (static_cast<uint32_t>(head[11]) << 8), 312u);
  CHECK_EQ(read_le32(head, 12), 48000u);
  // Two octets, not read_le32(): the gain field is the last-but-one in the
  // 19-octet packet, and a 32-bit read there would run one octet past the end.
  CHECK_EQ(static_cast<int16_t>(static_cast<uint16_t>(head[16]) |
                                (static_cast<uint16_t>(head[17]) << 8)),
           0);
  CHECK_EQ(head[18], 0u);

  // OpusTags: magic, vendor length, the vendor text with no NUL terminator,
  // and a comment count of zero.
  const std::vector<uint8_t> &tags = pages[1].body;
  REQUIRE_EQ(tags.size(), 29u);
  CHECK_EQ(std::string(reinterpret_cast<const char *>(tags.data()), 8), "OpusTags");
  CHECK_EQ(read_le32(tags, 8), 13u);
  CHECK_EQ(std::string(reinterpret_cast<const char *>(tags.data()) + 12, 13),
           "LayerAnalyzer");
  CHECK_EQ(read_le32(tags, 25), 0u);
}
