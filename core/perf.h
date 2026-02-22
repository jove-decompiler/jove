#pragma once
#include "mmap.h"
#include "likely.h"
#include "eintr.h"
#include "assert.h"
#include "fd.h"

#include <memory>
#include <functional>
#include <cassert>
#include <iterator>

#include <boost/filesystem.hpp>

#include <linux/perf_event.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

namespace jove {

class scoped_fd;

namespace perf {

static inline bool is_magic(uint64_t magic) {
  static const char *__magic1 = "PERFFILE";
  static const uint64_t __magic2    = 0x32454c4946524550ULL;
  static const uint64_t __magic2_sw = 0x50455246494c4532ULL;

  if (!memcmp(&magic, __magic1, sizeof(magic))
      || magic == __magic2
      || magic == __magic2_sw)
  return true;

  return false;
}

static constexpr unsigned PERF_RECORD_EVENT_TYPE_AUXTRACE = 71;

struct file_section {
  uint64_t offset; /* offset from start of file */
  uint64_t size;   /* size of the section */
};

struct header {
  char magic[8];      /* PERFILE2 */
  uint64_t size;      /* size of the header */
  uint64_t attr_size; /* size of an attribute in attrs */
  struct file_section attrs;
  struct file_section data;
  struct file_section event_types;
  uint64_t flags;
  uint64_t flags1[3];
};

struct auxtrace_event {
  struct perf_event_header header;
  uint64_t size;
  uint64_t offset;
  uint64_t reference;
  uint32_t idx;
  uint32_t tid;
  uint32_t cpu;
  uint32_t reserved__; /* For alignment */
};

class event_iterator {
  const struct perf_event_header *current;

public:
  using iterator_category = std::forward_iterator_tag;

  using difference_type = std::ptrdiff_t;
  using value_type = struct perf_event_header;
  using pointer = value_type *;
  using reference = value_type &;

  event_iterator() = default;
  event_iterator(const struct perf_event_header *current) : current(current) {}

  event_iterator &operator++() {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(current);

    const auto &hdr = *current;
#if 0
    if (hdr.type == PERF_RECORD_EVENT_TYPE_AUXTRACE) {
      auto &aux = *reinterpret_cast<const struct auxtrace_event *>(current);
      p += aux.size;
    }
#endif

    assert(hdr.size);
    p += hdr.size;

    current = reinterpret_cast<const struct perf_event_header *>(p);
    return *this;
  }

  event_iterator operator++(int) {
    event_iterator temp = *this;
    ++(*this);
    return temp;
  }

  bool operator==(const event_iterator other) const {
    return current == other.current;
  }

  bool operator!=(const event_iterator other) const {
    return !(*this == other);
  }

  const struct perf_event_header &operator*() const { return *current; }
  const struct perf_event_header *operator->() const { return current; }
};

static_assert(std::forward_iterator<event_iterator>);

template <bool HasHeader>
struct data_reader {
  struct contents_t {
    scoped_fd fd;
    scoped_mmap mmap;

    contents_t(int fd, size_t len)
        : fd(fd), mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0) {}
  } contents;

  data_reader(const char *filename, bool sequential = true)
      : contents(sys::retry_eintr(::open, filename, O_RDONLY),
                 boost::filesystem::file_size(filename)) {
    if constexpr (HasHeader)
      aassert(check_magic());

    if (sequential)
      aassert(::madvise(contents.mmap.get(), contents.mmap.size(),
                        MADV_SEQUENTIAL) == 0);
  }

  ~data_reader() = default;

  template <bool H = HasHeader, typename = std::enable_if_t<H>>
  const struct header &get_header() const {
    return *reinterpret_cast<struct header *>(contents.mmap.get());
  }

  template <bool H = HasHeader, typename = std::enable_if_t<H>>
  bool check_magic(void) const {
    return is_magic(*reinterpret_cast<const uint64_t *>(&get_header().magic[0]));
  }

  const uint8_t *data_begin(void) const {
    if constexpr (HasHeader)
      return reinterpret_cast<const uint8_t *>(contents.mmap.get()) +
             get_header().data.offset;
    else
      return reinterpret_cast<const uint8_t *>(contents.mmap.get());
  }

  const uint8_t *data_end(void) const {
    if constexpr (HasHeader)
      return data_begin() + get_header().data.size;
    else
      return data_begin() + contents.mmap.size();
  }

  event_iterator begin(void) const {
    return reinterpret_cast<const struct perf_event_header *>(data_begin());
  }

  event_iterator end(void) const {
    return reinterpret_cast<const struct perf_event_header *>(data_end());
  }

  bool
  for_each_auxtrace(std::function<bool(const struct auxtrace_event &)> proc) const {
    const uint8_t *const beg = data_begin();
    const uint8_t *const end = data_end();

    const uint8_t *p = beg;
    while (unlikely(p != end)) {
      assert(p < end);

      auto &hdr = *reinterpret_cast<const struct perf_event_header *>(p);
      if (hdr.type == PERF_RECORD_EVENT_TYPE_AUXTRACE) {
        auto &aux = *reinterpret_cast<const struct auxtrace_event *>(p);
        if (unlikely(!proc(aux)))
          return false;
        p += aux.size;
      }

      assert(hdr.size);
      p += hdr.size;
    }

    return true;
  }
};

}
}
