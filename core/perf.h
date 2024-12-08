#pragma once
#include "mmap.h"
#include "likely.h"

#include <memory>
#include <functional>
#include <cassert>
#include <iterator>

#include <linux/perf_event.h>

namespace jove {

struct scoped_fd;

namespace perf {

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
    if (hdr.type == PERF_RECORD_EVENT_TYPE_AUXTRACE) {
      auto &aux = *reinterpret_cast<const struct auxtrace_event *>(current);
      p += aux.size;
    }

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
  struct {
    std::unique_ptr<scoped_fd> fd;
    std::unique_ptr<scoped_mmap> mmap;
  } contents;

  data_reader(const char *filename, bool sequential = true);
  ~data_reader();

  template <bool H = HasHeader, typename = std::enable_if_t<H>>
  const struct header &get_header() const {
    return *reinterpret_cast<struct header *>(contents.mmap->ptr);
  }

  template <bool H = HasHeader, typename = std::enable_if_t<H>>
  bool check_magic(void) const;

  const uint8_t *data_begin(void) const {
    if constexpr (HasHeader)
      return reinterpret_cast<const uint8_t *>(contents.mmap->ptr) +
             get_header().data.offset;
    else
      return reinterpret_cast<const uint8_t *>(contents.mmap->ptr);
  }

  const uint8_t *data_end(void) const {
    if constexpr (HasHeader)
      return data_begin() + get_header().data.size;
    else
      return data_begin() + contents.mmap->len;
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
