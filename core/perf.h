#pragma once
#include "mmap.h"
#include "likely.h"

#include <memory>
#include <functional>
#include <cassert>

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

struct data_reader {
  struct {
    std::unique_ptr<scoped_fd> fd;
    std::unique_ptr<scoped_mmap> mmap;
  } contents;

  data_reader(const char *filename);
  ~data_reader();

  const struct header &get_header() const {
    return *reinterpret_cast<struct header *>(contents.mmap->ptr);
  }

  bool check_magic(void) const;

  const uint8_t *data_begin(void) {
    return reinterpret_cast<uint8_t *>(contents.mmap->ptr) +
           get_header().data.offset;
  }

  const uint8_t *data_end(void) {
    return data_begin() + get_header().data.size;
  }

  void
  for_each_auxtrace(std::function<bool(const struct auxtrace_event &)> proc) {
    const uint8_t *const beg = data_begin();
    const uint8_t *const end = data_end();

    const uint8_t *p = beg;
    while (unlikely(p != end)) {
      assert(p < end);

      auto &hdr = *reinterpret_cast<const struct perf_event_header *>(p);
      if (hdr.type == PERF_RECORD_EVENT_TYPE_AUXTRACE) {
        auto &aux = *reinterpret_cast<const struct auxtrace_event *>(p);
        if (unlikely(!proc(aux)))
          return;
        p += aux.size;
      }

      assert(hdr.size);
      p += hdr.size;
    }
  }
};

}
}
