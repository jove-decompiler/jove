#include "vdso.h"
#include "util.h"
#include <cassert>
#include <cstring>

namespace jove {

std::pair<void *, unsigned> GetVDSO(void) {
  struct {
    void *first;
    unsigned second;
  } res;

  res.first = nullptr;
  res.second = 0;

  std::string maps = read_file_into_string("/proc/self/maps");
  assert(!maps.empty());

  unsigned n = maps.size();
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = (char *)memchr(line, '\n', left);

    //
    // second hex address
    //
    if (eol[-1] == ']' &&
        eol[-2] == 'o' &&
        eol[-3] == 's' &&
        eol[-4] == 'd' &&
        eol[-5] == 'v' &&
        eol[-6] == '[') {
      char *const dash = (char *)memchr(line, '-', left);
      assert(dash);

      char *const space = (char *)memchr(line, ' ', left);
      assert(space);

      *dash = '\0';
      uintptr_t min = strtoul(line, nullptr, 0x10);

      *space = '\0';
      uintptr_t max = strtoul(dash + 1, nullptr, 0x10);

      res.first = (void *)min;
      res.second = max - min;
      break;
    }
  }

  return std::make_pair(res.first, res.second);
}

}
