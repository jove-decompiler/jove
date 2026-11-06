#pragma once
#include "jove/jove.h"

#include <ranges>

#include <boost/container/small_vector.hpp>

#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/SmallVector.h>

namespace jove {
namespace B {

template <typename extra_t = std::monostate> struct section_t;
template <typename extra_t = std::monostate> struct sections_t;

template <typename extra_t>
using section_vec_t = llvm::SmallVector<section_t<extra_t>, 32>;

namespace cached {
template <typename extra_t>
void from_svec(sections_t<extra_t> &, const section_vec_t<extra_t> &);
}

template <typename extra_t>
struct section_t {
private:
  const addr_intvl oi, ai;

  friend void cached::from_svec<extra_t>(sections_t<extra_t> &,
                                         const section_vec_t<extra_t> &);

public:
  section_t(const taddr_t off_, const taddr_t size_,
            const taddr_t addr_, const taddr_t length_)
    : oi(off_, size_),
      ai(addr_, length_)
  {}

  taddr_t off(void)  const { return oi.first;  }
  taddr_t size(void) const { return oi.second; } /* number of bytes in file */

  taddr_t addr(void)   const { return ai.first; }
  taddr_t length(void) const { return ai.second; } /* number of bytes in memory */

  struct {
    unsigned r : 1;
    unsigned w : 1;
    unsigned x : 1;
  } perm;

  struct {
    unsigned init   : 1;
    unsigned fini   : 1;
    unsigned nobits : 1;
  } _elf;

  llvm::StringRef Name;

  extra_t extra;
};

struct section_cmp {
  using is_transparent = void;

  bool operator()(const addr_intvl &lhs, const addr_intvl &rhs) const {
    return lhs.first < rhs.first;
  }

  bool operator()(const addr_intvl &lhs, taddr_t rhs) const {
    return lhs.first < rhs;
  }

  bool operator()(taddr_t lhs, const addr_intvl &rhs) const {
    return lhs < rhs.first;
  }
};

using section_omap_t = boost::container::flat_map<addr_intvl, unsigned, addr_intvl_cmp>;
using section_amap_t = boost::container::flat_map<addr_intvl, unsigned, addr_intvl_cmp>;

template <typename extra_t>
struct sections_t {
  section_omap_t omap;
  section_amap_t amap;

  section_vec_t<extra_t> svec; /* unsorted (original order) */

  auto sorted_by_addr() {
    return amap |
           std::views::transform([this](auto &entry) -> section_t<extra_t> & {
             return svec[entry.second];
           });
  }
};

}
}
