#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

constexpr taddr_t invalid_taddr = std::numeric_limits<taddr_t>::max();

#ifdef NDEBUG
constexpr taddr_t uninit_taddr = invalid_taddr;
constexpr bool is_taddr_init(taddr_t) { return true; }
#else
constexpr taddr_t uninit_taddr = invalid_taddr - 1;
constexpr bool is_taddr_init(taddr_t Addr) { return Addr != uninit_taddr; }
#endif

static inline std::string taddr2str(taddr_t x, bool zero_padded = true) {
  std::stringstream stream;
  stream << "0x";
  if (zero_padded)
    stream << std::setfill('0') << std::setw(sizeof(taddr_t) * 2);
  stream << std::hex << x;
  return stream.str();
}

constexpr bool is_taddr_valid(taddr_t Addr) {
#ifdef NDEBUG
  // the following is equivalent to Addr != 0UL && Addr != ~0UL
  return !!((Addr + taddr_t(1)) & taddr_t(~1ull));
#else
  // same as the top except also covers uninit_taddr (and one **)
  return !!((Addr + taddr_t(2)) & taddr_t(~3ull));
#endif
}

