#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <bool MT>
struct objdump_thinks_t : public ip_base_rw_accessible_nospin<MT> {
  typedef boost::interprocess::allocator<uint32_t, segment_manager_t> alloc_type;

  typedef boost::container::vector_options<
      boost::container::stored_size<uint32_t>>::type VectorOptions;

  typedef boost::interprocess::vector<uint32_t, alloc_type, VectorOptions>
      buffer_type;

  using type = boost::dynamic_bitset<uint32_t, buffer_type>;

private:
  taddr_t begin = ~0UL;
  type good;

  template <bool> friend struct objdump_thinks_t;

public:
  objdump_thinks_t(segment_manager_t *psm) : good(alloc_type(psm)) {}

  template <bool MT2>
  objdump_thinks_t(const objdump_thinks_t<MT2> &other) noexcept
      : begin(other.begin), good(other.good) {}

  template <bool MT2>
  objdump_thinks_t(objdump_thinks_t<MT2> &&other) noexcept
      : begin(other.begin), good(std::move(other.good)) {}

  template <bool MT2>
  objdump_thinks_t &operator=(objdump_thinks_t<MT2> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    begin = std::move(other.begin);
    good = std::move(other.good);
    return *this;
  }

  template <bool MT2>
  objdump_thinks_t &
  operator=(const objdump_thinks_t<MT2> &other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    begin = other.begin;
    good = other.good;
    return *this;
  }

  bool empty(void) const {
    auto s_lck = this->shared_access();

    return empty_unlocked();
  }

  bool empty_unlocked(void) const {
    return good.empty();
  }

  bool is_addr_good(taddr_t addr) const noexcept {
    auto s_lck = this->shared_access();

    if (unlikely(empty_unlocked()))
      return true; /* who knows */

    if (addr < begin)
      return false;
    taddr_t idx = addr - begin;
    if (idx >= good.size())
      return false;
    return good.test(idx);
  }

  bool is_addr_bad(taddr_t addr) const noexcept {
    return !is_addr_good(addr);
  }

  // given address is less than the minimum address reported by objdump, or
  // is greater than the biggest address
  bool is_addr_really_bad(taddr_t addr) const {
    auto s_lck = this->shared_access();

    if (unlikely(empty_unlocked()))
      return false; /* who knows */

    if (addr < begin)
      return true;

    if (addr > begin + good.size())
      return true;

    return false;
  }

  int run(const char *filename, const B::ref &Bin);
};
