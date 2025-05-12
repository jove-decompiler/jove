#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <typename Alloc>
struct objdump_output_t : public ip_mt_base_rw_accessible_nospin {
  using allocator_type = Alloc;

  using type = boost::dynamic_bitset<unsigned long /* FIXME */, Alloc>;

private:
  taddr_t begin = ~0UL;
  type good;

  template <typename Alloc2> friend struct objdump_output_t;

public:
  template <typename... Args>
  objdump_output_t(Args &&...args) : good(std::forward<Args>(args)...) {}

  objdump_output_t(const objdump_output_t<Alloc> &other) noexcept
      : begin(other.begin), good(other.good) {}

  objdump_output_t(objdump_output_t<Alloc> &&other) noexcept
      : begin(other.begin), good(std::move(other.good)) {}

  objdump_output_t &operator=(objdump_output_t<Alloc> &&other) noexcept {
    if (this == &other)
      return *this;

    begin = std::move(other.begin);
    good = std::move(other.good);
    return *this;
  }

  objdump_output_t &operator=(const objdump_output_t<Alloc> &other) noexcept {
    if (this == &other)
      return *this;

    begin = other.begin;
    good = other.good;
    return *this;
  }

  template <bool MT>
  bool empty(void) const {
    auto s_lck = this->shared_access<MT>();

    return empty_unlocked();
  }

  bool empty_unlocked(void) const {
    return good.empty();
  }

  template <bool MT>
  bool is_addr_good(taddr_t addr) const {
    auto s_lck = this->shared_access<MT>();

    if (unlikely(empty_unlocked()))
      return true; /* who knows */

    if (addr < begin)
      return false;
    taddr_t idx = addr - begin;
    if (idx >= good.size())
      return false;
    return good.test(idx);
  }

  template <bool MT>
  bool is_addr_bad(taddr_t addr) const { return !is_addr_good<MT>(addr); }

  // given address is less than the minimum address reported by objdump, or
  // is greater than the biggest address
  template <bool MT>
  bool is_addr_really_bad(taddr_t addr) const {
    auto s_lck = this->shared_access<MT>();

    if (unlikely(empty_unlocked()))
      return false; /* who knows */

    if (addr < begin)
      return true;

    if (addr > begin + good.size())
      return true;

    return false;
  }

  static int generate(objdump_output_t &out, const char *filename,
                      llvm::object::Binary &Bin);
};
