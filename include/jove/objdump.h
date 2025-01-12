#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <typename Alloc, bool MT>
struct objdump_output_t : public ip_base_rw_accessible_spin<MT> {
  using allocator_type = Alloc;

  template <typename _Alloc>
  using bitset_type = boost::dynamic_bitset<uint32_t, _Alloc>;
  using bitset_t = bitset_type<Alloc>;

private:
  taddr_t begin = ~0UL;
  bitset_t good;

  template <typename Alloc2, bool MT2> friend struct objdump_output_t;

public:
  template <typename... Args>
  objdump_output_t(Args &&...args) : good(std::forward<Args>(args)...) {}

  template <bool MT2>
  objdump_output_t(const objdump_output_t<Alloc, MT2> &other) noexcept
      : begin(other.begin), good(other.good) {}

  template <bool MT2>
  objdump_output_t(objdump_output_t<Alloc, MT2> &&other) noexcept
      : begin(other.begin), good(std::move(other.good)) {}

  template <bool MT2>
  objdump_output_t &operator=(objdump_output_t<Alloc, MT2> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    begin = std::move(other.begin);
    good = std::move(other.good);
    return *this;
  }

  template <bool MT2>
  objdump_output_t &operator=(const objdump_output_t<Alloc, MT2> &other) noexcept {
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

  bool is_addr_good(taddr_t addr) const {
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

  bool is_addr_bad(taddr_t addr) const { return !is_addr_good(addr); }

  static int generate(objdump_output_t &out, const char *filename,
                      llvm::object::Binary &Bin);
};
