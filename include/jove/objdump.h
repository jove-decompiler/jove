#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <bool MultiThreaded = false,
          typename Alloc = std::allocator<unsigned long>>
class objdump_output_t {
  using allocator_type = Alloc;

  template <typename _Alloc>
  using bitset_type = boost::dynamic_bitset<unsigned long, _Alloc>;
  using bitset_t = bitset_type<Alloc>;

  template <typename _Alloc>
  void bits_assign_slow(const bitset_type<_Alloc> &other) {
    std::vector<unsigned long> blocks(other.num_blocks()); /* make a copy */
    boost::to_block_range(other, blocks.begin());

    this->good = bitset_t(blocks.begin(), blocks.end());
    this->good.resize(other.size());
  }

public:
  taddr_t begin = ~0UL;
  bitset_t good;

  mutable std::conditional_t<MultiThreaded, ip_sharable_mutex, std::monostate>
      mtx;

  template <typename... Args>
  objdump_output_t(Args &&...args) : good(std::forward<Args>(args)...) {}

  objdump_output_t(const objdump_output_t &other)
      : begin(other.begin), good(other.good) {}

  template <bool _MultiThreaded>
  objdump_output_t(const objdump_output_t<_MultiThreaded, Alloc> &other)
      : begin(other.begin), good(other.good) {}

  template <bool _MultiThreaded, typename _Alloc>
  objdump_output_t(const objdump_output_t<_MultiThreaded, _Alloc> &other)
      : begin(other.begin) {
    bits_assign_slow(other.good);
  }

  objdump_output_t(objdump_output_t &&other)
      : begin(other.begin), good(other.good.get_allocator()) {
    good = other.good;
  }

  objdump_output_t &operator=(const objdump_output_t &other) {
    if (this != &other) {
      this->begin = other.begin;
      this->good = other.good;
    }
    return *this;
  }

  template <bool _MultiThreaded>
  objdump_output_t &operator=(const objdump_output_t<_MultiThreaded, Alloc> &other) {
    if (this != &other) {
      this->begin = other.begin;
      this->good = other.good;
    }
    return *this;
  }

  template <bool _MultiThreaded, typename _Alloc>
  objdump_output_t &
  operator=(const objdump_output_t<_MultiThreaded, _Alloc> &other) {
    this->begin = other.begin;
    bits_assign_slow(other.good);
    return *this;
  }

  bool empty(void) const {
    std::conditional_t<MultiThreaded, ip_sharable_lock<ip_sharable_mutex>,
                       __do_nothing_t>
        s_lck(mtx);

    return good.empty();
  }

  bool is_addr_good(taddr_t addr) const {
    std::conditional_t<MultiThreaded, ip_sharable_lock<ip_sharable_mutex>,
                       __do_nothing_t>
        s_lck(mtx);

    if (addr < begin)
      return true; /* who knows? */
    taddr_t idx = addr - begin;
    if (idx >= good.size())
      return true; /* who knows? */
    return good.test(idx);
  }

  bool is_addr_bad(taddr_t addr) const { return !is_addr_good(addr); }
};
