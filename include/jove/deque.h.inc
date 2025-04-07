#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <typename T, typename Alloc,
          bool MT = true,
          bool Spin = true,
          bool PointUnique = false>
struct deque : public ip_base_rw_accessible<MT, Spin> {
  typedef boost::container::deque_options<
      boost::container::stored_size<uint32_t>>::type DequeOptions;

  using type = boost::interprocess::deque<T, Alloc, DequeOptions>;

  std::conditional_t<PointUnique, ip_unique_ptr<type>, type> _deque;

  const type &container(void) const {
    if constexpr (PointUnique)
      return *_deque;
    else
      return _deque;
  }
  type &container(void) {
    if constexpr (PointUnique)
      return *_deque;
    else
      return _deque;
  }

  deque() = delete;

  deque(jv_file_t &jv_file)
    requires(PointUnique)
      : _deque(boost::interprocess::make_managed_unique_ptr(
            jv_file.construct<type>(boost::interprocess::anonymous_instance)(
                jv_file.get_segment_manager()),
            jv_file)) {}

  deque(jv_file_t &jv_file)
    requires(!PointUnique)
      : _deque(jv_file.get_segment_manager()) {}

  template <bool MT2, bool Spin2>
  deque(deque<T, Alloc, MT2, Spin2, PointUnique> &&other) noexcept
      : _deque(std::move(other._deque)) {}

  template <bool MT2, bool Spin2>
  deque &operator=(deque<T, Alloc, MT2, Spin2, PointUnique> &&other) noexcept {
    if constexpr (MT == MT2) {
      if (this == &other)
        return *this;
    }

    _deque = std::move(other._deque);
    return *this;
  }

  unsigned size(void) const {
    auto s_lck = this->shared_access();
    return container().size();
  }

  bool empty(void) const { return size() == 0; }

  T &at(unsigned idx) {
    auto s_lck = this->shared_access();
    return container().at(idx);
  }

  const T &at(unsigned idx) const {
    auto s_lck = this->shared_access();
    return container().at(idx);
  }

  void clear(void) {
    auto e_lck = this->exclusive_access();

    container().clear();
  }

  /* FIXME */
  typename type::const_iterator cbegin(void) const { return container().cbegin(); }
  typename type::const_iterator cend(void) const { return container().cend(); }

  typename type::const_iterator begin(void) const { return cbegin(); }
  typename type::const_iterator end(void) const { return cend(); }

  typename type::iterator begin(void) { return container().begin(); }
  typename type::iterator end(void) { return container().end(); }
};


