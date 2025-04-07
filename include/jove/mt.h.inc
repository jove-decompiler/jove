#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

typedef boost::interprocess::managed_mapped_file jv_file_t;
typedef jv_file_t::segment_manager segment_manager_t;

template <typename T>
using ip_unique_ptr = boost::interprocess::managed_unique_ptr<T, jv_file_t>::type;

typedef boost::interprocess::allocator<void, segment_manager_t>
    ip_void_allocator_t;

//
// mutexes & locks
//

typedef boost::interprocess::interprocess_mutex ip_mutex;
typedef boost::interprocess::interprocess_sharable_mutex ip_sharable_mutex;
typedef boost::interprocess::interprocess_upgradable_mutex ip_upgradable_mutex;

template <typename Mutex>
using ip_scoped_lock = boost::interprocess::scoped_lock<Mutex>;
template <typename Mutex>
using ip_sharable_lock = boost::interprocess::sharable_lock<Mutex>;
template <typename Mutex>
using ip_upgradable_lock = boost::interprocess::upgradable_lock<Mutex>;

struct UnlockTool;

struct __do_nothing_t {
  template <typename... Args>
  __do_nothing_t (Args&&...) noexcept {}

  void unlock(void) const {}
  void lock(void) const {}
};

template <bool Spin>
using ip_base_mt_rw_choose_mutex =
    std::conditional_t<Spin, boost::unordered::detail::foa::rw_spinlock,
                       ip_sharable_mutex>;

template <bool Spin>
using ip_base_mt_rw_choose_sharable_lock_guard = std::conditional_t<
    Spin,
    boost::unordered::detail::foa::shared_lock<ip_base_mt_rw_choose_mutex<true>>,
    ip_sharable_lock<ip_base_mt_rw_choose_mutex<false>>>;

template <bool Spin>
using ip_base_mt_rw_choose_exclusive_lock_guard = std::conditional_t<
    Spin,
    boost::unordered::detail::foa::lock_guard<ip_base_mt_rw_choose_mutex<true>>,
    ip_scoped_lock<ip_base_mt_rw_choose_mutex<false>>>;

template <bool MT, bool Spin>
struct ip_base_rw_accessible {
  friend UnlockTool;

  using mutex_type =
      std::conditional_t<MT, ip_base_mt_rw_choose_mutex<Spin>, std::monostate>;

  mutable mutex_type mtx;

  using shared_lock_guard =
      std::conditional_t<MT, ip_base_mt_rw_choose_sharable_lock_guard<Spin>,
                         __do_nothing_t>;

  using exclusive_lock_guard =
      std::conditional_t<MT, ip_base_mt_rw_choose_exclusive_lock_guard<Spin>,
                         __do_nothing_t>;

  shared_lock_guard shared_access() const {
    return shared_lock_guard{mtx};
  }
  exclusive_lock_guard exclusive_access() const {
    return exclusive_lock_guard{mtx};
  }

  void lock_sharable(void) const {
    if constexpr (MT) {
      mtx.lock_sharable();
    }
  }

  ip_base_rw_accessible() noexcept {}
  ip_base_rw_accessible(ip_base_rw_accessible &&) noexcept {}
  ip_base_rw_accessible &operator=(ip_base_rw_accessible &&other) noexcept {
    return *this;
  }
  ip_base_rw_accessible(const ip_base_rw_accessible &) noexcept {}
  ip_base_rw_accessible &operator=(const ip_base_rw_accessible &) noexcept {
    return *this;
  }

  void __force_reset_access(void) {
    if constexpr (sizeof(mtx))
      __builtin_memset(&mtx, 0, sizeof(mtx));
  }
};

template <bool MT>
using ip_base_rw_accessible_spin = ip_base_rw_accessible<MT, true>;

template <bool MT>
using ip_base_rw_accessible_nospin = ip_base_rw_accessible<MT, false>;

template <bool Spin>
struct ip_mt_base_rw_accessible {
  friend UnlockTool;

  using mutex_type = ip_base_mt_rw_choose_mutex<Spin>;

  mutable mutex_type mtx;

  template <bool MT>
  using shared_lock_guard =
      std::conditional_t<MT, ip_base_mt_rw_choose_sharable_lock_guard<Spin>,
                         __do_nothing_t>;

  template <bool MT>
  using exclusive_lock_guard =
      std::conditional_t<MT, ip_base_mt_rw_choose_exclusive_lock_guard<Spin>,
                         __do_nothing_t>;

  template <bool MT> shared_lock_guard<MT> shared_access() const {
    return shared_lock_guard<MT>{mtx};
  }
  template <bool MT> exclusive_lock_guard<MT> exclusive_access() const {
    return exclusive_lock_guard<MT>{mtx};
  }

  template <bool MT> void lock_sharable(void) const {
    if constexpr (MT) {
      mtx.lock_sharable();
    }
  }

  ip_mt_base_rw_accessible() noexcept {}
  ip_mt_base_rw_accessible(ip_mt_base_rw_accessible &&) noexcept {}
  ip_mt_base_rw_accessible &
  operator=(ip_mt_base_rw_accessible &&other) noexcept {
    return *this;
  }
  ip_mt_base_rw_accessible(const ip_mt_base_rw_accessible &) noexcept {}
  ip_mt_base_rw_accessible &
  operator=(const ip_mt_base_rw_accessible &) noexcept {
    return *this;
  }

  void __force_reset_access(void) {
    if constexpr (sizeof(mtx))
      __builtin_memset(&mtx, 0, sizeof(mtx));
  }
};

using ip_mt_base_rw_accessible_spin = ip_mt_base_rw_accessible<true>;
using ip_mt_base_rw_accessible_nospin = ip_mt_base_rw_accessible<false>;

template <bool Spin>
using ip_base_mt_choose_mutex =
    std::conditional_t<Spin, boost::detail::spinlock, ip_mutex>;

template <bool Spin>
using ip_base_mt_choose_exclusive_lock_guard =
    std::conditional_t<Spin, boost::detail::spinlock::scoped_lock,
                       ip_scoped_lock<ip_base_mt_choose_mutex<false>>>;

template <bool Spin>
struct ip_mt_base_accessible {
  friend UnlockTool;

  using mutex_type = ip_base_mt_choose_mutex<Spin>;

  mutable mutex_type mtx;

  template <bool MT>
  using exclusive_lock_guard =
      std::conditional_t<MT, ip_base_mt_choose_exclusive_lock_guard<Spin>,
                         __do_nothing_t>;

  template <bool MT> exclusive_lock_guard<MT> exclusive_access() const {
    return exclusive_lock_guard<MT>{mtx};
  }

  ip_mt_base_accessible() noexcept requires(Spin) : mtx BOOST_DETAIL_SPINLOCK_INIT {}
  ip_mt_base_accessible() noexcept requires(!Spin) = default;

  ip_mt_base_accessible(ip_mt_base_accessible &&) noexcept {}
  ip_mt_base_accessible &operator=(ip_mt_base_accessible &&other) noexcept {
    return *this;
  }
  ip_mt_base_accessible(const ip_mt_base_accessible &) noexcept {}
  ip_mt_base_accessible &operator=(const ip_mt_base_accessible &) noexcept {
    return *this;
  }

  void __force_reset_access(void) {
    if constexpr (sizeof(mtx))
      __builtin_memset(&mtx, 0, sizeof(mtx));
  }
};

using ip_mt_base_accessible_spin = ip_mt_base_accessible<true>;
using ip_mt_base_accessible_nospin = ip_mt_base_accessible<false>;

//
// strings
//
typedef boost::interprocess::allocator<char, segment_manager_t>
    ip_char_allocator;
typedef boost::interprocess::basic_string<char, std::char_traits<char>,
                                          ip_char_allocator>
    ip_string;

static inline std::string un_ips(const ip_string &x) {
  std::string res;
  res.reserve(x.size());
  std::copy(x.begin(), x.end(), std::back_inserter(res));
  return res;
}

static inline ip_string &to_ips(ip_string &res, std::string_view x) {
  res.clear();
  res.reserve(x.size());
  std::copy(x.begin(), x.end(), std::back_inserter(res));
  return res;
}

struct ip_string_hash_t  {
  using is_transparent = void;

  template <typename A>
  std::size_t operator()(const boost::interprocess::basic_string<char, std::char_traits<char>, A> &str) const noexcept {
    return std::hash<std::string_view>{}(std::string_view(str.data(), str.size()));
  }

  std::size_t operator()(std::string_view sv) const noexcept {
    return std::hash<std::string_view>{}(sv);
  }

  std::size_t operator()(const char *s) const noexcept {
    return std::hash<std::string_view>{}(s);
  }
};

struct ip_string_equal_t {
  using is_transparent = void;

  template <typename A>
  bool operator()(
      const boost::interprocess::basic_string<char, std::char_traits<char>, A> &lhs,
      const boost::interprocess::basic_string<char, std::char_traits<char>, A> &rhs) const noexcept {
    return lhs == rhs;
  }

  template <typename A>
  bool operator()(const boost::interprocess::basic_string<char, std::char_traits<char>, A> &lhs,
      std::string_view rhs) const noexcept {
    return lhs == rhs;
  }

  template <typename A>
  bool operator()(std::string_view lhs,
                  const boost::interprocess::basic_string<char, std::char_traits<char>, A> &rhs) const noexcept {
    return lhs == rhs;
  }

  bool operator()(std::string_view lhs, std::string_view rhs) const noexcept {
    return lhs == rhs;
  }

  template <typename A>
  bool operator()(const boost::interprocess::basic_string<char, std::char_traits<char>, A> &lhs,
      const char *rhs) const noexcept {
    return lhs == rhs;
  }

  template <typename A>
  bool operator()(
      const char *lhs,
      const boost::interprocess::basic_string<char, std::char_traits<char>, A> &rhs) const noexcept {
    return lhs == rhs;
  }

  bool operator()(std::string_view lhs, const char* rhs) const noexcept {
    return lhs == rhs;
  }

  bool operator()(const char* lhs, std::string_view rhs) const noexcept {
    return lhs == rhs;
  }
};
