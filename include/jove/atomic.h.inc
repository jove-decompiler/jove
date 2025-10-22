#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <typename T>
using ip_atomic = boost::atomics::ipc_atomic<T>;
using ip_atomic_flag = boost::atomics::ipc_atomic_flag;

template <typename T>
class atomic_offset_ptr {
  static constexpr uint64_t null = 1u;

  ip_atomic<uint64_t> off = null;

  void takeFrom(atomic_offset_ptr &other) noexcept {
    const uint64_t newo = other.off.exchange(null, boost::memory_order_acquire);
    const uint64_t oldo = off.exchange(newo, boost::memory_order_release);

    (void)oldo;
  }

public:
  atomic_offset_ptr() noexcept = default;
  atomic_offset_ptr(std::nullptr_t) noexcept {}
  explicit atomic_offset_ptr(atomic_offset_ptr &&other) noexcept {
    takeFrom(other);
  }

  atomic_offset_ptr &operator=(atomic_offset_ptr &&other) noexcept {
    if (this != &other)
      takeFrom(other);

    return *this;
  }

  atomic_offset_ptr(const atomic_offset_ptr &) = delete;
  atomic_offset_ptr &operator=(const atomic_offset_ptr &) = delete;

  ~atomic_offset_ptr() noexcept = default;

  T *load(boost::memory_order memoryOrder = boost::memory_order_seq_cst) const volatile noexcept {
    return static_cast<T *>(
        boost::interprocess::ipcdetail::offset_ptr_to_raw_pointer(
            this, off.load(memoryOrder)));
  }

  void store(T *ptr,
             boost::memory_order memoryOrder = boost::memory_order_seq_cst) volatile noexcept {
    off.store(
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            ptr, this),
        memoryOrder);
  }

  bool compare_exchange_strong(T *&expected, T *desired,
                               boost::memory_order success,
                               boost::memory_order failure) volatile noexcept {

    uint64_t expected_off =
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            expected, this);

    bool res = off.compare_exchange_strong(
        expected_off,
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            desired, this),
        success, failure);

    expected = static_cast<T *>(
        boost::interprocess::ipcdetail::offset_ptr_to_raw_pointer(
            this, expected_off));

    return res;
  }

  T *exchange(T *desired, boost::memory_order order =
                              boost::memory_order_seq_cst) volatile noexcept {
    uint64_t desired_off =
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            desired, this);

    const uint64_t other_off = this->off.exchange(desired_off, order);
    return static_cast<T *>(
        boost::interprocess::ipcdetail::offset_ptr_to_raw_pointer(this,
                                                                  other_off));
  }
};

// this is a dangerous class.
template <typename T>
class atomic_unique_ptr {
  ip_atomic<T *> ptr = nullptr;

  void takeFrom(atomic_unique_ptr &other) noexcept {
    T *const newp = other.ptr.exchange(nullptr, boost::memory_order_acquire);
    T *const oldp = ptr.exchange(newp, boost::memory_order_release);
    delete oldp;
  }

public:
  atomic_unique_ptr() noexcept = default;
  explicit atomic_unique_ptr(T *p) noexcept : ptr(p) {}
  explicit atomic_unique_ptr(atomic_unique_ptr &&other) noexcept {
    takeFrom(other);
  }

  atomic_unique_ptr &operator=(atomic_unique_ptr &&other) noexcept {
    if (this != &other)
      takeFrom(other);

    return *this;
  }

  atomic_unique_ptr(const atomic_unique_ptr &) = delete;
  atomic_unique_ptr &operator=(const atomic_unique_ptr &) = delete;

  ~atomic_unique_ptr() {
    delete ptr.load(boost::memory_order_relaxed);
  }

  T *load(boost::memory_order order = boost::memory_order_acquire) noexcept {
    return ptr.load(order);
  }

  bool compare_exchange_strong(T *&expected,
                               T *desired,
                               boost::memory_order success,
                               boost::memory_order failure) noexcept {
    return ptr.compare_exchange_strong(expected, desired, success, failure);
  }
};
