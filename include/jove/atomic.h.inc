#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <typename T>
class AtomicOffsetPtr {
public:
  AtomicOffsetPtr() : m_offset(1) {}

  AtomicOffsetPtr(const AtomicOffsetPtr &other) {
    Store(other.Load(std::memory_order_relaxed), std::memory_order_relaxed);
  }

  AtomicOffsetPtr &operator=(const AtomicOffsetPtr &other) {
    Store(other.Load(std::memory_order_relaxed), std::memory_order_relaxed);
    return *this;
  }

  AtomicOffsetPtr(AtomicOffsetPtr &&other) {
    Store(other.Load(std::memory_order_relaxed), std::memory_order_relaxed);
    other.Store(nullptr, std::memory_order_relaxed);
  }

  AtomicOffsetPtr &operator=(AtomicOffsetPtr &&other) {
    Store(other.Load(std::memory_order_relaxed), std::memory_order_relaxed);
    other.Store(nullptr, std::memory_order_relaxed);
    return *this;
  }

  T *Load(std::memory_order memoryOrder = std::memory_order_seq_cst) const {
    return static_cast<T *>(
        boost::interprocess::ipcdetail::offset_ptr_to_raw_pointer(
            this, m_offset.load(memoryOrder)));
  }

  void Store(T *ptr,
             std::memory_order memoryOrder = std::memory_order_seq_cst) {
    m_offset.store(
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            ptr, this),
        memoryOrder);
  }

  bool CompareExchangeStrong(T *&expected, T *desired,
                             std::memory_order success,
                             std::memory_order failure) {

    uint64_t expected_off =
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            expected, this);

    bool res = m_offset.compare_exchange_strong(
        expected_off,
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            desired, this),
        success, failure);

    expected = static_cast<T *>(
        boost::interprocess::ipcdetail::offset_ptr_to_raw_pointer(
            this, expected_off));

    return res;
  }

  bool CompareExchangeWeak(T *&expected, T *desired,
                           std::memory_order success,
                           std::memory_order failure) {

    uint64_t expected_off =
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            expected, this);

    bool res = m_offset.compare_exchange_weak(
        expected_off,
        boost::interprocess::ipcdetail::offset_ptr_to_offset<std::uintptr_t>(
            desired, this),
        success, failure);

    expected = static_cast<T *>(
        boost::interprocess::ipcdetail::offset_ptr_to_raw_pointer(
            this, expected_off));

    return res;
  }

private:
  std::atomic<std::uint64_t> m_offset;
};

// this is a dangerous class.
template <typename T>
class atomic_unique_ptr {
  std::atomic<T *> ptr = nullptr;

  void takeFrom(atomic_unique_ptr &other) noexcept {
    T *const newp = other.ptr.exchange(nullptr, std::memory_order_acquire);
    T *const oldp = ptr.exchange(newp, std::memory_order_release);
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
    delete ptr.load(std::memory_order_relaxed);
  }

  T *load(std::memory_order order = std::memory_order_acquire) noexcept {
    return ptr.load(order);
  }

  bool compare_exchange_strong(T *&expected,
                               T *desired,
                               std::memory_order success,
                               std::memory_order failure) noexcept {
    return ptr.compare_exchange_strong(expected, desired, success, failure);
  }
};
