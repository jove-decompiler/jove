#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <typename T>
class AtomicOffsetPtr {
public:
  AtomicOffsetPtr() : m_offset(1) {}

  AtomicOffsetPtr(const AtomicOffsetPtr &) = delete;
  AtomicOffsetPtr &operator=(const AtomicOffsetPtr &) = delete;

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
