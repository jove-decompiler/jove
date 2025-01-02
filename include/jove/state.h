#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

template <typename BinaryStateTy = void,
          typename FunctionStateTy = void,
          typename BasicBlockStateTy = void,
          bool MultiThreaded = true,
          bool LazyInitialization = true,
          bool Eager = false,
          bool BoundsChecking = true,
          bool MT = true>
class jv_state_t {
  static_assert(!std::is_void_v<BinaryStateTy> ||
                !std::is_void_v<FunctionStateTy> ||
                !std::is_void_v<BasicBlockStateTy>,
                "At least one of the state types must be non-void.");

  static_assert(!(!BoundsChecking && !Eager),
                "If no bounds checking must be eager");

  const jv_base_t<MT> &jv;

  static constexpr bool IsContainerVec =
      (LazyInitialization && !MultiThreaded) || Eager;
  static constexpr bool CanReserve = IsContainerVec;

  static_assert(sizeof(binary_index_t) <= sizeof(uint32_t));
  static_assert(sizeof(function_index_t) <= sizeof(uint32_t));
  static_assert(sizeof(basic_block_index_t) <= sizeof(uint32_t));

  typedef boost::container::vector_options<
      boost::container::stored_size<uint32_t>>::type VectorOptions;
  typedef boost::container::deque_options<
      boost::container::stored_size<uint32_t>>::type DequeOptions;

  template <typename T>
  using DequeAlloc = boost::container::adaptive_pool<T>;
  template <typename T>
  using VectorAlloc = boost::container::allocator<T>;

  template <typename T>
  using ContainerType = std::conditional_t<
      IsContainerVec,
      boost::container::vector<T, VectorAlloc<T>, VectorOptions>,
      boost::container::deque<T, DequeAlloc<T>, DequeOptions>>;

  template <typename T>
  using StatePtr = std::conditional_t<
      LazyInitialization,
      std::conditional_t<MultiThreaded, std::atomic<std::shared_ptr<T>>,
                         std::unique_ptr<T>>,
      T>;

  using BinaryState =
      std::conditional_t<std::is_void_v<BinaryStateTy>, std::monostate,
                         StatePtr<BinaryStateTy>>;
  using FunctionStateContainer =
      std::conditional_t<std::is_void_v<FunctionStateTy>, std::monostate,
                         ContainerType<StatePtr<FunctionStateTy>>>;
  using BasicBlockStateContainer =
      std::conditional_t<std::is_void_v<BasicBlockStateTy>, std::monostate,
                         ContainerType<StatePtr<BasicBlockStateTy>>>;

  using StateTuple =
      std::tuple<BinaryState, FunctionStateContainer, BasicBlockStateContainer>;
  using StateContainer = ContainerType<StateTuple>;

  StateContainer x;

  using MutexType =
      std::conditional_t<MultiThreaded, std::shared_mutex, std::monostate>;
  mutable MutexType mtx;

  using shared_lock_guard =
      std::conditional_t<MultiThreaded, std::shared_lock<std::shared_mutex>,
                         __do_nothing_t>;

  using exclusive_lock_guard =
      std::conditional_t<MultiThreaded, std::unique_lock<std::shared_mutex>,
                         __do_nothing_t>;

  shared_lock_guard shared_access() const { return shared_lock_guard{mtx}; }
  exclusive_lock_guard exclusive_access() const { return exclusive_lock_guard{mtx}; }

  template <typename T> struct StatePtrRefHelper {
    using type = StatePtr<T> &;
  };

  template <> struct StatePtrRefHelper<void> {
    using type = void;
  };

  template <typename T> using StatePtrRef = typename StatePtrRefHelper<T>::type;

public:
  explicit jv_state_t(const jv_base_t<MT> &jv) : jv(jv) {
    if constexpr (Eager)
      update();
  }

  void update(void) /* accomodate everything */
    requires(Eager)
  {
    const unsigned N_B = jv.Binaries.size();

    if constexpr (LazyInitialization) {
      x = StateContainer(N_B);
    } else {
      if constexpr (CanReserve)
        x.reserve(N_B);

      for (binary_index_t BIdx = x.size(); BIdx < N_B; ++BIdx) {
        const binary_base_t<MT> &b = jv.Binaries.at(BIdx);

        if constexpr (std::is_void_v<BinaryStateTy>) {
          x.emplace_back();
        } else {
          x.emplace_back(b, FunctionStateContainer(), BasicBlockStateContainer());
        }
      }
    }

    for (binary_index_t BIdx = 0; BIdx < N_B; ++BIdx) {
      const binary_base_t<MT> &b = jv.Binaries.at(BIdx);

      StateTuple &y = x.at(BIdx);

      if constexpr (!std::is_void_v<FunctionStateTy>) {
        const unsigned N_F = b.Analysis.Functions.size();

        FunctionStateContainer &state_vec = std::get<1>(y);

        if constexpr (LazyInitialization) {
          state_vec = FunctionStateContainer(N_F);
        } else {
          if constexpr (CanReserve)
            state_vec.reserve(N_F);

          for (function_index_t FIdx = state_vec.size(); FIdx < N_F; ++FIdx) {
            const function_t &f = b.Analysis.Functions.at(FIdx);

            state_vec.emplace_back(f, b);
          }
        }
      }

      if constexpr (!std::is_void_v<BasicBlockStateTy>) {
        const unsigned N_BB = b.Analysis.ICFG.num_vertices();

        BasicBlockStateContainer &state_vec = std::get<2>(y);

        if constexpr (LazyInitialization) {
          state_vec = BasicBlockStateContainer(N_BB);
        } else {
          if constexpr (CanReserve)
            state_vec.reserve(N_BB);

          for (basic_block_index_t BBIdx = state_vec.size(); BBIdx < N_BB; ++BBIdx) {
            basic_block_t bb = basic_block_of_index<MT>(BBIdx, b.Analysis.ICFG);

            state_vec.emplace_back(b, bb);
          }
        }
      }
    }
  }

  void update(const binary_base_t<MT> &b) /* accomodate b */
    requires(!Eager && !std::is_void_v<BinaryStateTy>)
  {
    const binary_index_t BIdx = index_of_binary<MT>(b, jv);
    if (BIdx < x.size())
      return; /* no action required */

    const unsigned N_B = BIdx + 1;
    if constexpr (LazyInitialization) {
      x.resize(N_B);
    } else {
      if constexpr (CanReserve)
        x.reserve(N_B);

      for (binary_index_t BIdx = x.size(); BIdx < N_B - 1; ++BIdx) {
        if constexpr (std::is_void_v<BinaryStateTy>) {
          x.emplace_back();
        } else {
          x.emplace_back(jv.Binaries.at(BIdx), FunctionStateContainer(), BasicBlockStateContainer());
        }
      }

      // we already have a reference to b
      if constexpr (std::is_void_v<BinaryStateTy>) {
        x.emplace_back();
      } else {
        x.emplace_back(b, FunctionStateContainer(), BasicBlockStateContainer());
      }
    }
  }

  void update(const binary_base_t<MT> &b, const function_t &f,
              FunctionStateContainer &y) /* accomodate f */
    requires(!Eager && !std::is_void_v<FunctionStateTy>)
  {
    const function_index_t FIdx = index_of_function_in_binary<MT>(f, b);
    if (FIdx < y.size())
      return; /* no action required */

    const unsigned N_F = FIdx + 1;
    if constexpr (LazyInitialization) {
      y.resize(N_F);
    } else {
      if constexpr (CanReserve)
        y.reserve(N_F);

      for (function_index_t FIdx = y.size(); FIdx < N_F - 1; ++FIdx)
        y.emplace_back(b.Analysis.Functions.at(FIdx), b);

      // we already have a reference to f
      y.emplace_back(f, b);
    }
  }

  void update(const binary_base_t<MT> &b, basic_block_t bb,
              BasicBlockStateContainer &y) /* accomodate bb */
    requires(!Eager && !std::is_void_v<BasicBlockStateTy>)
  {
    const basic_block_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);
    if (BBIdx < y.size())
      return; /* no action required */

    const unsigned N_BB = BBIdx + 1;
    if constexpr (LazyInitialization) {
      y.resize(N_BB);
    } else {
      if constexpr (CanReserve)
        y.reserve(N_BB);

      for (basic_block_index_t BBIdx = y.size(); BBIdx < N_BB - 1; ++BBIdx)
        y.emplace_back(b, basic_block_of_index<MT>(BBIdx, b.Analysis.ICFG));

      // we already have bb
      y.emplace_back(b, bb);
    }
  }

public:

#define FOR_SOMETHING_BODY(thing)                                              \
  if constexpr (LazyInitialization) {                                          \
    StatePtr<T> &x = __for_##thing(BOOST_PP_CAT(thing,_GET_ARGS));             \
    if constexpr (MultiThreaded) {                                             \
      {                                                                        \
        std::shared_ptr<T> the_x = x.load(std::memory_order_relaxed);          \
        T *const xp = the_x.get();                                             \
        if (likely(xp))                                                        \
          return *xp;                                                          \
      }                                                                        \
                                                                               \
      std::shared_ptr<T> new_x = std::allocate_shared<T>(boost::container::adaptive_pool<T>(), BOOST_PP_CAT(thing,_NEW_ARGS));\
      std::shared_ptr<T> expected;                                             \
      if (x.compare_exchange_strong(expected, new_x,                           \
                                    std::memory_order_relaxed,                 \
                                    std::memory_order_relaxed)) {              \
        return *new_x;                                                         \
      }                                                                        \
      return *expected;                                                        \
    } else {                                                                   \
      T *xp = x.get();                                                         \
      if (unlikely(!xp)) {                                                     \
        auto new_x = std::make_unique<T>(BOOST_PP_CAT(thing,_NEW_ARGS));       \
        xp = new_x.get();                                                      \
        x = std::move(new_x);                                                  \
      }                                                                        \
      return *xp;                                                              \
    }                                                                          \
  } else {                                                                     \
    return __for_##thing(BOOST_PP_CAT(thing,_GET_ARGS));                       \
  }

  template <typename T = BinaryStateTy>
  std::enable_if_t<!std::is_void_v<T>, T &> for_binary(const binary_base_t<MT> &b) {
#define binary_GET_ARGS b
#define binary_NEW_ARGS b
    FOR_SOMETHING_BODY(binary)
#undef binary_GET_ARGS
#undef binary_NEW_ARGS
  }

  template <typename T = FunctionStateTy>
  std::enable_if_t<!std::is_void_v<T>, T &> for_function(const function_t &f) {
#define function_GET_ARGS f
#define function_NEW_ARGS f, binary_of_function<MT>(f, jv)
    FOR_SOMETHING_BODY(function)
#undef function_GET_ARGS
#undef function_NEW_ARGS
  }

  template <typename T = BasicBlockStateTy>
  std::enable_if_t<!std::is_void_v<T>, T &> for_basic_block(const binary_base_t<MT> &b,
                                                            basic_block_t bb) {
#define basic_block_GET_ARGS b, bb
#define basic_block_NEW_ARGS b, bb
    FOR_SOMETHING_BODY(basic_block)
#undef basic_block_GET_ARGS
#undef basic_block_NEW_ARGS
  }

#undef FOR_SOMETHING_BODY

private:
  StatePtrRef<BinaryStateTy> __for_binary(const binary_base_t<MT> &b)
    requires(!std::is_void_v<BinaryStateTy>)
  {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        return std::get<0>(x.at(index_of_binary<MT>(b, jv)));
      } else {
        auto s_lck = shared_access();

        binary_index_t BIdx = index_of_binary<MT>(b, jv);
        if (unlikely(BIdx >= x.size())) {
          s_lck.unlock();
          {
            auto e_lck = exclusive_access();
            update(b);
          }
          s_lck.lock();
        }
        return std::get<0>(x[BIdx]);
      }
    } else {
      return std::get<0>(x[index_of_binary<MT>(b, jv)]);
    }
  }

  StatePtrRef<FunctionStateTy> __for_function(const function_t &f)
    requires(!std::is_void_v<FunctionStateTy>)
  {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        binary_index_t BIdx = binary_index_of_function<MT>(f, jv);
        function_index_t FIdx = index_of_function(f);

        return std::get<1>(x.at(BIdx)).at(FIdx);
      } else {
        auto s_lck = shared_access();

        binary_index_t BIdx = binary_index_of_function<MT>(f, jv);
        if (unlikely(BIdx >= x.size())) {
          s_lck.unlock();
          {
            auto e_lck = exclusive_access();
            update(binary_of_function<MT>(f, jv));
          }
          s_lck.lock();
        }
        FunctionStateContainer &y = std::get<1>(x[BIdx]);
        function_index_t FIdx = index_of_function(f);
        if (unlikely(FIdx >= y.size())) {
          s_lck.unlock();
          {
            auto e_lck = exclusive_access();
            update(binary_of_function<MT>(f, jv), f, y);
          }
          s_lck.lock();
        }
        return y[FIdx];
      }
    } else {
      binary_index_t BIdx = binary_index_of_function<MT>(f, jv);
      function_index_t FIdx = index_of_function(f);

      return std::get<1>(x[BIdx])[FIdx];
    }
  }

  StatePtrRef<BasicBlockStateTy> __for_basic_block(const binary_base_t<MT> &b,
                                                   basic_block_t bb)
    requires(!std::is_void_v<BasicBlockStateTy>)
  {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        binary_index_t BIdx = index_of_binary<MT>(b, jv);
        basic_block_index_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);

        return std::get<2>(x.at(BIdx)).at(BBIdx);
      } else {
        auto s_lck = shared_access();

        binary_index_t BIdx = index_of_binary<MT>(b, jv);
        if (unlikely(BIdx >= x.size())) {
          s_lck.unlock();
          {
            auto e_lck = exclusive_access();
            update(b);
          }
          s_lck.lock();
        }
        BasicBlockStateContainer &y = std::get<2>(x[BIdx]);
        basic_block_index_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);
        if (unlikely(BBIdx >= y.size())) {
          s_lck.unlock();
          {
            auto e_lck = exclusive_access();
            update(b, bb, y);
          }
          s_lck.lock();
        }
        return y[BBIdx];
      }
    } else {
      binary_index_t BIdx = index_of_binary<MT>(b, jv);
      basic_block_index_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);

      return std::get<2>(x[BIdx])[BBIdx];
    }
  }
};
