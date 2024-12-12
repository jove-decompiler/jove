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

private:
  const jv_base_t<MT> &jv;

  static constexpr bool IsContainerVec = LazyInitialization && !MultiThreaded;
  static constexpr bool CanReserve = IsContainerVec;

  template <typename T>
  using ContainerType =
      std::conditional_t<IsContainerVec, std::vector<T>, std::deque<T>>;

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

public:
  explicit jv_state_t(const jv_base_t<MT> &jv) : jv(jv) {
    if constexpr (Eager)
      update();
  }

  void update(void) {
    unsigned N_B = jv.Binaries.size();

    for (binary_index_t BIdx = x.size(); BIdx < N_B; ++BIdx) {
      if constexpr (CanReserve)
        x.reserve(N_B);

      const binary_base_t<MT> &b = jv.Binaries.at(BIdx);

      if constexpr (std::is_void_v<BinaryStateTy>) {
        x.emplace_back();
      } else {
        if constexpr (LazyInitialization) {
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
        unsigned N_F = b.Analysis.Functions.size();

        FunctionStateContainer &state_vec = std::get<1>(y);

        if constexpr (CanReserve)
          state_vec.reserve(N_F);

        for (function_index_t FIdx = state_vec.size(); FIdx < N_F; ++FIdx) {
          const function_t &f = b.Analysis.Functions.at(FIdx);

          if constexpr (LazyInitialization) {
            state_vec.emplace_back();
          } else {
            state_vec.emplace_back(f, b);
          }
        }
      }

      if constexpr (!std::is_void_v<BasicBlockStateTy>) {
        unsigned N_BB = b.Analysis.ICFG.num_vertices();

        BasicBlockStateContainer &state_vec = std::get<2>(y);

        if constexpr (CanReserve)
          state_vec.reserve(N_BB);

        for (basic_block_index_t BBIdx = state_vec.size(); BBIdx < N_BB; ++BBIdx) {
          basic_block_t bb = basic_block_of_index<MT>(BBIdx, b.Analysis.ICFG);

          if constexpr (LazyInitialization) {
            state_vec.emplace_back();
          } else {
            state_vec.emplace_back(b, bb);
          }
        }
      }
    }
  }

  void update(const binary_base_t<MT> &b) {
    if constexpr (CanReserve)
      x.reserve(CanReserve);

    unsigned N_B = index_of_binary<MT>(b, jv) + 1;

    for (binary_index_t BIdx = x.size(); BIdx < N_B - 1; ++BIdx) {
      if constexpr (std::is_void_v<BinaryStateTy>) {
        x.emplace_back();
      } else {
        if constexpr (LazyInitialization) {
          x.emplace_back();
        } else {
          x.emplace_back(jv.Binaries.at(BIdx), FunctionStateContainer(), BasicBlockStateContainer());
        }
      }
    }

    if constexpr (std::is_void_v<BinaryStateTy>) {
      x.emplace_back();
    } else {
      if constexpr (LazyInitialization) {
        x.emplace_back();
      } else {
        x.emplace_back(b, FunctionStateContainer(), BasicBlockStateContainer());
      }
    }
  }

  template <typename T = FunctionStateTy>
  std::enable_if_t<!std::is_void_v<T>, void> update(const binary_base_t<MT> &b,
                                                    const function_t &f,
                                                    FunctionStateContainer &y) {
    if constexpr (CanReserve)
      y.reserve(b.Analysis.Functions.size());

    unsigned N_F = index_of_function_in_binary<MT>(f, b) + 1;

    for (function_index_t FIdx = y.size(); FIdx < N_F - 1; ++FIdx) {
      if constexpr (LazyInitialization) {
        y.emplace_back();
      } else {
        y.emplace_back(b.Analysis.Functions.at(FIdx), b);
      }
    }

    if constexpr (LazyInitialization) {
      y.emplace_back();
    } else {
      y.emplace_back(f, b);
    }
  }

  template <typename T = BasicBlockStateTy>
  std::enable_if_t<!std::is_void_v<T>, void> update(const binary_base_t<MT> &b,
                                                    basic_block_t bb,
                                                    BasicBlockStateContainer &y) {
    if constexpr (CanReserve)
      y.reserve(b.Analysis.ICFG.num_vertices());

    unsigned N_BB = index_of_basic_block<MT>(b.Analysis.ICFG, bb) + 1;

    for (basic_block_index_t BBIdx = y.size(); BBIdx < N_BB - 1; ++BBIdx) {
      if constexpr (LazyInitialization) {
        y.emplace_back();
      } else {
        y.emplace_back(b, basic_block_of_index<MT>(BBIdx, b.Analysis.ICFG));
      }
    }

    if constexpr (LazyInitialization) {
      y.emplace_back();
    } else {
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
        if (likely(the_x))                                                     \
          return *the_x;                                                       \
      }                                                                        \
                                                                               \
      std::shared_ptr<T> new_x = std::make_shared<T>(BOOST_PP_CAT(thing,_NEW_ARGS));\
      std::shared_ptr<T> expected;                                             \
      if (x.compare_exchange_strong(expected, new_x,                           \
                                    std::memory_order_relaxed,                 \
                                    std::memory_order_relaxed)) {              \
        return *new_x;                                                         \
      }                                                                        \
      return *expected;                                                        \
    } else {                                                                   \
      if (unlikely(!x))                                                        \
        x = std::make_unique<T>(BOOST_PP_CAT(thing,_NEW_ARGS));                \
      return *x;                                                               \
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
#define function_NEW_ARGS f, binary_of_function<MT>(f)
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

private:
  template <typename T = BinaryStateTy>
  std::enable_if_t<!std::is_void_v<T>,
                   std::conditional_t<std::is_void_v<T>, void, StatePtr<T> &>>
  __for_binary(const binary_base_t<MT> &b) {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        try {
          auto s_lck = shared_access();

          return std::get<0>(x.at(index_of_binary<MT>(b, jv)));
        } catch (const std::out_of_range &ex) {}
        {
          auto e_lck = exclusive_access();
          update();
        }
        __attribute__((musttail)) return __for_binary(b);
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

  template <typename T = FunctionStateTy>
  std::enable_if_t<!std::is_void_v<T>,
                   std::conditional_t<std::is_void_v<T>, void, StatePtr<T> &>>
  __for_function(const function_t &f) {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        try {
          auto s_lck = shared_access();

          binary_index_t BIdx = binary_index_of_function<MT>(f, jv);
          function_index_t FIdx = index_of_function(f);

          return std::get<1>(x.at(BIdx)).at(FIdx);
        } catch (const std::out_of_range &ex) {}
        {
          auto e_lck = exclusive_access();
          update();
        }
        __attribute__((musttail)) return __for_function(f);
      } else {
        auto s_lck = shared_access();

        binary_index_t BIdx = binary_index_of_function<MT>(f, jv);
        if (unlikely(BIdx >= x.size())) {
          s_lck.unlock();
          {
            auto e_lck = exclusive_access();
            update(binary_of_function<MT>(f));
          }
          s_lck.lock();
        }
        FunctionStateContainer &y = std::get<1>(x[BIdx]);
        function_index_t FIdx = index_of_function(f);
        if (unlikely(FIdx >= y.size())) {
          s_lck.unlock();
          {
            auto e_lck = exclusive_access();
            update(binary_of_function<MT>(f), f, y);
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

  template <bool L = true, typename T = BasicBlockStateTy>
  std::enable_if_t<!std::is_void_v<T>,
                   std::conditional_t<std::is_void_v<T>, void, StatePtr<T> &>>
  __for_basic_block(const binary_base_t<MT> &b, basic_block_t bb) {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        try {
          auto s_lck = shared_access();

          binary_index_t BIdx = index_of_binary<MT>(b, jv);
          basic_block_index_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);

          return std::get<2>(x.at(BIdx)).at(BBIdx);
        } catch (const std::out_of_range &ex) {}
        {
          auto e_lck = exclusive_access();
          update();
        }
        __attribute__((musttail)) return __for_basic_block(b, bb);
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
