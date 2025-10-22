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
          bool SubjectToChange = true,
          bool MT = true,
          bool MinSize = true>
struct jv_state_t {
  static_assert(!std::is_void_v<BinaryStateTy> ||
                !std::is_void_v<FunctionStateTy> ||
                !std::is_void_v<BasicBlockStateTy>,
                "At least one of the state types must be non-void.");

  static_assert(!(!BoundsChecking && !Eager),
                "If no bounds checking must be eager");

  static_assert(!(!BoundsChecking && SubjectToChange),
                "If no bounds checking must not be subject to change");

  const jv_base_t<MT, MinSize> &jv;
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;

private:
  //
  // Eager implies no chance of dangling references. Similarily, lazy
  // initialization means that references to state contents will never be
  // invalidated.
  //
  static constexpr bool IsContainerVec = Eager || LazyInitialization;
  static constexpr bool CanReserve = IsContainerVec;

  template <typename T>
  using ContainerType =
      std::conditional_t<IsContainerVec, std::vector<T>, std::deque<T>>;

  template <typename T>
  using StatePtr = std::conditional_t<
      LazyInitialization,
      std::conditional_t<MultiThreaded,
                         atomic_unique_ptr<T>,
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
                         nop_t>;

  using exclusive_lock_guard =
      std::conditional_t<MultiThreaded, std::unique_lock<std::shared_mutex>,
                         nop_t>;

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
  explicit jv_state_t(const jv_base_t<MT, MinSize> &jv) : jv(jv) {
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
        const binary_base_t<MT, MinSize> &b = jv.Binaries.at(BIdx);

        if constexpr (std::is_void_v<BinaryStateTy>) {
          x.emplace_back();
        } else {
          x.emplace_back(b, FunctionStateContainer(), BasicBlockStateContainer());
        }
      }
    }

    for (binary_index_t BIdx = 0; BIdx < N_B; ++BIdx) {
      const binary_base_t<MT, MinSize> &b = jv.Binaries.at(BIdx);

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
            bb_t bb = basic_block_of_index<MT>(BBIdx, b.Analysis.ICFG);

            state_vec.emplace_back(b, bb);
          }
        }
      }
    }
  }

  void update(const binary_base_t<MT, MinSize> &b) /* accomodate b */
    requires(!Eager && !std::is_void_v<BinaryStateTy>)
  {
    const unsigned N = x.size();

    const binary_index_t BIdx = index_of_binary<MT>(b, jv);
    if (BIdx < N)
      return; /* no action required */

    const unsigned N_B = BIdx + 1;
    if constexpr (LazyInitialization) {
      x.resize(std::max<unsigned>(N_B, N));
    } else {
      if constexpr (CanReserve)
        x.reserve(N_B);

      for (binary_index_t TheBIdx = N; TheBIdx < BIdx; ++TheBIdx) {
        if constexpr (std::is_void_v<BinaryStateTy>) {
          x.emplace_back();
        } else {
          x.emplace_back(jv.Binaries.at(TheBIdx), FunctionStateContainer(), BasicBlockStateContainer());
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

  void update(const binary_base_t<MT, MinSize> &b, const function_t &f,
              FunctionStateContainer &y) /* accomodate f */
    requires(!Eager && !std::is_void_v<FunctionStateTy>)
  {
    const unsigned N = y.size();

    const function_index_t FIdx = index_of_function_in_binary<MT>(f, b);
    if (FIdx < N)
      return; /* no action required */

    const unsigned N_F = FIdx + 1;
    if constexpr (LazyInitialization) {
      y.resize(std::max<unsigned>(N_F, N));
    } else {
      if constexpr (CanReserve)
        y.reserve(N_F);

      for (function_index_t TheFIdx = N; TheFIdx < FIdx; ++TheFIdx)
        y.emplace_back(b.Analysis.Functions.at(TheFIdx), b);

      // we already have a reference to f
      y.emplace_back(f, b);
    }
  }

  void update(const binary_base_t<MT, MinSize> &b, bb_t bb,
              BasicBlockStateContainer &y) /* accomodate bb */
    requires(!Eager && !std::is_void_v<BasicBlockStateTy>)
  {
    const unsigned N = y.size();

    const basic_block_index_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);
    if (BBIdx < N)
      return; /* no action required */

    const unsigned N_BB = BBIdx + 1;
    if constexpr (LazyInitialization) {
      y.resize(std::max<unsigned>(N_BB, N));
    } else {
      if constexpr (CanReserve)
        y.reserve(N_BB);

      for (basic_block_index_t TheBBIdx = N; TheBBIdx < BBIdx; ++TheBBIdx)
        y.emplace_back(b, basic_block_of_index<MT>(TheBBIdx, b.Analysis.ICFG));

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
        T *const xp = x.load(boost::memory_order_acquire);                     \
        if (likely(xp))                                                        \
          return *xp;                                                          \
      }                                                                        \
                                                                               \
      auto new_x = std::make_unique<T>(BOOST_PP_CAT(thing,_NEW_ARGS));         \
                                                                               \
      T *expected = nullptr;                                                   \
      T *const desired = new_x.get();                                          \
      if (x.compare_exchange_strong(expected, desired,                         \
                                    boost::memory_order_release,               \
                                    boost::memory_order_acquire)) {            \
        new_x.release();                                                       \
        return *desired;                                                       \
      }                                                                        \
      assert(expected);                                                        \
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
  std::enable_if_t<!std::is_void_v<T>, T &>
  for_binary(const binary_base_t<MT, MinSize> &b) {
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
  std::enable_if_t<!std::is_void_v<T>, T &>
  for_basic_block(const binary_base_t<MT, MinSize> &b, bb_t bb) {
#define basic_block_GET_ARGS b, bb
#define basic_block_NEW_ARGS b, bb
    FOR_SOMETHING_BODY(basic_block)
#undef basic_block_GET_ARGS
#undef basic_block_NEW_ARGS
  }

#undef FOR_SOMETHING_BODY
#undef CREATE_SHARED

private:
  StatePtrRef<BinaryStateTy> __for_binary(const binary_base_t<MT, MinSize> &b)
    requires(!std::is_void_v<BinaryStateTy>)
  {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        if constexpr (SubjectToChange) {
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
          return std::get<0>(x.at(index_of_binary<MT>(b, jv)));
        }
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
        if constexpr (SubjectToChange) {
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
          binary_index_t BIdx = binary_index_of_function<MT>(f, jv);
          function_index_t FIdx = index_of_function(f);

          return std::get<1>(x.at(BIdx)).at(FIdx);
        }
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

  StatePtrRef<BasicBlockStateTy>
  __for_basic_block(const binary_base_t<MT, MinSize> &b, bb_t bb)
    requires(!std::is_void_v<BasicBlockStateTy>)
  {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        if constexpr (SubjectToChange) {
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
          binary_index_t BIdx = index_of_binary<MT>(b, jv);
          basic_block_index_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);

          return std::get<2>(x.at(BIdx)).at(BBIdx);
        }
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
