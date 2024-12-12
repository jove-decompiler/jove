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

  template <typename T>
  using ContainerType =
      std::conditional_t<MultiThreaded, std::deque<T>, std::vector<T>>;

  template <typename T>
  using StatePtr =
      std::conditional_t<LazyInitialization, std::unique_ptr<T>, T>;

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

  using MaybeSharableLock =
      std::conditional_t<MultiThreaded, std::shared_lock<std::shared_mutex>,
                         __do_nothing_t>;

  using MaybeExclusiveLock =
      std::conditional_t<MultiThreaded, std::unique_lock<std::shared_mutex>,
                         __do_nothing_t>;

public:
  explicit jv_state_t(const jv_base_t<MT> &jv) : jv(jv) {
    if constexpr (Eager)
      update();
  }

  void update(void) {
    unsigned N_B = jv.Binaries.size();

    for (binary_index_t BIdx = x.size(); BIdx < N_B; ++BIdx) {
      if constexpr (!MultiThreaded)
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

        if constexpr (!MultiThreaded)
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

        if constexpr (!MultiThreaded)
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
    if constexpr (!MultiThreaded)
      x.reserve(jv.Binaries.size());

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
    if constexpr (!MultiThreaded)
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
    if constexpr (!MultiThreaded)
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
  template <typename T = BinaryStateTy>
  std::enable_if_t<!std::is_void_v<T>, T &> for_binary(const binary_base_t<MT> &b) {
    if constexpr (LazyInitialization) {
      std::unique_ptr<BinaryStateTy> &y = __for_binary(b);
      if (unlikely(!y))
        y = std::make_unique<BinaryStateTy>(b);
      return *y;
    } else {
      return __for_binary(b);
    }
  }

  template <typename T = FunctionStateTy>
  std::enable_if_t<!std::is_void_v<T>, T &> for_function(const function_t &f) {
    if constexpr (LazyInitialization) {
      std::unique_ptr<FunctionStateTy> &y = __for_function(f);
      if (unlikely(!y))
        y = std::make_unique<FunctionStateTy>(f, binary_of_function<MT>(f));
      return *y;
    } else {
      return __for_function(f);
    }
  }

  template <typename T = BasicBlockStateTy>
  std::enable_if_t<!std::is_void_v<T>, T &> for_basic_block(const binary_base_t<MT> &b,
                                                            basic_block_t bb) {
    if constexpr (LazyInitialization) {
      std::unique_ptr<BasicBlockStateTy> &y = __for_basic_block(b, bb);
      if (unlikely(!y))
        y = std::make_unique<BasicBlockStateTy>(b, bb);
      return *y;
    } else {
      return __for_basic_block(b, bb);
    }
  }

private:
  template <typename T = BinaryStateTy>
  std::enable_if_t<!std::is_void_v<T>,
                   std::conditional_t<std::is_void_v<T>, void, StatePtr<T> &>>
  __for_binary(const binary_base_t<MT> &b) {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        try {
          MaybeSharableLock s_lck(mtx);

          return std::get<0>(x.at(index_of_binary<MT>(b, jv)));
        } catch (const std::out_of_range &ex) {}
        {
          MaybeExclusiveLock e_lck(mtx);
          update();
        }
        __attribute__((musttail)) return __for_binary(b);
      } else {
        MaybeSharableLock s_lck(mtx);

        binary_index_t BIdx = index_of_binary<MT>(b, jv);
        if (unlikely(BIdx >= x.size())) {
          s_lck.unlock();
          {
            MaybeExclusiveLock e_lck(mtx);
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
          MaybeSharableLock lck(mtx);

          binary_index_t BIdx = binary_index_of_function<MT>(f, jv);
          function_index_t FIdx = index_of_function(f);

          return std::get<1>(x.at(BIdx)).at(FIdx);
        } catch (const std::out_of_range &ex) {}
        {
          MaybeExclusiveLock lck(mtx);
          update();
        }
        __attribute__((musttail)) return __for_function(f);
      } else {
        MaybeSharableLock s_lck(mtx);

        binary_index_t BIdx = binary_index_of_function<MT>(f, jv);
        if (unlikely(BIdx >= x.size())) {
          s_lck.unlock();
          {
            MaybeExclusiveLock e_lck(mtx);
            update(binary_of_function<MT>(f));
          }
          s_lck.lock();
        }
        FunctionStateContainer &y = std::get<1>(x[BIdx]);
        function_index_t FIdx = index_of_function(f);
        if (unlikely(FIdx >= y.size())) {
          s_lck.unlock();
          {
            MaybeExclusiveLock e_lck(mtx);
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

  template <typename T = BasicBlockStateTy>
  std::enable_if_t<!std::is_void_v<T>,
                   std::conditional_t<std::is_void_v<T>, void, StatePtr<T> &>>
  __for_basic_block(const binary_base_t<MT> &b, basic_block_t bb) {
    if constexpr (BoundsChecking) {
      if constexpr (Eager) {
        try {
          MaybeSharableLock lck(mtx);

          binary_index_t BIdx = index_of_binary<MT>(b, jv);
          basic_block_index_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);

          return std::get<2>(x.at(BIdx)).at(BBIdx);
        } catch (const std::out_of_range &ex) {}
        {
          MaybeExclusiveLock lck(mtx);
          update();
        }
        __attribute__((musttail)) return __for_basic_block(b, bb);
      } else {
        MaybeSharableLock s_lck(mtx);

        binary_index_t BIdx = index_of_binary<MT>(b, jv);
        if (unlikely(BIdx >= x.size())) {
          s_lck.unlock();
          {
            MaybeExclusiveLock e_lck(mtx);
            update(b);
          }
          s_lck.lock();
        }
        BasicBlockStateContainer &y = std::get<2>(x[BIdx]);
        basic_block_index_t BBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);
        if (unlikely(BBIdx >= y.size())) {
          s_lck.unlock();
          {
            MaybeExclusiveLock e_lck(mtx);
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
