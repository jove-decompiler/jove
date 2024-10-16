#pragma once

namespace jove {

template <typename BinaryStateTy = void,
          typename FunctionStateTy = void,
          typename BasicBlockStateTy = void,
          bool MultiThreaded = true,
          bool LazyInitialization = true,
          bool Eager = false,
          bool BoundsChecking = true>
class jv_state_t {
  static_assert(!std::is_void_v<BinaryStateTy> ||
                    !std::is_void_v<FunctionStateTy> ||
                    !std::is_void_v<BasicBlockStateTy>,
                "At least one of the state types must be non-void.");
  static_assert(!(!BoundsChecking && !Eager),
                "If no bounds checking must be eager");

private:
  const jv_t &jv;

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
  explicit jv_state_t(const jv_t &jv) : jv(jv) {
    if constexpr (Eager) {
      update();
    } else {
      if constexpr (!MultiThreaded)
        x.reserve(jv.Binaries.size());
    }
  }

  void update(void) {
    unsigned N_B = jv.Binaries.size();

    if constexpr (!MultiThreaded)
      x.reserve(N_B);

    for (binary_index_t BIdx = x.size(); BIdx < N_B; ++BIdx) {
      const binary_t &b = jv.Binaries.at(BIdx);

      if constexpr (std::is_void_v<BinaryStateTy>) {
        x.emplace_back();
      } else {
        if constexpr (LazyInitialization) {
          x.emplace_back();
        } else {
          x.emplace_back(b, FunctionStateContainer(), BasicBlockStateContainer());
        }
      }

      auto &bin_stuff = x.back();

      if constexpr (!std::is_void_v<FunctionStateTy>) {
        unsigned N_F = b.Analysis.Functions.size();

        FunctionStateContainer &state_vec = std::get<1>(bin_stuff);

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

        BasicBlockStateContainer &state_vec = std::get<2>(bin_stuff);

        if constexpr (!MultiThreaded)
          state_vec.reserve(N_BB);

        for (basic_block_index_t BBIdx = state_vec.size(); BBIdx < N_BB; ++BBIdx) {
          basic_block_t bb = basic_block_of_index(BBIdx, b.Analysis.ICFG);

          if constexpr (LazyInitialization) {
            state_vec.emplace_back();
          } else {
            state_vec.emplace_back(b, bb);
          }
        }
      }
    }
  }

  void update(const binary_t &b) {
    binary_index_t BIdx = index_of_binary(b, jv);
    unsigned N_B = BIdx + 1;

    if constexpr (!MultiThreaded)
      x.reserve(N_B);

    for (binary_index_t BIdx = x.size(); BIdx < N_B; ++BIdx) {
      const binary_t &b = jv.Binaries.at(BIdx);

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
  }

  template <typename T = FunctionStateTy>
  std::enable_if_t<!std::is_void_v<T>, void> update(const function_t &f) {
    const binary_index_t BIdx = binary_index_of_function(f, jv);
    const binary_t &b = jv.Binaries.at(BIdx);
    update(b);

    auto &bin_stuff = x.at(BIdx);

    function_index_t FIdx =
        index_of_function_in_binary(f, jv.Binaries.at(BIdx));

    unsigned N_F = FIdx + 1;

    FunctionStateContainer &state_vec = std::get<1>(bin_stuff);

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

  template <typename T = BasicBlockStateTy>
  std::enable_if_t<!std::is_void_v<T>, void> update(const binary_t &b,
                                                    basic_block_t bb) {
    const binary_index_t BIdx = index_of_binary(b, jv);
    update(b);

    auto &bin_stuff = x.at(BIdx);

    basic_block_index_t BBIdx = index_of_basic_block(b.Analysis.ICFG, bb);
    unsigned N_BB = BBIdx + 1;

    BasicBlockStateContainer &state_vec = std::get<2>(bin_stuff);

    if constexpr (!MultiThreaded)
      state_vec.reserve(N_BB);

    for (basic_block_index_t BBIdx = state_vec.size(); BBIdx < N_BB; ++BBIdx) {
      basic_block_t bb = basic_block_of_index(BBIdx, b.Analysis.ICFG);

      if constexpr (LazyInitialization) {
        state_vec.emplace_back();
      } else {
        state_vec.emplace_back(b, bb);
      }
    }
  }

public:
  template <typename T = BinaryStateTy>
  std::enable_if_t<!std::is_void_v<T>, T &> for_binary(const binary_t &b) {
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
        y = std::make_unique<FunctionStateTy>(
            f, jv.Binaries.at(binary_index_of_function(f, jv)));
      return *y;
    } else {
      return __for_function(f);
    }
  }

  template <typename T = BasicBlockStateTy>
  std::enable_if_t<!std::is_void_v<T>, T &> for_basic_block(const binary_t &b,
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
  __for_binary(const binary_t &b) {
    if constexpr (BoundsChecking) {
      try {
        MaybeSharableLock lck(mtx);

        return std::get<0>(x.at(index_of_binary(b, jv)));
      } catch (const std::out_of_range &ex) {}
      {
        MaybeExclusiveLock lck(mtx);
        if constexpr (Eager)
          update();
        else
          update(b);
      }
      __attribute__((musttail)) return __for_binary(b);
    } else {
      return std::get<0>(x[index_of_binary(b, jv)]);
    }
  }

  template <typename T = FunctionStateTy>
  std::enable_if_t<!std::is_void_v<T>,
                   std::conditional_t<std::is_void_v<T>, void, StatePtr<T> &>>
  __for_function(const function_t &f) {
    if constexpr (BoundsChecking) {
      try {
        MaybeSharableLock lck(mtx);

        binary_index_t BIdx = binary_index_of_function(f, jv);
        function_index_t FIdx = index_of_function_in_binary(f, jv.Binaries.at(BIdx));

        return std::get<1>(x.at(BIdx)).at(FIdx);
      } catch (const std::out_of_range &ex) {}
      {
        MaybeExclusiveLock lck(mtx);
        if constexpr (Eager)
          update();
        else
          update(f);
      }
      __attribute__((musttail)) return __for_function(f);
    } else {
      binary_index_t BIdx = binary_index_of_function(f, jv);
      function_index_t FIdx = index_of_function_in_binary(f, jv.Binaries.at(BIdx));

      return std::get<1>(x[BIdx])[FIdx];
    }
  }

  template <typename T = BasicBlockStateTy>
  std::enable_if_t<!std::is_void_v<T>,
                   std::conditional_t<std::is_void_v<T>, void, StatePtr<T> &>>
  __for_basic_block(const binary_t &b, basic_block_t bb) {
    if constexpr (BoundsChecking) {
      try {
        MaybeSharableLock lck(mtx);

        binary_index_t BIdx = index_of_binary(b, jv);
        basic_block_index_t BBIdx = index_of_basic_block(b.Analysis.ICFG, bb);

        return std::get<2>(x.at(BIdx)).at(BBIdx);
      } catch (const std::out_of_range &ex) {}
      {
        MaybeExclusiveLock lck(mtx);
        if constexpr (Eager)
          update();
        else
          update(b, bb);
      }
      __attribute__((musttail)) return __for_basic_block(b, bb);
    } else {
      binary_index_t BIdx = index_of_binary(b, jv);
      basic_block_index_t BBIdx = index_of_basic_block(b.Analysis.ICFG, bb);

      return std::get<2>(x[BIdx])[BBIdx];
    }
  }
};
}
