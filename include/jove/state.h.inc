#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

enum class StateOpt : uint32_t {
  LazyInitialization  = 1u << 1,
  Eager               = 1u << 2,
  SubjectToChange     = 1u << 3,
  Spin                = 1u << 4,
};

constexpr std::underlying_type_t<StateOpt>
to_underlying(StateOpt e) noexcept {
  return static_cast<std::underlying_type_t<StateOpt>>(e);
}

constexpr StateOpt operator|(StateOpt a, StateOpt b) noexcept {
  return static_cast<StateOpt>(to_underlying(a) | to_underlying(b));
}
constexpr StateOpt operator&(StateOpt a, StateOpt b) noexcept {
  return static_cast<StateOpt>(to_underlying(a) & to_underlying(b));
}
constexpr StateOpt &operator|=(StateOpt &a, StateOpt b) noexcept {
  return a = a | b;
}

static constexpr StateOpt DefaultLvl0StateOpts =
    StateOpt::LazyInitialization | StateOpt::SubjectToChange;

static constexpr StateOpt DefaultLvl1StateOpts =
    DefaultLvl0StateOpts | StateOpt::Spin;

template <typename BinaryStateTy,
          typename FunctionStateTy,
          typename BasicBlockStateTy,
          bool MT,
          bool MinSize,
          StateOpt BOpts = DefaultLvl0StateOpts, /* binary */
          StateOpt FOpts = DefaultLvl1StateOpts, /* function */
          StateOpt BBOpts = DefaultLvl1StateOpts /* bb */>
struct jv_state_t {
  static_assert(!std::is_void_v<BinaryStateTy> ||
                !std::is_void_v<FunctionStateTy> ||
                !std::is_void_v<BasicBlockStateTy>,
                "At least one of the state types must be non-void.");

  template <StateOpt Set, StateOpt Flag>
  static constexpr bool has_flag_v =
      (to_underlying(Set) & to_underlying(Flag)) != 0;

#define ____flags____(Ops)                                                     \
    constexpr bool LazyInitialization = has_flag_v<Ops, StateOpt::LazyInitialization>;       \
    constexpr bool Eager              = has_flag_v<Ops, StateOpt::Eager>;                    \
    constexpr bool SubjectToChange    = has_flag_v<Ops, StateOpt::SubjectToChange>;          \
    constexpr bool Spin               = has_flag_v<Ops, StateOpt::Spin>

  // non-contiguous container guarantees element address stability
  template <StateOpt Ops>
  static constexpr bool Contiguous =
      has_flag_v<Ops, StateOpt::LazyInitialization> ||
      (has_flag_v<Ops, StateOpt::Eager> &&
       !has_flag_v<Ops, StateOpt::SubjectToChange>) ||
      !MT;

  template <StateOpt Ops> static constexpr bool CanReserve = Contiguous<Ops>;

  const jv_base_t<MT, MinSize> &jv;
  using bb_t = typename ip_icfg_base_t<MT>::vertex_descriptor;
  using binary_t = binary_base_t<MT, MinSize>;

private:

  template <typename T, StateOpt Opts>
  using StateSlot = std::conditional_t<
      has_flag_v<Opts, StateOpt::LazyInitialization>,
      std::conditional_t<MT,
                         std_atomic_unique_ptr<T>,
                         std::unique_ptr<T>>,
      T>;

  template <typename T, StateOpt Opts>
  using ContainerType = VecOrDeque<Contiguous<Opts>, T>;

  using FunctionStateContainer =
      std::conditional_t<std::is_void_v<FunctionStateTy>,
                         std::monostate,
                         ContainerType<StateSlot<FunctionStateTy, FOpts>, FOpts>>;

  using BasicBlockStateContainer =
      std::conditional_t<std::is_void_v<BasicBlockStateTy>,
                         std::monostate,
                         ContainerType<StateSlot<BasicBlockStateTy, BBOpts>, BBOpts>>;

  template <StateOpt Opts>
  using MutexType = std::conditional_t<
      MT,
      std::conditional_t<has_flag_v<Opts, StateOpt::Spin>,
                         boost::unordered::detail::foa::rw_spinlock,
                         std::shared_mutex>,
      std::monostate>;

  struct ForBinary {
    std::conditional_t<std::is_void_v<BinaryStateTy>, std::monostate,
                       StateSlot<BinaryStateTy, BOpts>> b;

    MutexType<FOpts> fvec_mtx;
    FunctionStateContainer fvec;

    MutexType<BBOpts> bbvec_mtx;
    BasicBlockStateContainer bbvec;
  };

  std::deque<ForBinary> vec;

  mutable MutexType<BOpts> mtx;

  template <StateOpt Opts>
  using shared_lock_guard = std::conditional_t<
      MT,
      std::conditional_t<
          has_flag_v<Opts, StateOpt::Spin>,
          boost::unordered::detail::foa::shared_lock<MutexType<Opts>>,
          std::shared_lock<MutexType<Opts>>>,
      nop_t>;

  template <StateOpt Opts>
  using exclusive_lock_guard = std::conditional_t<
      MT,
      std::conditional_t<
          has_flag_v<Opts, StateOpt::Spin>,
          boost::unordered::detail::foa::lock_guard<MutexType<Opts>>,
          std::lock_guard<MutexType<Opts>>>,
      nop_t>;

  exclusive_lock_guard<BOpts> exclusive_access(void) {
    return exclusive_lock_guard<BOpts>{this->mtx};
  }
  shared_lock_guard<BOpts> shared_access(void) {
    return shared_lock_guard<BOpts>{this->mtx};
  }

  exclusive_lock_guard<FOpts> exclusive_access_f(MutexType<FOpts> &mtx) {
    return exclusive_lock_guard<FOpts>{mtx};
  }
  shared_lock_guard<FOpts> shared_access_f(MutexType<FOpts> &mtx) {
    return shared_lock_guard<FOpts>{mtx};
  }

  exclusive_lock_guard<BBOpts> exclusive_access_bb(MutexType<BBOpts> &mtx) {
    return exclusive_lock_guard<BBOpts>{mtx};
  }
  shared_lock_guard<BBOpts> shared_access_bb(MutexType<BBOpts> &mtx) {
    return shared_lock_guard<BBOpts>{mtx};
  }

  template <StateOpt Ops, StateOpt TheFlag>
  static consteval void CheckFlag(void) {
    static_assert(has_flag_v<Ops, TheFlag>);
  }

public:
  explicit jv_state_t(const jv_base_t<MT, MinSize> &jv) : jv(jv) {
    if constexpr (has_flag_v<BOpts, StateOpt::Eager>)
      eager();
  }

  void clear(void) {
    {
      auto s_lck = shared_access();
      for (ForBinary &S : vec) {
        if constexpr (!std::is_void_v<FunctionStateTy>) {
          auto e_lck = exclusive_access_f(S.fvec_mtx);
          S.fvec.clear();
        }

        if constexpr (!std::is_void_v<BasicBlockStateTy>) {
          auto e_lck = exclusive_access_bb(S.bbvec_mtx);
          S.bbvec.clear();
        }
      }
    }

    auto e_lck = exclusive_access();
    vec.clear();
  }

private:
  void eager(void)
  {
    if constexpr (!has_flag_v<BOpts, StateOpt::Eager>)
      return;

    const unsigned N_B = jv.Binaries.size();

    {
      auto b_lck = exclusive_access();

      if constexpr (has_flag_v<BOpts, StateOpt::LazyInitialization>) {
        assert(vec.size() <= N_B);
        vec.resize(N_B);
      } else {
        if constexpr (CanReserve<BOpts>)
          vec.reserve(N_B);
        for (binary_index_t BIdx = vec.size(); BIdx < N_B; ++BIdx) {
          const binary_t &b = jv.Binaries.at(BIdx);
          if constexpr (std::is_void_v<BinaryStateTy>)
            vec.emplace_back();
          else
            vec.emplace_back(b);
        }
      }
    }

    if constexpr (!has_flag_v<DefaultLvl1StateOpts, StateOpt::Eager>)
      return;

    //
    // make sure we really have it all
    //
    assert(vec.size() >= N_B);
    for (binary_index_t BIdx = 0; BIdx < N_B; ++BIdx) {
      const binary_t &b = jv.Binaries.at(BIdx);
      ForBinary &outer_state = vec[BIdx];

      if constexpr (!std::is_void_v<FunctionStateTy>) {
        auto &inner_state = outer_state.fvec;

        auto f_lck = exclusive_access_f(outer_state.fvec_mtx);
        eager_functions(inner_state, b);
      }

      if constexpr (!std::is_void_v<BasicBlockStateTy>) {
        auto &inner_state = outer_state.bbvec;

        auto bb_lck = exclusive_access_bb(outer_state.bbvec_mtx);
        eager_basic_blocks(inner_state, b);
      }
    }
  }

  void eager_functions(auto &inner_state, const binary_t &b) {
    const unsigned N_F = b.Analysis.Functions.size();

    if constexpr (has_flag_v<FOpts, StateOpt::LazyInitialization>) {
      assert(inner_state.size() <= N_F);
      inner_state.resize(N_F);
    } else {
      if constexpr (CanReserve<FOpts>)
        inner_state.reserve(N_F);

      const unsigned N = inner_state.size();

      assert(N_F >= N);
      for (function_index_t FIdx = N; FIdx < N_F; ++FIdx) {
        const function_t &f = b.Analysis.Functions.at(FIdx);

        inner_state.emplace_back(f, b);
      }
    }
  }

  void eager_basic_blocks(auto &inner_state, const binary_t &b) {
    const unsigned N_BB = b.Analysis.ICFG.num_vertices();

    if constexpr (has_flag_v<BBOpts, StateOpt::LazyInitialization>) {
      assert(inner_state.size() <= N_BB);
      inner_state.resize(N_BB);
    } else {
      if constexpr (CanReserve<BBOpts>)
        inner_state.reserve(N_BB);

      const unsigned N = inner_state.size();

      assert(N_BB >= N);
      for (function_index_t BBIdx = N; BBIdx < N_BB; ++BBIdx) {
        bb_t bb = basic_block_of_index<MT>(BBIdx, b.Analysis.ICFG);

        inner_state.emplace_back(b, bb);
      }
    }
  }

  ForBinary *update(const binary_t &b) /* accomodate b */
  {
    const unsigned N = vec.size();

    const binary_index_t TheBIdx = index_of_binary<MT>(b, jv);
    if (unlikely(TheBIdx < N))
      return &vec[TheBIdx]; /* no action required */

    const unsigned NForB = TheBIdx + 1;
    if constexpr (has_flag_v<BOpts, StateOpt::LazyInitialization>) {
      vec.resize(NForB);
    } else {
      if constexpr (CanReserve<BOpts>)
        vec.reserve(NForB);
      for (binary_index_t BIdx = N; BIdx < TheBIdx; ++BIdx) {
        if constexpr (!std::is_void_v<BinaryStateTy>) {
          vec.emplace_back(b);
        } else {
          vec.emplace_back();
        }
      }
      if constexpr (!std::is_void_v<BinaryStateTy>) {
        return &vec.emplace_back(b);
      } else {
        return &vec.emplace_back();
      }
    }
    return &vec[TheBIdx];
  }

  StateSlot<FunctionStateTy, FOpts> *
  update(const binary_t &b,
         const function_t &f, /* accommodate f */
         ForBinary &outer_state)
    requires(!std::is_void_v<FunctionStateTy>)
  {
    auto &inner_state = outer_state.fvec;

    const unsigned N = inner_state.size();

    const function_index_t TheFIdx = index_of_function_in_binary<MT>(f, b);
    if (unlikely(TheFIdx < N))
      return &inner_state[TheFIdx]; /* no action required */

    if constexpr (has_flag_v<FOpts, StateOpt::Eager>) {
      eager_functions(inner_state, b);
    } else {
      const unsigned NForF = TheFIdx + 1;
      if constexpr (has_flag_v<FOpts, StateOpt::LazyInitialization>) {
        inner_state.resize(NForF);
      } else {
        if constexpr (CanReserve<FOpts>)
          inner_state.reserve(NForF);
        for (function_index_t FIdx = N; FIdx < TheFIdx; ++FIdx)
          inner_state.emplace_back(b.Analysis.Functions.at(TheFIdx), b);
        return &inner_state.emplace_back(f, b);
      }
    }
    return &inner_state[TheFIdx]; /* no action required */
  }

  StateSlot<BasicBlockStateTy, BBOpts> *
  update(const binary_t &b, bb_t bb,
         ForBinary &outer_state) /* accommodate bb */
    requires(!std::is_void_v<BasicBlockStateTy>)
  {
    auto &inner_state = outer_state.bbvec;

    const unsigned N = inner_state.size();

    const basic_block_index_t TheBBIdx = index_of_basic_block<MT>(b.Analysis.ICFG, bb);
    if (unlikely(TheBBIdx < N))
      return &inner_state[TheBBIdx]; /* no action required */

    if constexpr (has_flag_v<BBOpts, StateOpt::Eager>) {
      eager_basic_blocks(inner_state, b);
    } else {
      const unsigned NForBB = TheBBIdx + 1;
      if constexpr (has_flag_v<BBOpts, StateOpt::LazyInitialization>) {
        inner_state.resize(NForBB);
      } else {
        if constexpr (CanReserve<BBOpts>)
          inner_state.reserve(NForBB);
        for (function_index_t BBIdx = N; BBIdx < TheBBIdx; ++BBIdx)
          inner_state.emplace_back(b, basic_block_of_index<MT>(BBIdx, b.Analysis.ICFG));
        return &inner_state.emplace_back(b, bb);
      }
    }
    return &inner_state[TheBBIdx];
  }

#define LAZYMAKE(thing, Opts, therep, T)                                       \
  do {                                                                         \
    /* we have to be LazyInitialization to get here  */                        \
    CheckFlag<Opts, StateOpt::LazyInitialization>();                           \
    if constexpr (MT) {                                                        \
      StateSlot<T, Opts> &there = *therep;                                     \
      {                                                                        \
        T *const xp = there.load(std::memory_order_acquire);                   \
        if (likely(xp))                                                        \
          return *xp;                                                          \
      }                                                                        \
                                                                               \
      auto new_x = std::make_unique<T>(BOOST_PP_CAT(thing, _NEW_ARGS));        \
                                                                               \
      T *expected = nullptr;                                                   \
      T *const desired = new_x.get();                                          \
      if (there.compare_exchange_strong(expected, desired,                     \
                                        std::memory_order_release,             \
                                        std::memory_order_acquire)) {          \
        new_x.release();                                                       \
        return *desired;                                                       \
      }                                                                        \
      assert(expected);                                                        \
      return *expected;                                                        \
    } else {                                                                   \
      StateSlot<T, Opts> &there = *therep;                                     \
      T *xp = there.get();                                                     \
      if (unlikely(!xp)) {                                                     \
        auto new_x = std::make_unique<T>(BOOST_PP_CAT(thing, _NEW_ARGS));      \
        xp = new_x.get();                                                      \
        there = std::move(new_x);                                              \
      }                                                                        \
      return *xp;                                                              \
    }                                                                          \
  } while (0)

  ForBinary &associated_with_binary(const binary_t &b) {
    const binary_index_t BIdx = index_of_binary<MT>(b, jv);

    ForBinary *p = ({
      auto s_lck = shared_access();
      likely(BIdx < vec.size()) ? &vec[BIdx] : nullptr;
    });

    if (unlikely(!p))
      p = ({
        const binary_t &b = jv.Binaries.at(BIdx);

        auto e_lck = exclusive_access();
        update(b);
      });

    return *p;
  }

public:
  std::add_lvalue_reference_t<BinaryStateTy>
  for_binary(const binary_t &b)
    requires(!std::is_void_v<BinaryStateTy>)
  {
    ForBinary *const p = &associated_with_binary(b);
    StateSlot<BinaryStateTy, BOpts> *slotp = &p->b;

    if constexpr (has_flag_v<BOpts, StateOpt::LazyInitialization>) {
#define binary_GET_ARGS b
#define binary_NEW_ARGS b
      LAZYMAKE(binary,BOpts,slotp,BinaryStateTy);
#undef binary_GET_ARGS
#undef binary_NEW_ARGS
    } else {
      return *slotp;
    }
  }

  std::add_lvalue_reference_t<FunctionStateTy>
  for_function(const function_t &f)
    requires(!std::is_void_v<FunctionStateTy>)
  {
    const function_index_t FIdx = index_of_function(f);

    const auto &b = binary_of_function(f, jv);
    ForBinary *const p = &associated_with_binary(b);

    StateSlot<FunctionStateTy, FOpts> *slotp = nullptr;

    auto s_lck = shared_access_f(p->fvec_mtx);
    if (likely(FIdx < p->fvec.size())) {
      slotp = &p->fvec[FIdx];
    } else {
      s_lck.unlock();

      {
        auto e_lck = exclusive_access_f(p->fvec_mtx);
        slotp = update(b, f, *p);
      }

      if constexpr (Contiguous<FOpts>) {
        s_lck.lock();
        slotp = &p->fvec[FIdx];
      }
    }

    if constexpr (has_flag_v<FOpts, StateOpt::LazyInitialization>) {
#define function_GET_ARGS f
#define function_NEW_ARGS f, binary_of_function<MT, MinSize>(f, jv)
      LAZYMAKE(function, FOpts, slotp, FunctionStateTy);
#undef function_GET_ARGS
#undef function_NEW_ARGS
    } else {
      return *slotp;
    }
  }

  std::add_lvalue_reference_t<BasicBlockStateTy>
  for_basic_block(const binary_t &b, bb_t bb)
    requires(!std::is_void_v<BasicBlockStateTy>)
  {
    const function_index_t BBIdx = index_of_basic_block(b.Analysis.ICFG, bb);

    ForBinary *const p = &associated_with_binary(b);

    StateSlot<BasicBlockStateTy, BBOpts> *slotp = nullptr;

    auto s_lck = shared_access_bb(p->bbvec_mtx);
    if (likely(BBIdx < p->bbvec.size())) {
      slotp = &p->bbvec[BBIdx];
    } else {
      s_lck.unlock();

      {
        auto e_lck = exclusive_access_bb(p->bbvec_mtx);
        slotp = update(b, bb, *p);
      }

      if constexpr (Contiguous<BBOpts>) {
        s_lck.lock();
        slotp = &p->bbvec[BBIdx];
      }
    }

    if constexpr (has_flag_v<BBOpts, StateOpt::LazyInitialization>) {
#define basic_block_GET_ARGS b, bb
#define basic_block_NEW_ARGS b, bb
      LAZYMAKE(basic_block, BBOpts, slotp, BasicBlockStateTy);
#undef basic_block_GET_ARGS
#undef basic_block_NEW_ARGS
    } else {
      return *slotp;
    }
  }
};
