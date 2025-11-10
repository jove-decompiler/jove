#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

static inline std::string description_of_block(const bbprop_t &bbprop,
                                               bool zero_padded = true) {
  std::string res;

  res += "[";
  res += taddr2str(bbprop.Addr, zero_padded);
  res += ", ";
  res += taddr2str(bbprop.Addr + bbprop.Size, zero_padded);
  res += ")";

  return res;
}

template <bool MT>
constexpr auto basic_block_of_index(basic_block_index_t BBIdx,
                                    const ip_icfg_base_t<MT> &ICFG) {
  assert(is_basic_block_index_valid(BBIdx));
  assert(BBIdx < ICFG.num_vertices());

  return ICFG.vertex(BBIdx);
}

template <bool MT, bool MinSize>
constexpr auto basic_block_of_index(basic_block_index_t BBIdx,
                                    const binary_base_t<MT, MinSize> &b) {
  const auto &ICFG = b.Analysis.ICFG;
  return basic_block_of_index(BBIdx, ICFG);
}

static inline bbmap_t::iterator bbmap_find(bbmap_t &bbmap, addr_intvl intvl) {
  return intvl_map_find(bbmap, intvl);
}

static inline bbmap_t::const_iterator bbmap_find(const bbmap_t &bbmap, addr_intvl intvl) {
  return intvl_map_find(bbmap, intvl);
}

static inline bbmap_t::iterator bbmap_find(bbmap_t &bbmap, taddr_t Addr) {
  return intvl_map_find(bbmap, Addr);
}

static inline bbmap_t::const_iterator bbmap_find(const bbmap_t &bbmap,
                                                 taddr_t Addr) {
  return intvl_map_find(bbmap, Addr);
}

constexpr bool bbmap_contains(bbmap_t &bbmap, addr_intvl intvl) {
  return intvl_map_contains(bbmap, intvl);
}

constexpr bool bbmap_contains(bbmap_t &bbmap, taddr_t Addr) {
  return intvl_map_contains(bbmap, Addr);
}

template <typename Value>
constexpr auto bbmap_add(bbmap_t &bbmap,
                         addr_intvl intvl,
                         Value &&val) {
  return intvl_map_add(bbmap, intvl, std::move(val));
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr
void for_each_binary(_ExecutionPolicy &&__exec,
                     jv_base_t<MT, MinSize> &jv,
                     Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_binary(jv_base_t<MT, MinSize> &jv, Proc proc) {
  std::for_each(jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr
void for_each_binary(_ExecutionPolicy &&__exec,
                     const jv_base_t<MT, MinSize> &jv,
                     Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_binary(const jv_base_t<MT, MinSize> &jv, Proc proc) {
  std::for_each(jv.Binaries.begin(),
                jv.Binaries.end(),
                proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr
void for_each_binary_if(_ExecutionPolicy &&__exec,
                        jv_base_t<MT, MinSize> &jv,
                        Pred pred,
                        Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr
void for_each_binary_if(_ExecutionPolicy &&__exec,
                        const jv_base_t<MT, MinSize> &jv,
                        Pred pred,
                        Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr
void for_each_binary_if(jv_base_t<MT, MinSize> &jv, Pred pred, Proc proc) {
  for_each_if(jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr
void for_each_binary_if(const jv_base_t<MT, MinSize> &jv, Pred pred, Proc proc) {
  for_each_if(jv.Binaries.begin(),
              jv.Binaries.end(),
              pred, proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr
void for_each_function(_ExecutionPolicy &&__exec,
                       jv_base_t<MT, MinSize> &jv,
                       Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec),
                  jv,
                  [&__exec, proc](auto &b) {
    std::for_each(std::forward<_ExecutionPolicy>(__exec),
                  b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr
void for_each_function(_ExecutionPolicy &&__exec,
                       const jv_base_t<MT, MinSize> &jv,
                       Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec),
                  jv,
                  [&__exec, proc](auto &b) {
    std::for_each(std::forward<_ExecutionPolicy>(__exec),
                  b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_function(jv_base_t<MT, MinSize> &jv, Proc proc) {
  for_each_binary(jv,
                  [proc](auto &b) {
    std::for_each(b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_function(const jv_base_t<MT, MinSize> &jv, Proc proc) {
  for_each_binary(jv,
                  [proc](auto &b) {
    std::for_each(b.Analysis.Functions.begin(),
                  b.Analysis.Functions.end(),
                  [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr void for_each_function_if_in_binary(_ExecutionPolicy &&__exec,
                                              binary_base_t<MT, MinSize> &b,
                                              Pred pred, Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr
void for_each_function_if_in_binary(binary_base_t<MT, MinSize> &b,
                                    Pred pred,
                                    Proc proc) {
  for_each_if(b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr void for_each_function_if_in_binary(_ExecutionPolicy &&__exec,
                                              const binary_base_t<MT, MinSize> &b,
                                              Pred pred, Proc proc) {
  for_each_if(std::forward<_ExecutionPolicy>(__exec),
              b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr
void for_each_function_if_in_binary(const binary_base_t<MT, MinSize> &b,
                                    Pred pred,
                                    Proc proc) {
  for_each_if(b.Analysis.Functions.begin(),
              b.Analysis.Functions.end(), pred, proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void for_each_function_in_binary(_ExecutionPolicy &&__exec,
                                           binary_base_t<MT, MinSize> &b,
                                           Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void for_each_function_in_binary(_ExecutionPolicy &&__exec,
                                           const binary_base_t<MT, MinSize> &b,
                                           Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_function_in_binary(binary_base_t<MT, MinSize> &b,
                                           Proc proc) {
  std::for_each(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr
void for_each_function_in_binary(const binary_base_t<MT, MinSize> &b,
                                 Proc proc) {
  std::for_each(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void
for_each_function_in_binary(_ExecutionPolicy &&__exec,
                            binary_analysis_t<MT, MinSize> &Analysis,
                            Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                Analysis.Functions.begin(),
                Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void
for_each_function_in_binary(_ExecutionPolicy &&__exec,
                            const binary_analysis_t<MT, MinSize> &Analysis,
                            Proc proc) {
  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                Analysis.Functions.begin(),
                Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr void
for_each_function_in_binary(binary_analysis_t<MT, MinSize> &Analysis,
                            Proc proc) {
  std::for_each(Analysis.Functions.begin(),
                Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class Proc>
constexpr
void for_each_function_in_binary(const binary_analysis_t<MT, MinSize> &Analysis,
                                 Proc proc) {
  std::for_each(Analysis.Functions.begin(),
                Analysis.Functions.end(), proc);
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr void for_each_function_if(_ExecutionPolicy &&__exec,
                                    jv_base_t<MT, MinSize> &jv,
                                    Pred pred,
                                    Proc proc) {
  for_each_binary(std::forward<_ExecutionPolicy>(__exec), jv,
                  [&__exec, pred, proc](auto &b) {
                    for_each_if(std::forward<_ExecutionPolicy>(__exec),
                                b.Analysis.Functions.begin(),
                                b.Analysis.Functions.end(), pred,
                                [&b, proc](auto &f) { proc(f, b); });
                  });
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr void for_each_function_if(jv_base_t<MT, MinSize> &jv,
                                    Pred pred,
                                    Proc proc) {
  for_each_binary(jv, [pred, proc](auto &b) {
    for_each_if(b.Analysis.Functions.begin(),
                b.Analysis.Functions.end(), pred,
                [&b, proc](auto &f) { proc(f, b); });
  });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
constexpr void for_each_basic_block(_ExecutionPolicy &&__exec,
                                    jv_base_t<MT, MinSize> &jv, Proc proc) {
  for_each_binary(
      std::forward<_ExecutionPolicy>(__exec),
      jv, [&__exec, proc](auto &b) {
        auto it_pair = b.Analysis.ICFG.vertices();

        std::for_each(std::forward<_ExecutionPolicy>(__exec),
                      it_pair.first,
                      it_pair.second, [&b, proc](auto bb) { proc(b, bb); });
      });
}

template <bool MT, bool MinSize, class Proc>
constexpr void for_each_basic_block(jv_base_t<MT, MinSize> &jv, Proc proc) {
  for_each_binary(jv, [proc](auto &b) {
    auto it_pair = b.Analysis.ICFG.vertices();

    std::for_each(it_pair.first,
                  it_pair.second,
                  [&b, proc](auto bb) { proc(b, bb); });
  });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Pred, class Proc>
constexpr void for_each_basic_block_if(_ExecutionPolicy &&__exec,
                                       jv_base_t<MT, MinSize> &jv,
                                       Pred pred,
                                       Proc proc) {
  for_each_binary(
      std::forward<_ExecutionPolicy>(__exec),
      jv, [&__exec, pred, proc](auto &b) {
        auto it_pair = b.Analysis.ICFG.vertices();

        for_each_if(std::forward<_ExecutionPolicy>(__exec),
                    it_pair.first,
                    it_pair.second,
                    [&b, pred](auto bb) -> bool { return pred(b, bb); },
                    [&b, proc](auto bb) { proc(b, bb); });
      });
}

template <bool MT, bool MinSize, class Pred, class Proc>
constexpr void for_each_basic_block_if(jv_base_t<MT, MinSize> &jv,
                                       Pred pred,
                                       Proc proc) {
  for_each_binary(
      jv, [pred, proc](auto &b) {
        auto it_pair = b.Analysis.ICFG.vertices();

        for_each_if(it_pair.first,
                    it_pair.second,
                    [&b, pred](auto bb) -> bool { return pred(b, bb); },
                    [&b, proc](auto bb) { proc(b, bb); });
      });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    binary_base_t<MT, MinSize> &b,
                                    Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                it_pair.first,
                it_pair.second, [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
static inline
void for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                                    const binary_base_t<MT, MinSize> &b,
                                    Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                it_pair.first,
                it_pair.second, [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Proc>
static inline
void for_each_basic_block_in_binary(binary_base_t<MT, MinSize> &b, Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  std::for_each(it_pair.first,
                it_pair.second,
                [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Proc>
static inline void
for_each_basic_block_in_binary(const binary_base_t<MT, MinSize> &b, Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  std::for_each(it_pair.first,
                it_pair.second,
                [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class _ExecutionPolicy, class Proc>
static inline void
for_each_basic_block_in_binary(_ExecutionPolicy &&__exec,
                               const binary_analysis_t<MT, MinSize> &Analysis,
                               Proc proc) {
  auto it_pair = Analysis.ICFG.vertices();

  std::for_each(std::forward<_ExecutionPolicy>(__exec),
                it_pair.first,
                it_pair.second, [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Proc>
static inline void
for_each_basic_block_in_binary(binary_analysis_t<MT, MinSize> &Analysis,
                               Proc proc) {
  auto it_pair = Analysis.ICFG.vertices();

  std::for_each(it_pair.first,
                it_pair.second,
                [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Proc>
static inline void
for_each_basic_block_in_binary(const binary_analysis_t<MT, MinSize> &Analysis,
                               Proc proc) {
  auto it_pair = Analysis.ICFG.vertices();

  std::for_each(it_pair.first,
                it_pair.second,
                [proc](auto bb) { proc(bb); });
}

template <bool MT, bool MinSize, class Pred, class Proc>
static inline void
for_each_basic_block_in_binary_if(const binary_analysis_t<MT, MinSize> &Analysis,
                                  Pred pred,
                                  Proc proc) {
  auto it_pair = Analysis.ICFG.vertices();

  for_each_if(it_pair.first,
              it_pair.second,
              pred,
              proc);
}

template <bool MT, bool MinSize, class Pred, class Proc>
static inline void
for_each_basic_block_in_binary_if(const binary_base_t<MT, MinSize> &b,
                                  Pred pred,
                                  Proc proc) {
  auto it_pair = b.Analysis.ICFG.vertices();

  for_each_if(it_pair.first,
              it_pair.second,
              pred,
              proc);
}

template <bool MT>
constexpr basic_block_index_t
index_of_basic_block(const ip_icfg_base_t<MT> &ICFG, auto bb) {
  return ICFG.index(bb);
}

template <bool MT, bool MinSize>
constexpr basic_block_index_t
index_of_basic_block(const binary_base_t<MT, MinSize> &b, auto bb) {
  return index_of_basic_block(b.Analysis.ICFG, bb);
}

constexpr binary_index_t binary_index_of_function(const function_t &f) {
  binary_index_t res = f.BIdx;
  assert(is_binary_index_valid(res));
  return res;
}

template <bool MT, bool MinSize>
[[deprecated]] /* use binary_index_of_function(f) */
constexpr binary_index_t
binary_index_of_function(const function_t &f,
                         const jv_base_t<MT, MinSize> &jv) {
  return binary_index_of_function(f);
}

template <bool MT, bool MinSize>
constexpr binary_index_t index_of_binary(const binary_base_t<MT, MinSize> &b) {
  binary_index_t res = b.Idx;
  assert(is_binary_index_valid(res));
  return res;
}

template <bool MT, bool MinSize>
[[deprecated]] /* use index_of_binary(b) */
constexpr binary_index_t
index_of_binary(const binary_base_t<MT, MinSize> &b,
                const jv_base_t<MT, MinSize> &jv) {
  return index_of_binary(b);
}

constexpr function_index_t index_of_function(const function_t &f) {
  function_index_t res = f.Idx;
  assert(is_function_index_valid(res));
  return res;
}

template <bool MT, bool MinSize>
[[deprecated]] /* use index_of_function(f) */
constexpr function_index_t
index_of_function_in_binary(const function_t &f,
                            const binary_base_t<MT, MinSize> &b) {
  return index_of_function(f);
}

template <bool MT, bool MinSize>
constexpr const binary_base_t<MT, MinSize> &
binary_of_function(const function_t &f, const jv_base_t<MT, MinSize> &jv) {
  binary_index_t BIdx = f.BIdx;
  assert(is_binary_index_valid(BIdx));
  return jv.Binaries.at(BIdx);
}

template <bool MT, bool MinSize>
constexpr binary_base_t<MT, MinSize> &
binary_of_function(function_t &f, jv_base_t<MT, MinSize> &jv) {
  binary_index_t BIdx = f.BIdx;
  assert(is_binary_index_valid(BIdx));
  return jv.Binaries.at(BIdx);
}

template <bool MT, bool MinSize>
constexpr const function_t &
function_of_target(dynamic_target_t X, const jv_base_t<MT, MinSize> &jv) {
  return jv.Binaries.at(X.first).Analysis.Functions.at(X.second);
}

template <bool MT, bool MinSize>
constexpr function_t &function_of_target(dynamic_target_t X,
                                         jv_base_t<MT, MinSize> &jv) {
  return jv.Binaries.at(X.first).Analysis.Functions.at(X.second);
}

constexpr dynamic_target_t target_of_function(const function_t &f) {
  return {binary_index_of_function(f), index_of_function(f)};
}

static inline dynamic_target_t
target_of_function(const function_analysis_t &Analysis) {
  const function_t &f =
      *JOVE_CONTAINER_OF_CONST(&Analysis, function_t, Analysis);
  return {binary_index_of_function(f), index_of_function(f)};
}

template <bool MT, bool MinSize>
static inline void basic_blocks_of_function_at_block(
    typename ip_icfg_base_t<MT>::vertex_descriptor entry,
    const binary_base_t<MT, MinSize> &b,
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &out) {
  const auto &ICFG = b.Analysis.ICFG;

  struct bb_visitor : public boost::default_dfs_visitor {
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &out;

    bb_visitor(
        std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
            &out)
        : out(out) {}

    void
    discover_vertex(typename ip_icfg_base_t<MT>::vertex_descriptor bb,
                    const typename ip_icfg_base_t<MT>::type &) const {
      out.push_back(bb);
    }
  };

  out.clear();
  out.reserve(ICFG.num_vertices());

  bb_visitor vis(out);
  ICFG.depth_first_visit(entry, vis);
}

template <bool MT, bool MinSize>
static inline void basic_blocks_of_function(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &out) {

  const auto &ICFG = b.Analysis.ICFG;

  basic_blocks_of_function_at_block(basic_block_of_index(f.Entry, ICFG), b, out);
}

template <bool MT, bool MinSize>
static inline void exit_basic_blocks_of_function(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &bbvec,
    std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> &out) {
  const auto &ICFG = b.Analysis.ICFG;

  out.reserve(bbvec.size());

  std::copy_if(
      bbvec.begin(),
      bbvec.end(), std::back_inserter(out),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        return IsExitBlock(ICFG, bb);
      });
}

template <bool MT, bool MinSize>
static inline bool does_function_return_fast(
    const ip_icfg_base_t<MT> &ICFG,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &bbvec) {
  return std::any_of(
      bbvec.begin(),
      bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        return IsExitBlock(ICFG, bb);
      });
}

template <bool MT, bool MinSize>
static inline bool does_function_at_block_return(
    typename ip_icfg_base_t<MT>::vertex_descriptor entry,
    const binary_base_t<MT, MinSize> &b) {
  std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor> bbvec;
  basic_blocks_of_function_at_block(entry, b, bbvec);

  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(
      bbvec.begin(),
      bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        return IsExitBlock(ICFG, bb);
      });
}

template <bool MT, bool MinSize>
static inline bool does_function_return(const function_t &f,
                                        const binary_base_t<MT, MinSize> &b) {
  return does_function_at_block_return(basic_block_of_index(f.Entry, b), b);
}

template <bool MT, bool MinSize>
static inline bool IsLeafFunction(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &bbvec,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &exit_bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  if (!std::none_of(bbvec.begin(),
                    bbvec.end(),
                    [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
                      auto T = ICFG[bb].Term.Type;
                      return (T == TERMINATOR::INDIRECT_JUMP &&
                              ICFG.out_degree(bb) == 0)
                           || T == TERMINATOR::INDIRECT_CALL
                           || T == TERMINATOR::CALL;
                    }))
    return false;

  return std::all_of(
      exit_bbvec.begin(),
      exit_bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        auto T = ICFG[bb].Term.Type;
        return T == TERMINATOR::RETURN || T == TERMINATOR::UNREACHABLE;
      });
}

template <bool MT, bool MinSize>
static inline bool IsFunctionSetjmp(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(
      bbvec.begin(),
      bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        return ICFG[bb].Sj;
      });
}

template <bool MT, bool MinSize>
static inline bool IsFunctionLongjmp(
    const function_t &f,
    const binary_base_t<MT, MinSize> &b,
    const std::vector<typename ip_icfg_base_t<MT>::vertex_descriptor>
        &bbvec) {
  const auto &ICFG = b.Analysis.ICFG;

  return std::any_of(
      bbvec.begin(),
      bbvec.end(),
      [&](typename ip_icfg_base_t<MT>::vertex_descriptor bb) -> bool {
        auto &Term = ICFG[bb].Term;
        return Term.Type == TERMINATOR::INDIRECT_JUMP &&
               Term._indirect_jump.IsLj;
      });
}

template <bool MT, bool MinSize>
static inline basic_block_index_t
index_of_basic_block_at_address(taddr_t Addr,
                                const binary_base_t<MT, MinSize> &b) {
  bbmap_t *pmap = b.BBMap.map.get();
  assert(pmap);
  bbmap_t &bbmap = *pmap;
  auto it = bbmap_find(bbmap, Addr);
  assert(it != bbmap.end());
  return (*it).second;
}

template <bool MT, bool MinSize>
static inline basic_block_index_t
index_of_basic_block_starting_at_address(taddr_t Addr,
                                         const binary_base_t<MT, MinSize> &b) {
  basic_block_index_t res = invalid_basic_block_index;
  bool found;
  if constexpr (MT) {
    found = b.bbbmap.cvisit(Addr, [&](const auto &x) {
      res = static_cast<basic_block_index_t>(x.second);
    });
  } else {
    auto it = b.bbbmap.find(Addr);
    found = it != b.bbbmap.end();
    if (found)
      res = static_cast<basic_block_index_t>((*it).second);
  }

  assert(found);

  return res;
}

template <bool MT, bool MinSize>
static inline typename ip_icfg_base_t<MT>::vertex_descriptor
basic_block_starting_at_address(taddr_t Addr,
                                const binary_base_t<MT, MinSize> &b) {
  return basic_block_of_index(index_of_basic_block_starting_at_address(Addr, b), b);
}

template <bool MT, bool MinSize>
static inline typename ip_icfg_base_t<MT>::vertex_descriptor
basic_block_at_address(taddr_t Addr, const binary_base_t<MT, MinSize> &b) {
  return basic_block_of_index(index_of_basic_block_at_address(Addr, b), b);
}

template <bool MT, bool MinSize>
static inline bool
exists_basic_block_at_address(taddr_t Addr,
                              const binary_base_t<MT, MinSize> &b) {
  bbmap_t *const pbbmap = b.BBMap.map.get();
  assert(pbbmap);
  bbmap_t &bbmap = *pbbmap;

  return bbmap_contains(bbmap, Addr);
}

template <bool MT, bool MinSize>
static inline bool
exists_basic_block_starting_at_address(taddr_t Addr,
                                       const binary_base_t<MT, MinSize> &b) {
  return b.bbbmap.contains(Addr);
}

template <bool MT, bool MinSize>
static inline function_index_t
index_of_function_at_address(const binary_base_t<MT, MinSize> &b,
                             taddr_t Addr) {
  function_index_t FIdx = invalid_function_index;
  if constexpr (MT) {
    b.fnmap.cvisit(Addr, [&](const auto &x) {
      FIdx = static_cast<function_index_t>(x.second);
    });
  } else {
    auto it = b.fnmap.find(Addr);
    if (it != b.fnmap.end())
      FIdx = static_cast<function_index_t>((*it).second);
  }
  assert(is_function_index_valid(FIdx));

  return FIdx;
}

template <bool MT, bool MinSize>
static inline const function_t &
function_at_address(const binary_base_t<MT, MinSize> &b, taddr_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

template <bool MT, bool MinSize>
static inline function_t &function_at_address(binary_base_t<MT, MinSize> &b,
                                              taddr_t Addr) {
  return b.Analysis.Functions.at(index_of_function_at_address(b, Addr));
}

template <bool MT, bool MinSize>
static inline bool
exists_function_at_address(const binary_base_t<MT, MinSize> &b, taddr_t Addr) {
  return b.fnmap.contains(Addr);
}

// NOTE: this function excludes tail calls.
template <bool MT, bool MinSize>
static inline bool
exists_indirect_jump_at_address(taddr_t Addr,
                                const binary_base_t<MT, MinSize> &binary) {
  if (exists_basic_block_at_address(Addr, binary)) {
    const auto &ICFG = binary.Analysis.ICFG;
    typename ip_icfg_base_t<MT>::vertex_descriptor bb =
        basic_block_at_address(Addr, binary);
    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
        !ICFG[bb].hasDynTarget())
      return true;
  }

  return false;
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_basic_block(
    typename ip_icfg_base_t<MT>::vertex_descriptor bb,
    const ip_icfg_base_t<MT> &ICFG) {
  return ICFG[bb].Addr;
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_basic_block(
    typename ip_icfg_base_t<MT>::vertex_descriptor bb,
    const binary_base_t<MT, MinSize> &b) {
  return address_of_basic_block(bb, b.Analysis.ICFG);
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_basic_block_terminator(
    typename ip_icfg_base_t<MT>::vertex_descriptor bb,
    const ip_icfg_base_t<MT> &ICFG) {
  return ICFG[bb].Term.Addr;
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_basic_block_terminator(
    typename ip_icfg_base_t<MT>::vertex_descriptor bb,
    const binary_base_t<MT, MinSize> &b) {
  return address_of_basic_block_terminator(bb, b.Analysis.ICFG);
}

template <bool MT, bool MinSize>
static inline taddr_t
entry_address_of_function(const function_t &f,
                          const binary_base_t<MT, MinSize> &binary) {
  const auto &ICFG = binary.Analysis.ICFG;
  return ICFG[basic_block_of_index(f.Entry, binary)].Addr;
}

template <bool MT, bool MinSize>
static inline taddr_t
address_of_block_in_binary(basic_block_index_t BBIdx,
                           const binary_base_t<MT, MinSize> &b) {
  return b.Analysis.ICFG[basic_block_of_index(BBIdx, b)].Addr;
}

template <bool MT, bool MinSize>
static inline taddr_t address_of_block(const block_t &block,
                                       const jv_base_t<MT, MinSize> &jv) {
  const binary_base_t<MT, MinSize> &b = jv.Binaries.at(block.first);
  return address_of_block_in_binary(block.second, b);
}

template <bool MT, bool MinSize>
static inline taddr_t
address_of_block_terminator(const block_t &Block,
                            const jv_base_t<MT, MinSize> &jv) {
  const binary_base_t<MT, MinSize> &b = jv.Binaries.at(Block.first);
  return b.Analysis.ICFG[basic_block_of_index(Block.second, b)].Term.Addr;
}

template <bool MT, bool MinSize>
static inline const binary_base_t<MT, MinSize> &
get_dynl(const jv_base_t<MT, MinSize> &jv) {
  for (auto &b : jv.Binaries) {
    if (b.IsDynamicLinker)
      return b;
  }

  throw std::runtime_error(std::string(__func__) + ": not found!");
}

template <bool MT, bool MinSize>
static inline const binary_base_t<MT, MinSize> &
get_vdso(const jv_base_t<MT, MinSize> &jv) {
  for (auto &b : jv.Binaries) {
    if (b.IsVDSO)
      return b;
  }

  throw std::runtime_error(std::string(__func__) + ": not found!");
}
