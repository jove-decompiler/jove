#include "jove/jove.h"
#include "util.h"
#include "hash.h"
#include "sizes.h"
#include "objdump.h"
#include "B.h"
#include "explore.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace jove {

size_t jvDefaultInitialSize(void) {
  switch (sizeof(void *)) {
  case 8:
    return 3*GiB;
  case 4:
    return 384*MiB;
  }

  __compiletime_unreachable();
}

cached_hash_t::cached_hash_t(const char *path, std::string &file_contents,
                             hash_t &out) {
  Update(path, file_contents);
  out = h;
}

void cached_hash_t::Update(const char *path, std::string &file_contents) {
  struct stat64 st;
  if (::stat64(path, &st) < 0) {
    int err = errno;
    throw std::runtime_error("HashNeedsUpdate: stat failed: " +
                             std::string(strerror(err)));
  }

  if (!st.st_size)
    throw std::runtime_error(std::string("HashNeedsUpdate: empty file: ") + path);

  if (mtime.sec == st.st_mtim.tv_sec &&
      mtime.nsec == st.st_mtim.tv_nsec)
    return;

  //
  // otherwise
  //
  load_file(path, file_contents);
  if (file_contents.empty())
    throw std::runtime_error(std::string("HashNeedsUpdate: empty file: ") + path);

  h = hash_data(file_contents);
  mtime.sec = st.st_mtim.tv_sec;
  mtime.nsec = st.st_mtim.tv_nsec;
}

template <bool MT, bool MinSize>
void jv_base_t<MT, MinSize>::LookupAndCacheHash(
    hash_t &out,
    const char *path,
    std::string &file_contents) {
  assert(path);
  std::string_view sv(path);

  if constexpr (MT) {
    ip_string ips(get_segment_manager());
    to_ips(ips, sv);

    this->cached_hashes.try_emplace_or_visit(
        std::move(ips),
        path, std::ref(file_contents), std::ref(out),
        [&](typename ip_cached_hashes_type<MT, MinSize>::value_type &x) -> void {
          x.second.Update(path, file_contents);
          out = x.second.h;
        });
  } else {
    auto it = this->cached_hashes.find(sv);
    if (it == this->cached_hashes.end()) {
      ip_string ips(get_segment_manager());
      to_ips(ips, sv);

      bool succ = this->cached_hashes
                      .try_emplace(std::move(ips), path,
                                   std::ref(file_contents), std::ref(out))
                      .second;
      assert(succ);
    } else {
      (*it).second.Update(path, file_contents);
      out = (*it).second.h;
    }
  }
}

template <bool MT, bool MinSize>
bool jv_base_t<MT, MinSize>::LookupByName(const char *name, binary_index_set &out) {
  assert(name);
  std::string_view sv(name);

  if constexpr (MT) {
    return static_cast<bool>(this->name_to_binaries.cvisit(
        sv,
        [&](const typename ip_name_to_binaries_map_type<MT, MinSize>::value_type &x) -> void {
          assert(!x.second.empty());
          x.second.cvisit_all(
              [&](binary_index_t BIdx) -> void { out.insert(BIdx); });
        }));
  } else {
    auto it = this->name_to_binaries.find(sv);
    if (it == this->name_to_binaries.end()) {
      return false;
    } else {
      const ip_binary_index_set &set = (*it).second;
      assert(!set.empty());
      set.cvisit_all([&](binary_index_t BIdx) -> void { out.insert(BIdx); });
      return true;
    }
  }
}

template <bool MT, bool MinSize>
std::optional<binary_index_t> jv_base_t<MT, MinSize>::LookupByHash(const hash_t &h) {
  std::optional<binary_index_t> Res = std::nullopt;

  if constexpr (MT) {
    this->hash_to_binary.cvisit(
        h, [&](const typename ip_hash_to_binary_map_type<MT, MinSize>::value_type &x) -> void {
          Res = static_cast<binary_index_t>(x.second);
        });
  } else {
    auto it = this->hash_to_binary.find(h);
    if (it != this->hash_to_binary.end())
      Res = static_cast<binary_index_t>((*it).second);
  }

  return Res;
}

template <bool MT, bool MinSize>
template <bool ValidatePath>
std::pair<binary_index_t, bool>
jv_base_t<MT, MinSize>::AddFromPath(explorer_t<MT, MinSize> &explorer,
                                    jv_file_t &jv_file,
                                    const char *path,
                                    on_newbin_proc_t<MT, MinSize> on_newbin,
                                    const AddOptions_t &Options) {
  assert(path);

  std::conditional_t<ValidatePath, fs::path, std::monostate> canon_path;
  if constexpr (ValidatePath) {
    if (!fs::exists(path) || !fs::is_regular_file(path))
      return std::make_pair(invalid_binary_index, false);

    path = (canon_path = fs::canonical(path)).c_str();
  }

  std::string file_contents;
  hash_t h;

  try {
    LookupAndCacheHash(h, path, file_contents);
  } catch (...) {
    return std::make_pair(invalid_binary_index, false);
  }

  get_data_t get_data;
  if (file_contents.empty())
    get_data = [&](void) -> std::string_view {
      load_file(path, file_contents);
      return file_contents;
    };
  else
    get_data = [&](void) -> std::string_view {
      return file_contents;
    };

  return AddFromDataWithHash(explorer, jv_file, get_data, h, path,
                             on_newbin, Options);
}

template <bool MT, bool MinSize>
std::pair<binary_index_t, bool>
jv_base_t<MT, MinSize>::Add(jv_file_t &jv_file,
                            binary_t &&b,
                            on_newbin_proc_t<MT, MinSize> on_newbin) {
  binary_index_t Res = invalid_binary_index;
  bool isNewBinary = false;
  try {
    auto h = b.Hash;

    if constexpr (MT) {
      isNewBinary = this->hash_to_binary.try_emplace_or_visit(
          h, std::ref(Res), std::ref(jv_file), *this, std::move(b),
          [&](const typename ip_hash_to_binary_map_type<MT, MinSize>::value_type
                  &x) -> void { Res = static_cast<binary_index_t>(x.second); });
    } else {
      auto it = this->hash_to_binary.find(h);
      if (it == this->hash_to_binary.end()) {
        isNewBinary = this->hash_to_binary
                          .try_emplace(h, std::ref(Res), std::ref(jv_file),
                                       *this, std::move(b))
                          .second;
        assert(isNewBinary);
      } else {
        isNewBinary = false;
        Res = static_cast<binary_index_t>((*it).second);
      }
    }

    assert(is_binary_index_valid(Res));
  } catch (...) {
    return std::make_pair(invalid_binary_index, false);
  }

  binary_t &b_ = this->Binaries.at(Res);

  ip_binary_index_set ResSet(get_segment_manager());
  ResSet.insert(Res);

  bool isNewName = false;
  if constexpr (MT) {
    isNewName = this->name_to_binaries.try_emplace_or_visit(
        b_.Name, boost::move(ResSet),
        [&](typename ip_name_to_binaries_map_type<MT, MinSize>::value_type &x) -> void {
          x.second.insert(Res);
        });
  } else {
    auto it = this->name_to_binaries.find(b_.Name);
    if (it == this->name_to_binaries.end()) {
      isNewName =
          this->name_to_binaries.try_emplace(b_.Name, boost::move(ResSet))
              .second;
      assert(isNewName);
    } else {
      isNewName = false;
      (*it).second.insert(Res);
    }
  }

  if (unlikely(isNewBinary))
    on_newbin(b_);

  return std::make_pair(Res, isNewBinary || isNewName);
}

template <bool MT, bool MinSize>
std::pair<binary_index_t, bool> jv_base_t<MT, MinSize>::AddFromData(
    explorer_t<MT, MinSize> &explorer,
    jv_file_t &jv_file,
    std::string_view data,
    const char *name,
    on_newbin_proc_t<MT, MinSize> on_newbin,
    const AddOptions_t &Options) {
  return AddFromDataWithHash(
      explorer, jv_file,
      [&](void) -> std::string_view { return data; },
      hash_data(data), name, on_newbin, Options);
}

template <bool MT, bool MinSize>
std::pair<binary_index_t, bool> jv_base_t<MT, MinSize>::AddFromDataWithHash(
    explorer_t<MT, MinSize> &explorer,
    jv_file_t &jv_file,
    get_data_t get_data,
    const hash_t &h,
    const char *name,
    on_newbin_proc_t<MT, MinSize> on_newbin,
    const AddOptions_t &Options) {
  binary_index_t Res = invalid_binary_index;
  bool isNewBinary = false;
  try {
    if constexpr (MT) {
      isNewBinary = this->hash_to_binary.try_emplace_or_visit(
          h, std::ref(Res), jv_file, *this, explorer, get_data, std::ref(h),
          name, std::ref(Options),
          [&](const typename ip_hash_to_binary_map_type<MT, MinSize>::value_type
                  &x) -> void { Res = static_cast<binary_index_t>(x.second); });
    } else {
      auto it = this->hash_to_binary.find(h);
      if (it == this->hash_to_binary.end()) {
        isNewBinary =
            this->hash_to_binary
                .try_emplace(h, std::ref(Res), jv_file,
                             *this, explorer,
                             get_data, std::ref(h), name,
                             std::ref(Options))
                .second;
        assert(isNewBinary);
      } else {
        isNewBinary = false;
        Res = static_cast<binary_index_t>((*it).second);
      }
    }

    if (!is_binary_index_valid(Res))
      return std::make_pair(invalid_binary_index, false);
  } catch (...) {
    return std::make_pair(invalid_binary_index, false);
  }

  ip_binary_index_set ResSet(get_segment_manager());
  ResSet.insert(Res);

  bool isNewName = false;
  std::string_view name_sv(name);
  if constexpr (MT) {
    ip_string name_ips(get_segment_manager());
    to_ips(name_ips, name_sv);

    isNewName = this->name_to_binaries.try_emplace_or_visit(
        std::move(name_ips),
        boost::move(ResSet),
        [&](typename ip_name_to_binaries_map_type<MT, MinSize>::value_type &x) -> void {
          x.second.insert(Res);
        });
  } else {
    auto it = this->name_to_binaries.find(name_sv);
    if (it == this->name_to_binaries.end()) {
      ip_string name_ips(get_segment_manager());
      to_ips(name_ips, name_sv);

      isNewName = this->name_to_binaries
                      .try_emplace(std::move(name_ips),
                                   std::move(ResSet))
                      .second;
      assert(isNewName);
    } else {
      isNewName = false;
      (*it).second.insert(Res);
    }
  }

  if (isNewBinary) {
    binary_t &b = this->Binaries.at(Res);

    if (Options.Objdump) {
      std::unique_ptr<llvm::object::Binary> Bin = B::Create(b.data());

      binary_t::Analysis_t::objdump_output_type::generate(
          b.Analysis.objdump, b.is_file() ? b.Name.c_str() : nullptr, *Bin);
    }

    on_newbin(b);
  }

  return std::make_pair(Res, isNewBinary || isNewName);
}

template <bool MT, bool MinSize>
adds_binary_t::adds_binary_t(binary_index_t &out,
                             jv_file_t &jv_file,
                             jv_base_t<MT, MinSize> &jv,
                             explorer_t<MT, MinSize> &explorer_,
                             get_data_t get_data,
                             const hash_t &h,
                             const char *name,
                             const AddOptions_t &Options) noexcept(false) {
  std::string_view data = get_data();

  if (unlikely(data.empty()))
    throw std::runtime_error("adds_binary_t(): no data");

  std::unique_ptr<llvm::object::Binary> Bin;
  try {
    Bin = B::Create(data);
  } catch (...) {
    //
    // we're making note here that this is *not* a (valid) binary
    //
    out = BIdx = invalid_basic_block_index;
    return;
  }

  //
  // if we make it here then it's most likely a legitimate binary of interest.
  //
  {
    binary_base_t<false /* !MT */, MinSize> b(jv_file);

    if (name)
      to_ips(b.Name, name); /* set up name */

    if constexpr (MT == false) {
      jv.DoAdd(b, explorer_, *Bin, Options);
    } else {
      explorer_t<false /* !MT */, MinSize> explorer(explorer_);
      assert(!explorer.get_jv());
      jv.DoAdd(b, explorer, *Bin, Options);
    }

    //
    // success!
    //
    b.Data.resize(data.size()); /* lock it in */
    memcpy(&b.Data[0], data.data(), data.size());

    b.Hash = h;

    if constexpr (MinSize) {
      auto e_lck = jv.Binaries.exclusive_access();

      BIdx = jv.Binaries.container().size();
      b.Idx = BIdx;
      jv.Binaries.container().emplace_back(std::move(b));
    } else {
      BIdx = jv.Binaries.len_.fetch_add(1u, std::memory_order_relaxed);
      b.Idx = BIdx;
      jv.Binaries[BIdx] = std::move(b);
    }
  }

  jv.fixup_binary(jv_file, BIdx);

  out = BIdx;
}

template <bool MT, bool MinSize>
adds_binary_t::adds_binary_t(binary_index_t &out,
                             jv_file_t &jv_file,
                             jv_base_t<MT, MinSize> &jv,
                             binary_base_t<MT, MinSize> &&b) noexcept {
  // don't ask questions
  {
    if constexpr (MinSize) {
      auto e_lck = jv.Binaries.exclusive_access();

      BIdx = jv.Binaries.container().size();
      b.Idx = BIdx;
      jv.Binaries.container().push_back(std::move(b));
    } else {
      BIdx  = jv.Binaries.len_.fetch_add(1u, std::memory_order_relaxed);

      b.Idx = BIdx;
      jv.Binaries[BIdx] = std::move(b);
    }
  }

  jv.fixup_binary(jv_file, BIdx);

  out = BIdx;
}

template <bool MT, bool MinSize>
void jv_base_t<MT, MinSize>::clear(bool everything) {
  name_to_binaries.clear();
  hash_to_binary.clear();

  this->Binaries.clear();
  initialize_all_binary_indices();

  if (everything)
    cached_hashes.clear();
}

template <bool MT, bool MinSize>
void jv_base_t<MT, MinSize>::InvalidateFunctionAnalyses(void) {
  for_each_binary(maybe_par_unseq, *this, [&](binary_t &b) {
    for_each_function_in_binary(maybe_par_unseq, b,
                                [&](function_t &f) { f.InvalidateAnalysis(); });
  });
}

template <bool MT, bool MinSize>
void jv_base_t<MT, MinSize>::fixup_binary(jv_file_t &jv_file,
                                          const binary_index_t BIdx) {
  //
  // TODO explain why all this is necessary in the first place
  //
  assert(is_binary_index_valid(BIdx));
  auto &b = Binaries.at(BIdx);
  assert(index_of_binary(b) == BIdx);

  for_each_function_in_binary(maybe_par_unseq, b, [&](function_t &f) {
    f.BIdx = BIdx;

    assert(!f.pCallers.Load(std::memory_order_relaxed));

    using OurCallers_t = Callers_t<MT, MinSize>;
    f.pCallers.Store(jv_file.construct<OurCallers_t>(
                         boost::interprocess::anonymous_instance)(
                         jv_file.get_segment_manager()),
                     std::memory_order_relaxed);

  });

  //
  // we assume that explorer_t::jvptr was NULL when the binary was explored, so
  // we need to update the callers
  //
  for_each_basic_block_in_binary(
      maybe_par_unseq, b, [&](bb_t bb) {
        bbprop_t &bbprop = b.Analysis.ICFG[bb];
        if (bbprop.Term.Type != TERMINATOR::CALL)
          return;

        function_t &callee = b.Analysis.Functions.at(bbprop.Term._call.Target);

        callee.Callers(*this).Insert(caller_t(BIdx, bbprop.Term.Addr));

        const auto &ParentsVec = bbprop.Parents.template get<MT>();
        std::for_each(maybe_par_unseq,
                      ParentsVec.cbegin(),
                      ParentsVec.cend(), [&](function_index_t FIdx) {
                        function_t &caller = b.Analysis.Functions.at(FIdx);

                        Analysis.ReverseCallGraph.template add_edge<MT>(
                            callee.ReverseCGVert(*this),
                            caller.ReverseCGVert(*this));
                      });
      });
}

template <bool MT, bool MinSize>
void jv_base_t<MT, MinSize>::fixup(jv_file_t& jv_file) {
  for_each_binary(maybe_par_unseq, *this,
                  [&](auto &b) { fixup_binary(jv_file, index_of_binary(b)); });
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template struct jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),          \
                            GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH3                                            \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template std::pair<binary_index_t, bool>                                     \
  jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                          \
            GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>::                        \
      AddFromPath<GET_VALUE(BOOST_PP_SEQ_ELEM(2, product))>(                   \
          explorer_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                 \
                     GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))> &,              \
          jv_file_t &, const char *,                                           \
          on_newbin_proc_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),           \
                           GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>,          \
          const AddOptions_t &);
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2)(VALUES_TO_INSTANTIATE_WITH3))

}
