#include "jove/jove.h"
#include "util.h"
#include "hash.h"
#include "sizes.h"
#include "objdump.h"
#include "B.h"

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace jove {

size_t jvDefaultInitialSize(void) {
  switch (sizeof(void *)) {
  case 8:
    return 9*GiB;
  case 4:
    return 1280*MiB;
  }

  abort();
}

cached_hash_t::cached_hash_t(const char *path, std::string &file_contents,
                             hash_t &out) {
  Update(path, file_contents);
  out = h;
}

void cached_hash_t::Update(const char *path, std::string &file_contents) {
  struct stat st;
  if (stat(path, &st) < 0) {
    int err = errno;
    throw std::runtime_error("HashNeedsUpdate: stat failed: " +
                             std::string(strerror(err)));
  }

  if (mtime.sec == st.st_mtim.tv_sec &&
      mtime.nsec == st.st_mtim.tv_nsec)
    return;

  //
  // otherwise
  //
  read_file_into_thing(path, file_contents);
  h = hash_data(file_contents);
  mtime.sec = st.st_mtim.tv_sec;
  mtime.nsec = st.st_mtim.tv_nsec;
}

template <bool MT>
void jv_base_t<MT>::LookupAndCacheHash(hash_t &out, const char *path,
                                       std::string &file_contents) {
  assert(path);
  std::string_view sv(path);

  if constexpr (MT) {
    this->cached_hashes.try_emplace_or_visit(
        sv, path, std::ref(file_contents), std::ref(out),
        [&](typename ip_cached_hashes_type<MT>::value_type &x) -> void {
          x.second.Update(path, file_contents);
          out = x.second.h;
        });
  } else {
    auto it = this->cached_hashes.find(sv);
    if (it == this->cached_hashes.end()) {
      bool succ = this->cached_hashes.try_emplace(
          sv, path, std::ref(file_contents), std::ref(out)).second;
      assert(succ);
    } else {
      (*it).second.Update(path, file_contents);
      out = (*it).second.h;
    }
  }
}

template <bool MT>
bool jv_base_t<MT>::LookupByName(const char *name, binary_index_set &out) {
  assert(name);
  std::string_view sv(name);

  if constexpr (MT) {
    return static_cast<bool>(this->name_to_binaries.cvisit(
        sv,
        [&](const typename ip_name_to_binaries_map_type<MT>::value_type &x) -> void {
          assert(!x.second.set.empty());
          x.second.set.cvisit_all(
              [&](binary_index_t BIdx) -> void { out.insert(BIdx); });
        }));
  } else {
    auto it = this->name_to_binaries.find(sv);
    if (it == this->name_to_binaries.end()) {
      return false;
    } else {
      const ip_binary_index_set &set = (*it).second.set;
      assert(!set.empty());
      set.cvisit_all([&](binary_index_t BIdx) -> void { out.insert(BIdx); });
      return true;
    }
  }
}

template <bool MT>
std::optional<binary_index_t> jv_base_t<MT>::LookupByHash(const hash_t &h) {
  std::optional<binary_index_t> Res = std::nullopt;

  if constexpr (MT) {
    this->hash_to_binary.cvisit(
        h, [&](const typename ip_hash_to_binary_map_type<MT>::value_type &x) -> void {
          Res = x.second;
        });
  } else {
    auto it = this->hash_to_binary.find(h);
    if (it != this->hash_to_binary.end())
      Res = (*it).second;
  }

  return Res;
}

template <bool MT>
template <bool ValidatePath>
std::pair<binary_index_t, bool>
jv_base_t<MT>::AddFromPath(explorer_t &explorer,
                           jv_file_t &jv_file,
                           const char *path,
                           on_newbin_proc_t<MT> on_newbin,
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
      read_file_into_thing(path, file_contents);
      return file_contents;
    };
  else
    get_data = [&](void) -> std::string_view {
      return file_contents;
    };

  return AddFromDataWithHash(explorer, jv_file, get_data, h, path,
                             on_newbin, Options);
}

template <bool MT>
std::pair<binary_index_t, bool> jv_base_t<MT>::Add(binary_base_t<MT> &&b,
                                                   on_newbin_proc_t<MT> on_newbin) {
  try {
    auto h = b.Hash;
    binary_index_t Res = invalid_binary_index;
    bool isNewBinary;

    if constexpr (MT) {
      isNewBinary = this->hash_to_binary.try_emplace_or_visit(
          h, std::ref(Res), *this, std::move(b),
          [&](const typename ip_hash_to_binary_map_type<MT>::value_type &x) -> void {
            Res = x.second;
          });
    } else {
      auto it = this->hash_to_binary.find(h);
      if (it == this->hash_to_binary.end()) {
        isNewBinary = this->hash_to_binary.try_emplace(
          h, std::ref(Res), *this, std::move(b)).second;
        assert(isNewBinary);
      } else {
        isNewBinary = false;
        Res = (*it).second;
      }
    }

    assert(is_binary_index_valid(Res));

    binary_base_t<MT> &b_ = this->Binaries.at(Res);

    bool isNewName;
    if constexpr (MT) {
      isNewName = this->name_to_binaries.try_emplace_or_visit(
          b_.Name, get_allocator(), Res,
          [&](typename ip_name_to_binaries_map_type<MT>::value_type &x) -> void {
            x.second.set.insert(Res);
          });
    } else {
      auto it = this->name_to_binaries.find(b_.Name);
      if (it == this->name_to_binaries.end()) {
        isNewName =
            this->name_to_binaries.try_emplace(b_.Name, get_allocator(), Res)
                .second;
        assert(isNewName);
      } else {
        isNewName = false;
        (*it).second.set.insert(Res);
      }
    }

    if (unlikely(isNewBinary))
      on_newbin(b_);

    return std::make_pair(Res, isNewBinary || isNewName);
  } catch (...) {
    return std::make_pair(invalid_binary_index, false);
  }
}

template <bool MT>
std::pair<binary_index_t, bool>
jv_base_t<MT>::AddFromData(explorer_t &explorer,
                           jv_file_t &jv_file,
                           std::string_view data,
                           const char *name,
                           on_newbin_proc_t<MT> on_newbin,
                           const AddOptions_t &Options) {
  return AddFromDataWithHash(
      explorer, jv_file,
      [&](void) -> std::string_view { return data; },
      hash_data(data), name, on_newbin, Options);
}

template <bool MT>
std::pair<binary_index_t, bool> jv_base_t<MT>::AddFromDataWithHash(
    explorer_t &explorer,
    jv_file_t &jv_file,
    get_data_t get_data,
    const hash_t &h,
    const char *name,
    on_newbin_proc_t<MT> on_newbin,
    const AddOptions_t &Options) {
  try {
    binary_index_t Res = invalid_binary_index;
    bool isNewBinary;
    if constexpr (MT) {
      isNewBinary = this->hash_to_binary.try_emplace_or_visit(
          h, std::ref(Res), jv_file, *this,
          std::ref(explorer), get_data, std::ref(h), name,
          std::ref(Options),
          [&](const typename ip_hash_to_binary_map_type<MT>::value_type &x)
              -> void { Res = x.second; });
    } else {
      auto it = this->hash_to_binary.find(h);
      if (it == this->hash_to_binary.end()) {
        isNewBinary =
            this->hash_to_binary
                .try_emplace(h, std::ref(Res), jv_file,
                             *this, std::ref(explorer),
                             get_data, std::ref(h), name,
                             std::ref(Options))
                .second;
        assert(isNewBinary);
      } else {
        isNewBinary = false;
        Res = (*it).second;
      }
    }

    assert(is_binary_index_valid(Res));

    std::string_view name_sv(name);

    bool isNewName;
    if constexpr (MT) {
      isNewName = this->name_to_binaries.try_emplace_or_visit(
          name_sv, get_allocator(), Res,
          [&](typename ip_name_to_binaries_map_type<MT>::value_type &x) -> void {
            x.second.set.insert(Res);
          });
    } else {
      auto it = this->name_to_binaries.find(name_sv);
      if (it == this->name_to_binaries.end()) {
        isNewName =
            this->name_to_binaries.try_emplace(name_sv, get_allocator(), Res)
                .second;
        assert(isNewName);
      } else {
        isNewName = false;
        (*it).second.set.insert(Res);
      }
    }

    binary_base_t<MT> &b = this->Binaries.at(Res);
    if (Options.Objdump) {
      catch_exception([&]() {
        std::unique_ptr<llvm::object::Binary> Bin = B::Create(b.data());

        run_objdump_and_parse_addresses(b.is_file() ? b.Name.c_str() : nullptr,
                                        *Bin, b.Analysis.objdump);
      });
    }

    if (unlikely(isNewBinary))
      on_newbin(b);

    return std::make_pair(Res, isNewBinary || isNewName);
  } catch (...) {
    return std::make_pair(invalid_binary_index, false);
  }
}

template <bool MT>
adds_binary_t::adds_binary_t(binary_index_t &out,
                             jv_file_t &jv_file,
                             jv_base_t<MT> &jv,
                             explorer_t &explorer,
                             get_data_t get_data,
                             const hash_t &h,
                             const char *name,
                             const AddOptions_t &Options) {
  std::string_view data = get_data();

  if (unlikely(data.empty()))
    throw std::runtime_error("adds_binary_t(): no data");

  std::unique_ptr<llvm::object::Binary> Bin = B::Create(data);

  //
  // if we make it here then it's most likely a legitimate binary of interest.
  //
  {
    binary_base_t<false> b(jv_file);

    if (name)
      to_ips(b.Name, name); /* set up name */

    jv.DoAdd(b, explorer, *Bin, Options);

    //
    // success!
    //
    b.Data.resize(data.size()); /* lock it in */
    memcpy(&b.Data[0], data.data(), data.size());

    b.Hash = h;

    {
      auto e_lck = jv.Binaries.exclusive_access();

      BIdx = jv.Binaries.container().size();
      b.Idx = BIdx;
      jv.Binaries.container().push_back(std::move(b));
    }
  }

  binary_base_t<MT> &b = jv.Binaries.at(BIdx);
  assert(b.Idx == BIdx);

  for (function_t &f : b.Analysis.Functions)
    f.b = &b; /* XXX */

  out = BIdx;
}

template <bool MT>
adds_binary_t::adds_binary_t(binary_index_t &out,
                             jv_base_t<MT> &jv,
                             binary_base_t<MT> &&b) {
  if (unlikely(b.data().empty()))
    throw std::runtime_error("adds_binary_t(): no data");

  {
    auto e_lck = jv.Binaries.exclusive_access();

    BIdx = jv.Binaries.container().size();
    b.Idx = BIdx;
    jv.Binaries.container().push_back(std::move(b));
  }

  binary_base_t<MT> &newb = jv.Binaries.at(BIdx);
  for (function_t &f : newb.Analysis.Functions)
    f.b = &newb; /* XXX */

  out = BIdx;
}

template <bool MT>
void jv_base_t<MT>::clear(bool everything) {
  name_to_binaries.clear();
  hash_to_binary.clear();

  {
    auto e_lck = this->Binaries.exclusive_access();

    this->Binaries.container().clear();
  }

  {
    ip_scoped_lock<ip_sharable_mutex> e_lck_sets(this->FIdxSetsMtx);
    this->FIdxSets.clear();
  }

  if (everything)
    cached_hashes.clear();
}

template <bool MT>
void jv_base_t<MT>::InvalidateFunctionAnalyses(void) {
  for_each_binary(std::execution::par_unseq, *this, [&](binary_base_t<MT> &b) {
    for_each_function_in_binary(std::execution::par_unseq, b,
                                [&](function_t &f) { f.InvalidateAnalysis(); });
  });
}

template <bool MT>
function_t::function_t(binary_base_t<MT> &b, function_index_t Idx)
    : b((void *)&b), Idx(Idx), Callers(b.get_allocator()) {}

function_t::function_t(const ip_void_allocator_t &A)
    : Callers(A) {}

#define VALUES_TO_INSTANTIATE_WITH                                             \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template function_t::function_t(binary_base_t<GET_VALUE(elem)> &,            \
                                  function_index_t Idx);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, ValidatePath, elem)                                  \
  template std::pair<binary_index_t, bool>                                     \
  jv_base_t<GET_VALUE(elem)>::AddFromPath<ValidatePath>(                       \
      explorer_t &, jv_file_t &, const char *,                                 \
      on_newbin_proc_t<GET_VALUE(elem)>, const AddOptions_t &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, true, VALUES_TO_INSTANTIATE_WITH)
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, false, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template std::pair<binary_index_t, bool> jv_base_t<GET_VALUE(elem)>::Add(    \
      binary_base_t<GET_VALUE(elem)> &&, on_newbin_proc_t<GET_VALUE(elem)>);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template std::pair<binary_index_t, bool>                                     \
  jv_base_t<GET_VALUE(elem)>::AddFromData(                                     \
      explorer_t &, jv_file_t &, std::string_view, const char *,               \
      on_newbin_proc_t<GET_VALUE(elem)>, const AddOptions_t &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template std::optional<binary_index_t>                                       \
  jv_base_t<GET_VALUE(elem)>::LookupByHash(const hash_t &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template bool jv_base_t<GET_VALUE(elem)>::LookupByName(const char *name,     \
                                                         binary_index_set &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template void jv_base_t<GET_VALUE(elem)>::clear(bool everything);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
template void jv_base_t<GET_VALUE(elem)>::InvalidateFunctionAnalyses(void);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)
}
