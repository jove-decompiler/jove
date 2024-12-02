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

void jv_t::LookupAndCacheHash(hash_t &out, const char *path,
                              std::string &file_contents) {
  assert(path);
  std::string_view sv(path);

  this->cached_hashes.try_emplace_or_visit(
      sv, path, std::ref(file_contents), std::ref(out),
      [&](typename ip_cached_hashes_type::value_type &x) -> void {
        x.second.Update(path, file_contents);
        out = x.second.h;
      });
}

bool jv_t::LookupByName(const char *name, binary_index_set &out) {
  assert(name);
  std::string_view sv(name);

  return static_cast<bool>(this->name_to_binaries.cvisit(
      sv,
      [&](const typename ip_name_to_binaries_map_type::value_type &x) -> void {
        assert(!x.second.set.empty());
        x.second.set.cvisit_all(
            [&](binary_index_t BIdx) -> void { out.insert(BIdx); });
      }));
}

std::optional<binary_index_t> jv_t::LookupByHash(const hash_t &h) {
  std::optional<binary_index_t> Res = std::nullopt;

  this->hash_to_binary.cvisit(
      h, [&](const typename ip_hash_to_binary_map_type::value_type &x) -> void {
        Res = x.second;
      });
  return Res;
}

template <bool ValidatePath>
std::pair<binary_index_t, bool> jv_t::AddFromPath(explorer_t &explorer,
                                                  const char *path,
                                                  on_newbin_proc_t on_newbin,
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

  return AddFromDataWithHash(explorer, get_data, h, path,
                             invalid_binary_index, on_newbin, Options);
}

bool jv_t::InplaceAdd(explorer_t &explorer,
                      const binary_index_t BIdx,
                      const AddOptions_t &Options) {
  binary_t &b = Binaries.at(BIdx);
  return AddFromDataWithHash(
             explorer, [&](void) -> std::string_view { return b.Data; },
             hash_data(b.Data), b.Name.c_str(), BIdx, [](binary_t &) {},
             Options)
      .second;
}

std::pair<binary_index_t, bool> jv_t::Add(binary_t &&b,
                                          on_newbin_proc_t on_newbin) {
  try {
    auto h = b.Hash;
    binary_index_t Res = invalid_binary_index;
    const bool isNewBinary = this->hash_to_binary.try_emplace_or_visit(
        h, std::ref(Res), std::ref(*this), std::move(b),
        [&](const typename ip_hash_to_binary_map_type::value_type &x) -> void {
          Res = x.second;
        });

    assert(is_binary_index_valid(Res));

    binary_t &b_ = this->Binaries.at(Res);

    const bool isNewName = this->name_to_binaries.try_emplace_or_visit(
        b_.Name, get_allocator(), Res,
        [&](typename ip_name_to_binaries_map_type::value_type &x) -> void {
          x.second.set.insert(Res);
        });

    if (unlikely(isNewBinary))
      on_newbin(b_);

    return std::make_pair(Res, isNewBinary || isNewName);
  } catch (...) {
    return std::make_pair(invalid_binary_index, false);
  }
}

std::pair<binary_index_t, bool> jv_t::AddFromData(explorer_t &explorer,
                                                  std::string_view data,
                                                  const char *name,
                                                  on_newbin_proc_t on_newbin,
                                                  const AddOptions_t &Options) {
  return AddFromDataWithHash(
      explorer,
      [&](void) -> std::string_view { return data; },
      hash_data(data), name, invalid_binary_index, on_newbin, Options);
}

std::pair<binary_index_t, bool> jv_t::AddFromDataWithHash(explorer_t &explorer,
                                                          get_data_t get_data,
                                                          const hash_t &h,
                                                          const char *name,
                                                          const binary_index_t TargetIdx,
                                                          on_newbin_proc_t on_newbin,
                                                          const AddOptions_t &Options) {
  try {
    binary_index_t Res = invalid_binary_index;
    const bool isNewBinary = this->hash_to_binary.try_emplace_or_visit(
        h, std::ref(Res), std::ref(*this), std::ref(explorer), get_data,
        std::ref(h), name, TargetIdx, std::ref(Options),
        [&](const typename ip_hash_to_binary_map_type::value_type &x) -> void {
          Res = x.second;
        });

    assert(is_binary_index_valid(Res));

    const bool isNewName = this->name_to_binaries.try_emplace_or_visit(
        std::string_view(name), get_allocator(), Res,
        [&](typename ip_name_to_binaries_map_type::value_type &x) -> void {
          x.second.set.insert(Res);
        });

    if (unlikely(isNewBinary))
      on_newbin(this->Binaries.at(Res));

    return std::make_pair(Res, isNewBinary || isNewName);
  } catch (...) {
    return std::make_pair(invalid_binary_index, false);
  }
}

adds_binary_t::adds_binary_t(binary_index_t &out,
                             jv_t &jv,
                             explorer_t &explorer,
                             get_data_t get_data,
                             const hash_t &h,
                             const char *name,
                             const binary_index_t TargetIdx,
                             const AddOptions_t &Options) {
  std::string_view data = get_data();

  if (unlikely(data.empty()))
    throw std::runtime_error("adds_binary_t(): no data");

  std::unique_ptr<llvm::object::Binary> Bin = B::Create(data);

  //
  // if we make it here then it's most likely a legitimate binary of interest.
  //
  const bool HasTargetIdx = is_binary_index_valid(TargetIdx);

  std::unique_ptr<binary_t> _b;
  if (!HasTargetIdx)
    _b = std::make_unique<binary_t>(jv.get_allocator());

  {
    binary_t &b = _b ? *_b : jv.Binaries.at(TargetIdx);

    if (HasTargetIdx) {
      b.Idx = TargetIdx; /* XXX might as well ensure? */
    } else {
      if (name)
        to_ips(b.Name, name); /* set up name */
    }

    if (Options.Objdump) {
      try {
        run_objdump_and_parse_addresses(b.is_file() ? b.Name.c_str() : nullptr,
                                        *Bin, b.Analysis.objdump);
      } catch (...) {
        ; // failed to run objdump
      }
    }

    jv.DoAdd(b, explorer, *Bin, Options);

    //
    // success!
    //
    if (!HasTargetIdx) {
      b.Data.resize(data.size()); /* lock it in */
      memcpy(&b.Data[0], data.data(), data.size());
    }
  }

  BIdx = TargetIdx;
  if (!HasTargetIdx) {
    assert(!is_binary_index_valid(BIdx));

    auto e_lck = jv.Binaries.exclusive_access();

    BIdx = jv.Binaries._deque.size();
    _b->Idx = BIdx;
    jv.Binaries._deque.push_back(std::move(*_b));
  }

  binary_t &b = jv.Binaries.at(BIdx);
  b.Hash = h;

  assert(b.Idx == BIdx);

  if (!HasTargetIdx)
    for (function_t &f : b.Analysis.Functions)
      f.b = &b; /* XXX */

  out = BIdx;
}

adds_binary_t::adds_binary_t(binary_index_t &out, jv_t &jv, binary_t &&b) {
  if (unlikely(b.data().empty()))
    throw std::runtime_error("adds_binary_t(): no data");

  {
    auto e_lck = jv.Binaries.exclusive_access();

    BIdx = jv.Binaries._deque.size();
    b.Idx = BIdx;
    jv.Binaries._deque.push_back(std::move(b));
  }

  for (function_t &f : b.Analysis.Functions)
    f.b = &b; /* XXX */

  out = BIdx;
}

void jv_t::clear(bool everything) {
  name_to_binaries.clear();
  hash_to_binary.clear();

  {
    auto e_lck = this->Binaries.exclusive_access();

    this->Binaries._deque.clear();
  }

  {
    ip_scoped_lock<ip_sharable_mutex> e_lck_sets(this->FIdxSetsMtx);
    this->FIdxSets.clear();
  }

  if (everything)
    cached_hashes.clear();
}

void jv_t::InvalidateFunctionAnalyses(void) {
  for_each_binary(std::execution::par_unseq, *this, [&](binary_t &b) {
    for_each_function_in_binary(std::execution::par_unseq, b,
                                [&](function_t &f) { f.InvalidateAnalysis(); });
  });
}

function_t::function_t(binary_t &b, function_index_t Idx)
    : b(&b), Idx(Idx), Callers(b.get_allocator()) {}

function_t::function_t(const ip_void_allocator_t &A)
    : Callers(A) {}

#define VALUES_TO_INSTANTIATE_WITH                                             \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)
#define DO_INSTANTIATE(r, data, elem)                                          \
  template std::pair<binary_index_t, bool> jv_t::AddFromPath<GET_VALUE(elem)>( \
      explorer_t &, const char *, on_newbin_proc_t, const AddOptions_t &);

BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

}
