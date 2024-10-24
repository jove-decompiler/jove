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
  ip_string s(path, get_allocator());

  // FIXME handle empty file
  this->cached_hashes.try_emplace_or_visit(
      s, path, std::ref(file_contents), std::ref(out),
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

std::pair<binary_index_t, bool> jv_t::AddFromPath(explorer_t &explorer,
                                                  const char *path,
                                                  on_newbin_proc_t on_newbin,
                                                  const AddOptions_t &Options) {
  assert(path);

  if (!fs::exists(path))
    return std::make_pair(invalid_binary_index, false);

  fs::path the_path = fs::canonical(path);

  std::string file_contents;
  hash_t h;
  LookupAndCacheHash(h, the_path.c_str(), file_contents);

  get_data_t get_data;
  if (file_contents.empty())
    get_data = [&](ip_string &out) -> void { read_file_into_thing(path, out); };
  else
    get_data = [&](ip_string &out) -> void {
      out.resize(file_contents.size());
      memcpy(&out[0], file_contents.data(), out.size());
    };

  return AddFromDataWithHash(explorer, get_data, h, the_path.c_str(),
                             invalid_binary_index, on_newbin, Options);
}

bool jv_t::Add(explorer_t &explorer,
               const binary_index_t BIdx,
               const AddOptions_t &Options) {
  binary_t &b = Binaries.at(BIdx);
  return AddFromDataWithHash(
             explorer, [](ip_string &) -> void {}, hash_data(b.Data),
             b.Name.c_str(), BIdx, [](binary_t &) {}, Options)
      .second;
}

std::pair<binary_index_t, bool> jv_t::AddFromData(explorer_t &explorer,
                                                  std::string_view x,
                                                  const char *name,
                                                  on_newbin_proc_t on_newbin,
                                                  const AddOptions_t &Options) {
  return AddFromDataWithHash(
      explorer,
      [&](ip_string &out) -> void {
        out.resize(x.size());
        memcpy(&out[0], x.data(), out.size());
      },
      hash_data(x), name, invalid_binary_index, on_newbin, Options);
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
  const bool HasTargetIdx = is_binary_index_valid(TargetIdx);

  std::unique_ptr<binary_t> _b;
  if (!HasTargetIdx)
    _b = std::make_unique<binary_t>(jv.get_allocator());

  {
    binary_t &b = _b ? *_b : jv.Binaries.at(TargetIdx);

    if (HasTargetIdx) {
      b.Idx = TargetIdx; /* might as well */
    } else {
      get_data(b.Data);
      if (name)
        to_ips(b.Name, name);
    }

    if (b.Data.empty())
      throw std::runtime_error(
          "AddFromDataWithHash: empty data"); /* uh oh... */

    std::unique_ptr<llvm::object::Binary> Bin = B::Create(b.data());

    if (Options.Objdump)
      run_objdump_and_parse_addresses(b.is_file() ? b.Name.c_str() : nullptr,
                                      *Bin, b.Analysis.objdump);

    jv.DoAdd(b, explorer, *Bin, Options);
  }

  BIdx = TargetIdx;
  if (!HasTargetIdx) {
    assert(!is_binary_index_valid(BIdx));

    ip_scoped_lock<ip_sharable_mutex> e_b_lck(jv.Binaries._mtx);

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

void jv_t::clear(bool everything) {
  name_to_binaries.clear();
  hash_to_binary.clear();

  {
    ip_scoped_lock<ip_sharable_mutex> e_lck(this->Binaries._mtx);

    this->Binaries._deque.clear();
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

}
