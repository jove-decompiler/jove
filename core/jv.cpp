#include "jove/jove.h"
#include "util.h"
#include "hash.h"

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace jove {

size_t jvDefaultInitialSize(void) {
  return (sizeof(void *) == 8 ? 128UL : 1UL) * 2UL * 1024UL * 65536UL;
}

void jv_t::UpdateCachedHash(cached_hash_t &cache,
                            const char *path,
                            std::string &file_contents) {
  struct stat st;
  if (stat(path, &st) < 0) {
    int err = errno;
    throw std::runtime_error("HashNeedsUpdate: stat failed: " +
                             std::string(strerror(err)));
  }

  if (cache.mtime.sec == st.st_mtim.tv_sec &&
      cache.mtime.nsec == st.st_mtim.tv_nsec)
    return;

  //
  // otherwise
  //

  read_file_into_thing(path, file_contents);
  cache.h = hash_data(file_contents);
  cache.mtime.sec = st.st_mtim.tv_sec;
  cache.mtime.nsec = st.st_mtim.tv_nsec;
}

hash_t jv_t::LookupAndCacheHash(const char *path,
                                std::string &file_contents) {
  ip_string s(path, get_allocator());

  {
    ip_scoped_lock<ip_mutex> lck(this->cached_hashes_mtx);

    // FIXME handle empty file
    auto it = cached_hashes.find(s);
    if (it == cached_hashes.end())
      it = cached_hashes.emplace(s, cached_hash_t{}).first;

    cached_hash_t &cache = (*it).second;
    UpdateCachedHash(cache, path, file_contents);

    return cache.h;
  }
}

boost::optional<const ip_binary_index_set &> jv_t::Lookup(const char *name) {
  assert(name);

  ip_string s(get_allocator());
  to_ips(s, name);

  {
    ip_sharable_lock<ip_sharable_mutex> s_lck(this->name_to_binaries_mtx);

    auto it = this->name_to_binaries.find(s);
    if (it == this->name_to_binaries.end()) {
      return boost::optional<const ip_binary_index_set &>();
    } else {
      return (*it).second;
    }
  }
}

boost::optional<binary_index_t> jv_t::LookupByHash(const hash_t &h) {
  ip_sharable_lock<ip_sharable_mutex> s_lck(this->hash_to_binary_mtx);

  auto it = this->hash_to_binary.find(h);
  if (it == this->hash_to_binary.end()) {
    return boost::optional<binary_index_t>();
  } else {
    return (*it).second;
  }
}

std::pair<binary_index_t, bool> jv_t::AddFromPath(explorer_t &E,
                                                  const char *path,
                                                  const binary_index_t TargetIdx,
                                                  on_newbin_proc_t on_newbin) {
  assert(path);

  if (!fs::exists(path))
    return std::make_pair(invalid_binary_index, false);

  fs::path the_path = fs::canonical(path);

  std::string file_contents;
  hash_t h = LookupAndCacheHash(the_path.c_str(), file_contents);

  get_data_t get_data;
  if (file_contents.empty())
    get_data = [&](ip_string &out) -> void { read_file_into_thing(path, out); };
  else
    get_data = [&](ip_string &out) -> void {
      out.resize(file_contents.size());
      memcpy(&out[0], file_contents.data(), out.size());
    };

  return AddFromDataWithHash(E, get_data, h, the_path.c_str(), TargetIdx, on_newbin);
}

std::pair<binary_index_t, bool> jv_t::AddFromData(explorer_t &E,
                                                  std::string_view x,
                                                  const char *name,
                                                  const binary_index_t TargetIdx,
                                                  on_newbin_proc_t on_newbin) {
  return AddFromDataWithHash(
      E,
      [&](ip_string &out) -> void {
        out.resize(x.size());
        memcpy(&out[0], x.data(), out.size());
      },
      hash_data(x), name, TargetIdx, on_newbin);
}

std::pair<binary_index_t, bool> jv_t::AddFromDataWithHash(explorer_t &E,
                                                          get_data_t get_data,
                                                          const hash_t &h,
                                                          const char *name,
                                                          const binary_index_t TargetIdx,
                                                          on_newbin_proc_t on_newbin) {
  const bool HasTargetIdx = is_binary_index_valid(TargetIdx);

  //
  // check if exists (fast path)
  //
  {
    ip_sharable_lock<ip_sharable_mutex> s_lck(this->hash_to_binary_mtx);

    auto it = this->hash_to_binary.find(h);
    if (it != this->hash_to_binary.end()) {
      assert(!HasTargetIdx);
      return std::make_pair((*it).second, false);
    }
  }

  std::unique_ptr<binary_t> _b;
  if (!HasTargetIdx)
    _b = std::make_unique<binary_t>(get_allocator());

  {
    binary_t &b = _b ? *_b : Binaries.at(TargetIdx);

    get_data(b.Data);

    if (b.Data.empty())
      throw std::runtime_error(
          "AddFromDataWithHash: empty data"); /* uh oh... */

    try {
      DoAdd(b, E);
    } catch (const std::exception &e) {
      return std::make_pair(invalid_binary_index, false);
    }
  }

  ip_scoped_lock<ip_sharable_mutex> e_h2b_lck(this->hash_to_binary_mtx);

  //
  // check if exists
  //
  {
    auto it = this->hash_to_binary.find(h);
    if (it != this->hash_to_binary.end()) {
      assert(!HasTargetIdx);
      return std::make_pair((*it).second, false);
    }
  }

  //
  // nope!
  //
  binary_index_t BIdx = TargetIdx;
  if (!is_binary_index_valid(BIdx)) {
    assert(!HasTargetIdx);

    ip_scoped_lock<ip_sharable_mutex> e_b_lck(this->Binaries._mtx);

    BIdx = Binaries._deque.size();
    Binaries._deque.push_back(std::move(*_b));
  }

  binary_t &b = Binaries.at(BIdx);
  b.Idx = BIdx;
  b.Hash = h;

  if (!HasTargetIdx)
    for (function_t &f : b.Analysis.Functions)
      f.b = &b; /* XXX */

  this->hash_to_binary.insert(std::make_pair(h, BIdx));

  if (name) {
    to_ips(b.Name, name);

    ip_scoped_lock<ip_sharable_mutex> e_n2b_lck(this->name_to_binaries_mtx);

    auto it = this->name_to_binaries.find(b.Name);
    if (it == this->name_to_binaries.end()) {
      ip_binary_index_set set(get_allocator());
      set.insert(BIdx);
      this->name_to_binaries.insert(std::make_pair(b.Name, set));
    } else {
      (*it).second.insert(BIdx);
    }
  }

  on_newbin(b);

  return std::make_pair(BIdx, true);
}

void jv_t::clear(bool everything) {
  {
    ip_scoped_lock<ip_sharable_mutex> e_lck(this->name_to_binaries_mtx);

    name_to_binaries.clear();
  }

  {
    ip_scoped_lock<ip_sharable_mutex> e_lck(this->hash_to_binary_mtx);

    hash_to_binary.clear();
  }

  {
    ip_scoped_lock<ip_sharable_mutex> e_lck(this->Binaries._mtx);

    this->Binaries._deque.clear();
  }

  if (everything) {
    ip_scoped_lock<ip_mutex> e_lck(this->cached_hashes_mtx);

    cached_hashes.clear();
  }
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

void binary_t::InvalidateBasicBlockAnalyses(void) {
  for_each_function_in_binary(std::execution::par_unseq, *this,
                              [&](function_t &f) { f.InvalidateAnalysis(); });
}

void binary_t::Analysis_t::addSymDynTarget(const std::string &sym,
                                           dynamic_target_t X) {
  ip_string ips(Functions._deque.get_allocator());
  to_ips(ips, sym);

  auto it = SymDynTargets.find(ips);
  if (it == SymDynTargets.end())
    it = SymDynTargets.emplace(ips, ip_dynamic_target_set(Functions._deque.get_allocator())).first;

  (*it).second.insert(X);
}

void binary_t::Analysis_t::addRelocDynTarget(uint64_t A, dynamic_target_t X) {
  auto it = RelocDynTargets.find(A);
  if (it == RelocDynTargets.end())
    it = RelocDynTargets.emplace(A, ip_dynamic_target_set(Functions._deque.get_allocator())).first;

  (*it).second.insert(X);
}

void binary_t::Analysis_t::addIFuncDynTarget(uint64_t A, dynamic_target_t X) {
  auto it = IFuncDynTargets.find(A);
  if (it == IFuncDynTargets.end())
    it = IFuncDynTargets.emplace(A, ip_dynamic_target_set(Functions._deque.get_allocator())).first;

  (*it).second.insert(X);
}

void basic_block_properties_t::AddParent(function_index_t FIdx, jv_t &jv) {
  ip_func_index_set Idxs(jv.get_allocator());

  {
    if (this->Parents)
      Idxs = *this->Parents;
  }

  {
    bool success = Idxs.insert(FIdx).second;
    assert(success);
  }

  {
    ip_sharable_lock<ip_sharable_mutex> s_lck(jv.FIdxSetsMtx);

    auto it = jv.FIdxSets.find(Idxs);
    if (it != jv.FIdxSets.end()) {
      this->Parents = &(*it);
      return;
    }
  }

  ip_scoped_lock<ip_sharable_mutex> e_lck(jv.FIdxSetsMtx);

  this->Parents = &(*jv.FIdxSets.insert(boost::move(Idxs)).first);
}

bool basic_block_properties_t::insertDynTarget(dynamic_target_t X, jv_t &jv) {
  ip_void_allocator_t Alloc = jv.get_allocator();

  if (!pDynTargets)
    pDynTargets =
        Alloc.get_segment_manager()->construct<ip_dynamic_target_set>(
            boost::interprocess::anonymous_instance)(Alloc);
  return pDynTargets->insert(X).second;
}

}
