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
  ip_string s(path, Binaries.get_allocator());

  {
    ip_scoped_lock<ip_mutex> lck(this->cached_hashes_mtx);

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

  ip_string s(Binaries.get_allocator());
  to_ips(s, name);

  {
    ip_scoped_lock<ip_mutex> lck(this->name_to_binaries_mtx);

    auto it = this->name_to_binaries.find(s);
    if (it == this->name_to_binaries.end()) {
      return boost::optional<const ip_binary_index_set &>();
    } else {
      return (*it).second;
    }
  }
}

binary_index_t jv_t::LookupWithHash(const hash_t &h) {
  ip_scoped_lock<ip_mutex> lck(this->hash_to_binary_mtx);

  auto it = this->hash_to_binary.find(h);
  if (it == this->hash_to_binary.end())
    return invalid_binary_index;

  return (*it).second;
}

std::pair<binary_index_t, bool> jv_t::AddFromPath(explorer_t &E,
                                                  const char *path,
                                                  binary_index_t TargetIdx) {
  assert(path);

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

  return AddFromDataWithHash(E, get_data, h, the_path.c_str(), TargetIdx);
}

std::pair<binary_index_t, bool> jv_t::AddFromData(explorer_t &E,
                                                  std::string_view x,
                                                  const char *name,
                                                  binary_index_t TargetIdx) {
  return AddFromDataWithHash(
      E,
      [&](ip_string &out) -> void {
        out.resize(x.size());
        memcpy(&out[0], x.data(), out.size());
      },
      hash_data(x), name, TargetIdx);
}

std::pair<binary_index_t, bool> jv_t::AddFromDataWithHash(explorer_t &E,
                                                          get_data_t get_data,
                                                          const hash_t &h,
                                                          const char *name,
                                                          binary_index_t TargetIdx) {
  binary_index_t BIdx = LookupWithHash(h);

  if (is_binary_index_valid(BIdx))
    return std::make_pair(BIdx, false);

  {
    ip_scoped_lock<ip_mutex> lck(this->binaries_mtx);

    if (is_binary_index_valid(TargetIdx)) {
      BIdx = TargetIdx;
    } else {
      BIdx = Binaries.size();
      Binaries.emplace_back(Binaries.get_allocator());
    }

    binary_t &b = Binaries.at(BIdx);
    b.bbmap_mtx(); /* XXX */
    b.fnmap_mtx(); /* XXX */
    b.Hash = h;

    {
      ip_scoped_lock<ip_mutex> lck(this->hash_to_binary_mtx);

      this->hash_to_binary.insert(std::make_pair(h, BIdx));
    }

    if (name) {
      to_ips(b.Name, name);

      ip_scoped_lock<ip_mutex> lck(this->name_to_binaries_mtx);

      auto it = this->name_to_binaries.find(b.Name);
      if (it == this->name_to_binaries.end()) {
        ip_binary_index_set set(Binaries.get_allocator());
        set.insert(BIdx);
        this->name_to_binaries.insert(std::make_pair(b.Name, set));
      } else {
        (*it).second.insert(BIdx);
      }
    }
  }

  assert(is_binary_index_valid(BIdx));

  binary_t &b = Binaries.at(BIdx);

  get_data(b.Data);

  if (b.Data.empty())
    throw std::runtime_error("AddFromDataWithHash: empty data"); /* uh oh... */

  DoAdd(b, E);

  return std::make_pair(BIdx, true);
}

void jv_t::clear(bool everything) {
  {
    ip_scoped_lock<ip_mutex> lck(this->name_to_binaries_mtx);
    name_to_binaries.clear();
  }

  {
    ip_scoped_lock<ip_mutex> lck(this->hash_to_binary_mtx);
    hash_to_binary.clear();
  }

  {
    ip_scoped_lock<ip_mutex> lck(this->binaries_mtx);
    Binaries.clear();
  }

  if (everything) {
    ip_scoped_lock<ip_mutex> lck(this->cached_hashes_mtx);

    cached_hashes.clear();
  }
}

void jv_t::InvalidateFunctionAnalyses(void) {
  for_each_binary(std::execution::par_unseq, *this, [&](binary_t &b) {
    for_each_function_in_binary(std::execution::par_unseq, b,
                                [&](function_t &f) { f.InvalidateAnalysis(); });
  });
}

}
