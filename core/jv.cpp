#include "jove/jove.h"
#include "util.h"
#include "hash.h"

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace jove {

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
      it = cached_hashes.insert(std::make_pair(s, cached_hash_t(0))).first;

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

binary_index_t jv_t::LookupWithHash(hash_t h) {
  ip_scoped_lock<ip_mutex> lck(this->hash_to_binary_mtx);

  auto it = this->hash_to_binary.find(h);
  if (it == this->hash_to_binary.end())
    return invalid_binary_index;

  return (*it).second;
}

std::pair<binary_index_t, bool> jv_t::AddFromPath(explorer_t &E, const char *path) {
  assert(path);

  fs::path the_path = fs::canonical(path);

  std::string file_contents;
  hash_t h = LookupAndCacheHash(the_path.c_str(), file_contents);

  if (file_contents.empty())
    read_file_into_thing(path, file_contents);

  return AddFromDataWithHash(E, file_contents, h, the_path.c_str());
}

std::pair<binary_index_t, bool> jv_t::AddFromData(explorer_t &E,
                                                  std::string_view data,
                                                  const char *name) {
  return AddFromDataWithHash(E, data, hash_data(data), name);
}

std::pair<binary_index_t, bool> jv_t::AddFromDataWithHash(explorer_t &E,
                                                          std::string_view data,
                                                          hash_t h,
                                                          const char *name) {
  if (data.empty())
    throw std::runtime_error("AddFromDataWithHash: empty data");

  {
    ip_scoped_lock<ip_mutex> lck(this->binaries_mtx);

    binary_index_t BIdx = LookupWithHash(h);

    if (is_binary_index_valid(BIdx))
      return std::make_pair(BIdx, false);

    BIdx = Binaries.size();
    binary_t &b = Binaries.emplace_back(Binaries.get_allocator());
    b.Hash = h;

    b.Data.resize(data.size());
    memcpy(&b.Data[0], data.data(), data.size());

    try {
      DoAdd(b, E);
    } catch (...) {
      Binaries.pop_back(); /* OOPS */
      throw;
    }

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

    return std::make_pair(BIdx, true);
  }
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

}
