#include "jove/jove.h"
#include "elf.h"
#include "hash.h"
#include "util.h"

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace jove {

void UpdateCachedHash(cached_hash_t &cache, const char *path) {
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
  cache.h = hash_file(path);
  cache.mtime.sec = st.st_mtim.tv_sec;
  cache.mtime.nsec = st.st_mtim.tv_nsec;
}

hash_t jv_t::LookupAndCacheHash(const std::string &path) {
  ip_string tmp(Binaries.get_allocator());
  to_ips(tmp, path);

  {
    ip_scoped_lock<ip_mutex> lck(this->cached_hashes_mtx);

    auto it = cached_hashes.find(tmp);
    if (it == cached_hashes.end())
      it = cached_hashes.insert(std::make_pair(tmp, cached_hash_t(0))).first;

    cached_hash_t &cache = (*it).second;
    UpdateCachedHash(cache, path.c_str());

    return cache.h;
  }
}

binary_index_t jv_t::LookupWithHash(hash_t h) {
  ip_scoped_lock<ip_mutex> lck(this->hash_to_binary_mtx);

  auto it = this->hash_to_binary.find(h);
  if (it == this->hash_to_binary.end())
    return invalid_binary_index;

  return (*it).second;
}

binary_index_t jv_t::Lookup(const char *path) {
  fs::path the_path;
  try {
    the_path = fs::canonical(path);
  } catch (...) {
    return invalid_binary_index;
  }

  hash_t h = LookupAndCacheHash(the_path.string());

  {
    ip_scoped_lock<ip_mutex> lck(this->hash_to_binary_mtx);

    auto it = this->hash_to_binary.find(h);
    if (it == this->hash_to_binary.end())
      return invalid_binary_index;

    return (*it).second;
  }
}

binary_index_t jv_t::Add(const char *path, explorer_t &E) {
  fs::path the_path = fs::canonical(path);
  hash_t h = LookupAndCacheHash(the_path.string());

  {
    ip_scoped_lock<ip_mutex> lck(this->binaries_mtx);

    binary_index_t BIdx = LookupWithHash(h);

    if (is_binary_index_valid(BIdx))
      return BIdx;

    BIdx = Binaries.size();
    binary_t &b = Binaries.emplace_back(Binaries.get_allocator());
    b.Hash = h;

    read_file_into_thing(path, b.Data);

    if (b.Data.empty())
      throw std::runtime_error("given file \"" + std::string(path) + "\" is empty");

    std::unique_ptr<llvm::object::Binary> ObjectFile = CreateBinary(b.data());

    {
      ip_scoped_lock<ip_mutex> lck(this->hash_to_binary_mtx);

      this->hash_to_binary.insert(std::make_pair(h, BIdx));
    }

    return BIdx;
  }
}

} // namespace jove
