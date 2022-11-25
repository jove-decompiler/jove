#include "jv.h"

#include <fstream>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/graph/adj_list_serialize.hpp>

#include <sys/stat.h>

namespace jove {

void ReadJvFromFile(const std::string &path, jv_t &out) {
  std::ifstream ifs(path);
  if (!ifs.is_open())
    throw std::runtime_error("ReadDecompilationFromFile: failed to open " + path);

  boost::archive::text_iarchive ia(ifs);
  ia >> out;
}

void WriteJvToFile(const std::string &path, const jv_t &in) {
  assert(!path.empty());

  std::string tmp_fp(path);
  tmp_fp.append(".XXXXXX");

  int fd = mkstemp(&tmp_fp[0]);
  if (fd < 0) {
    int err = errno;
    throw std::runtime_error(
        "WriteDecompilationToFile: failed to make temporary file from " +
        tmp_fp + ": " + std::string(strerror(err)));
  } else {
    if (::fchmod(fd, 0666) < 0) {
      int err = errno;
      throw std::runtime_error(
          "WriteDecompilationToFile: changing permissions of temporary file failed: " +
          std::string(strerror(err)));
    }

    if (::close(fd) < 0) {
      int err = errno;
      throw std::runtime_error(
          "WriteDecompilationToFile: closing temporary file failed: " +
          std::string(strerror(err)));
    }
  }

  {
    std::ofstream ofs(tmp_fp);
    if (!ofs.is_open())
      throw std::runtime_error(
          "WriteDecompilationToFile: failed to open temporary file " + tmp_fp);

    boost::archive::text_oarchive oa(ofs);
    oa << in;
  }

  if (::rename(tmp_fp.c_str(), path.c_str()) < 0) { /* atomically replace */
    int err = errno;
    throw std::runtime_error("WriteDecompilationToFile: failed to rename " +
                             tmp_fp + " to " + path + ": " +
                             std::string(strerror(err)));
  }
}


}
