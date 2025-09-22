#pragma once
#include <boost/filesystem.hpp>

namespace jove {

static inline void dotdot(boost::filesystem::path &the_path) {
  the_path = the_path.parent_path();
}

}
