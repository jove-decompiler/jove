#include "win.h"

#include <boost/preprocessor/stringize.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <algorithm>
#include <array>
#include <cstring>

namespace jove {
namespace win {

static const char *apiset_table[][2] = {
#define _APISET(a,d) { BOOST_PP_STRINGIZE(a), BOOST_PP_STRINGIZE(d) },
#include "windows/apisetschema.spec.in"
};

static bool compare(const char *const lhs[2], const char *const rhs[2]) {
  return std::strcmp(lhs[0], rhs[0]) < 0;
}

const char *dll_of_apiset(const char *needed_c_str) {
  //
  // (1) The name must begin either with the string api- or ext-.
  // (2) [TODO] The name must end with the sequence l<n>-<n>-<n>, where n consists of decimal digits.
  //
  std::string needed(needed_c_str);
  if (needed.size() < sizeof("api-"))
    return nullptr;

  if (boost::algorithm::ends_with(needed, ".dll"))
    needed = needed.substr(0, needed.size() - sizeof(".dll")+1); /* chop it off */

  const char *key[2] = {needed.c_str(), ""};

  auto it = std::lower_bound(std::begin(apiset_table),
                             std::end(apiset_table),
                             key, compare);

  if (it != std::end(apiset_table) &&
      std::strcmp((*it)[0], key[0]) == 0)
    return (*it)[1];

  return nullptr;
}

}
}
