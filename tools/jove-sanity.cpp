#include "tool.h"

#include <boost/filesystem.hpp>

#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

class SanityCheck : public JVTool<ToolKind::CopyOnWrite> {
  int Run(void) override;
};

JOVE_REGISTER_TOOL("sanity", SanityCheck);

int SanityCheck::Run(void) {
  bool ret = 0;

  for_each_binary(maybe_par_unseq, jv, [&](binary_t &b) {
    if (!b.is_file())
      return;

    const char *const filename = b.path();
    assert(filename);

    if (!fs::exists(filename)) {
      WithColor::error() << llvm::formatv("\"{0}\" no longer exists.\n",
                                          filename);

      ret = 1;
      return;
    }

    std::vector<uint8_t> buff;
    read_file_into_vector(filename, buff);

    if (buff.empty()) {
      WithColor::error() << llvm::formatv("\"{0}\" has a length of zero.\n",
                                          filename);

      ret = 1;
      return;
    }

    if (buff.size() != b.Data.size()) {
      WithColor::error() << llvm::formatv(
          "\"{0}\" has a different size now ({1} != {2}).\n",
          filename, buff.size(), b.Data.size());

      ret = 1;
      return;
    }

    int cmp = memcmp(&buff[0], &b.Data[0], b.Data.size());
    if (cmp != 0) {
      WithColor::error() << llvm::formatv("\"{0}\" has changed ({1})\n",
                                          filename, cmp);

      ret = 1;
      return;
    }
  });

  return ret;
}

}
