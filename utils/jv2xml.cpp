#include <boost/filesystem.hpp>
#include <tuple>
#include <numeric>
#include <memory>
#include <sstream>
#include <fstream>
#include <cinttypes>
#include <array>
#include <sstream>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/WithColor.h>

#include "jove/jove.h"
#include <boost/dynamic_bitset.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/archive/xml_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace opts {
static cl::OptionCategory JoveCategory("Specific Options");

static cl::opt<std::string> jv(cl::Positional, cl::desc("decompilation.jv"),
                               cl::Required, cl::value_desc("filename"),
                               cl::cat(JoveCategory));

} // namespace opts

namespace jove {

static int jv2xml(void);

}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  cl::HideUnrelatedOptions({&opts::JoveCategory, &llvm::ColorCategory});
  cl::ParseCommandLineOptions(argc, argv, "Jove jv2xml\n");

  if (!fs::exists(opts::jv)) {
    WithColor::error() << "decompilation does not exist\n";
    return 1;
  }

  return jove::jv2xml();
}

namespace jove {

static decompilation_t Decompilation;

int jv2xml(void) {
  bool git = fs::is_directory(opts::jv);

  //
  // parse the decompilation file
  //
  {
    std::ifstream ifs(git ? (opts::jv + "/decompilation.jv") : opts::jv);

    boost::archive::binary_iarchive ia(ifs);
    ia >> Decompilation;
  }

  std::ostringstream oss;

  {
    boost::archive::xml_oarchive oa(oss);

    oa << BOOST_SERIALIZATION_NVP(Decompilation);
  }

  llvm::outs() << oss.str();
  return 0;
}

}
