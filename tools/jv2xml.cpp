#include "tool.h"

#include <boost/archive/xml_oarchive.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/graph/adj_list_serialize.hpp>
#include <boost/serialization/bitset.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/vector.hpp>

#include <llvm/Support/DataTypes.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <fstream>
#include <memory>
#include <sstream>

namespace fs = boost::filesystem;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class jv2xmlTool : public Tool {
  struct Cmdline {
    cl::opt<std::string> jv;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : jv(cl::Positional, cl::desc("jv.jv"), cl::Required,
             cl::value_desc("filename"), cl::cat(JoveCategory)) {}
  } opts;

public:
  jv2xmlTool() : opts(JoveCategory) {}

  int Run(void);
};

JOVE_REGISTER_TOOL("jv2xml", jv2xmlTool);

int jv2xmlTool::Run(void) {
  if (!fs::exists(opts.jv)) {
    WithColor::error() << "jv does not exist\n";
    return 1;
  }

  jv_t jv;
  ReadDecompilationFromFile(opts.jv, jv);

  //
  // destructively modify data so the output is printable
  //
  for (auto &binary : jv.Binaries) {
    for (unsigned i = 0; i < binary.Data.size(); ++i) {
      binary.Data[i] = ' ';
    }
  }

  std::string res;
  {
    std::ostringstream oss;

    {
      boost::archive::xml_oarchive oa(oss);

      oa << BOOST_SERIALIZATION_NVP(jv);
    }

    res = oss.str();
  }

  llvm::outs() << res;

  return 0;
}

}
