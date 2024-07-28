#include "tool.h"
#include "B.h"

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>

namespace obj = llvm::object;
namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class Addr2Off : public JVTool<ToolKind::CopyOnWrite> {
  struct Cmdline {
    cl::opt<std::string> Addr;
    cl::opt<std::string> Binary;
    cl::alias BinaryAlias;

    Cmdline(llvm::cl::OptionCategory &JoveCategory)
        : Addr(cl::Positional, cl::Required, cl::desc("Virtual address"),
               cl::value_desc("hexadecimal number"), cl::cat(JoveCategory)),

          Binary("binary", cl::desc("Binary of function"), cl::Required,
                 cl::cat(JoveCategory)),

          BinaryAlias("b", cl::desc("Alias for --binary."),
                      cl::aliasopt(Binary), cl::cat(JoveCategory)) {}
  } opts;

  binary_index_t BinaryIndex = invalid_binary_index;

public:
  Addr2Off() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("addr2off", Addr2Off);

int Addr2Off::Run(void) {
  //
  // find the binary of interest
  //
  BinaryIndex = invalid_binary_index;

  for (binary_index_t BIdx = 0; BIdx < jv.Binaries.size(); ++BIdx) {
    if (!strstr(jv.Binaries.at(BIdx).Name.c_str(), opts.Binary.c_str()))
      continue;

    BinaryIndex = BIdx;
    break;
  }

  if (BinaryIndex == invalid_binary_index) {
    WithColor::error() << llvm::formatv("failed to find binary \"{0}\"\n",
                                        opts.Binary);
    return 1;
  }

  binary_t &b = jv.Binaries.at(BinaryIndex);
  auto Bin = B::Create(b.data());
  uint64_t Addr = strtoull(opts.Addr.c_str(), nullptr, 0x10);

  llvm::outs() << llvm::formatv("{0:x}\n", B::offset_of_va(*Bin, Addr));
  return 0;
}

}

