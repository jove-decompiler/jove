#include "tool.h"
#include "score.h"

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include <llvm/Support/WithColor.h>
#include <llvm/Support/FormatVariadic.h>

namespace cl = llvm::cl;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

struct NumbersTool : public Tool {
  int Run(void) override;
};

JOVE_REGISTER_TOOL("numbers", NumbersTool);

typedef boost::format fmt;

#if 0
//typedef unsigned _BitInt(tcg_num_globals) new_tcg_global_set_t;
typedef tcg_global_set_t new_tcg_global_set_t;

struct __attribute__((packed)) my_basic_block_properties_t {
  boost::interprocess::offset_ptr<ip_dynamic_target_set> pDynTargets;
  uint64_t Addr;
  uint32_t Size;

  uint16_t TermOff;
  function_index_t Term_call_Target:24;

  TERMINATOR TermType : 4;
  unsigned Term_indirect_jump_IsLj : 1;
  unsigned Term_indirect_call_Returns : 1;
  unsigned Term_indirect_call_ReturnsOff : 4;
  unsigned Term_return_Returns : 1;
  unsigned Term_call_Returns : 1;
  unsigned Term_call_ReturnsOff : 4;
  unsigned DynTargetsComplete:1; // XXX
  unsigned Sj:1;
  unsigned Analysis_Stale:1;

  new_tcg_global_set_t Analysis_live_def;
  new_tcg_global_set_t Analysis_live_use;
  new_tcg_global_set_t Analysis_reach_def;
};

struct __attribute__((packed)) my_function_t {
  basic_block_index_t Entry;
  new_tcg_global_set_t Analysis_args;
  new_tcg_global_set_t Analysis_rets;
  unsigned Analysis_Stale : 1;
  unsigned IsABI : 1;
  unsigned IsSignalHandler : 1;
  unsigned Returns : 1;
};

#endif

int NumbersTool::Run(void) {
#define PRINT_STRUCT_SIZE(NM)                                                  \
  do {                                                                         \
    HumanOut() << (fmt("%-48s= %u") % ("sizeof(" #NM ")") % sizeof(NM)).str()  \
               << '\n';                                                        \
  } while (0)

  PRINT_STRUCT_SIZE(binary_t);
  PRINT_STRUCT_SIZE(basic_block_properties_t);
  PRINT_STRUCT_SIZE(function_t);

#if 0
  PRINT_STRUCT_SIZE(my_basic_block_properties_t);
  PRINT_STRUCT_SIZE(my_function_t);
#endif

#undef PRINT_STRUCT_SIZE

  return 0;
}

}
