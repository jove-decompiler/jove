#include "tcgcommon.hpp"

#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/ScopedPrinter.h>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/stringize.hpp>

static void print_tcgtemp(llvm::ScopedPrinter &, const TCGTemp &);

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);

  jove::tiny_code_generator_t tcg;

  llvm::ScopedPrinter Writer(llvm::outs());
  llvm::ListScope _(Writer);

  for (int i = 0; i < tcg._ctx.nb_globals; i++)
    print_tcgtemp(Writer, tcg._ctx.temps[i]);

  return 0;
}

static const char *cstr_of_tcg_temp_val(TCGTempVal x) {
#define ___CASE(text)                                                          \
  if (x == BOOST_PP_CAT(TEMP_VAL_, text))                                      \
    return BOOST_PP_STRINGIZE(text);

  ___CASE(DEAD);
  ___CASE(REG);
  ___CASE(MEM);
  ___CASE(CONST);

#undef ___CASE

  abort();
}

static const char *cstr_of_tcg_type(TCGType x) {
#define ___CASE(text)                                                          \
  if (x == BOOST_PP_CAT(TCG_TYPE_, text))                                      \
    return BOOST_PP_STRINGIZE(text);

  ___CASE(I32);
  ___CASE(I64);
  ___CASE(V64);
  ___CASE(V128);
  ___CASE(V256);

#undef ___CASE

  abort();
}

void print_tcgtemp(llvm::ScopedPrinter &Writer, const TCGTemp &ts) {
  llvm::DictScope _(Writer);

#define ___FIELD(NumOrStr, field)                                              \
  Writer.print##NumOrStr(BOOST_PP_STRINGIZE(field), ts.field)

#define __FIELD_(NumOrStr, field, transform)                                   \
  Writer.print##NumOrStr(BOOST_PP_STRINGIZE(field), transform(ts.field))

  ___FIELD(Number, reg);
  __FIELD_(String, val_type, cstr_of_tcg_temp_val);
  __FIELD_(String, base_type, cstr_of_tcg_type);
  __FIELD_(String, type, cstr_of_tcg_type);
  ___FIELD(Number, fixed_reg);
  ___FIELD(Number, indirect_reg);
  ___FIELD(Number, indirect_base);
  ___FIELD(Number, mem_coherent);
  ___FIELD(Number, mem_allocated);
  ___FIELD(Number, temp_global);
  ___FIELD(Number, temp_local);
  ___FIELD(Number, temp_allocated);
  ___FIELD(Number, val);

  if (ts.mem_base) {
    Writer.printString("mem_base");
    print_tcgtemp(Writer, *ts.mem_base);
  }

  ___FIELD(Number, mem_offset);
  ___FIELD(String, name);
  ___FIELD(Number, state);
  //___FIELD(Number, state_ptr);

#undef ___FIELD
#undef __FIELD_

}
