#pragma once
#include "jove/jove.h"
#include "B.h"

#include <memory>
#include <utility>

namespace jove {

struct tcg_helpers_t;

struct g2h_exception {
  uint64_t pc;

  g2h_exception(uint64_t pc) : pc(pc) {}
};

struct illegal_op_exception {
  uint64_t pc;

  illegal_op_exception(uint64_t pc) : pc(pc) {}
};

struct tiny_code_generator_private_t;

struct tiny_code_generator_base_t {
  typedef std::function<const void *(uint64_t)> g2h_t;

  struct context_t {
    terminator_info_t ti{};
    uint64_t end_pc = UINT64_MAX;
  };

  std::pair<unsigned, terminator_info_t> do_translate(context_t &,
                                                      g2h_t g2h,
                                                      uint64_t pc,
                                                      uint64_t pc_end);

  tiny_code_generator_base_t();
  tiny_code_generator_base_t(const tiny_code_generator_base_t &) = delete;
  tiny_code_generator_base_t(tiny_code_generator_base_t &&) {}

  void dump_ops(FILE *);

  int tcg_index_of_named_global(const char *name);
  const char *tcg_name_of_global(unsigned glb);

  const void *const *special_helpers(void);

  void for_each_operation(std::function<void(void *)> proc);
  std::pair<tcg_global_set_t, tcg_global_set_t>
  analyze_operation(tcg_helpers_t &, void *);
};

template <typename extra_t = std::monostate>
struct tiny_code_generator_t : public tiny_code_generator_base_t {
  const void *g2h_(B::cached::type<extra_t> *pcb, uint64_t Addr) {
    assert(pcb);
    return B::cached::toMappedAddr(*pcb, Addr);
  }

  std::pair<unsigned, terminator_info_t>
  translate(B::cached::type<extra_t> &cb,
            uint64_t pc,
            uint64_t pc_end = 0) {
    tiny_code_generator_base_t::context_t ctx;
    g2h_t g2h = std::bind(&tiny_code_generator_t::g2h_, this, &cb,
                          std::placeholders::_1);

    return this->do_translate(ctx, g2h, pc, pc_end);
  }

  tiny_code_generator_t() {}

  template <typename other_extra_t>
  tiny_code_generator_t(const tiny_code_generator_t<other_extra_t> &) = delete;

  template <typename other_extra_t>
  tiny_code_generator_t(tiny_code_generator_t<other_extra_t> &&other) {}
};

}
