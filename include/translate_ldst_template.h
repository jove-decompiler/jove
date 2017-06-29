#if DATA_SIZE == 8
#define SUFFIX q
#define USUFFIX q
#define DATA_TYPE uint64_t
#elif DATA_SIZE == 4
#define SUFFIX l
#define USUFFIX l
#define DATA_TYPE uint32_t
#elif DATA_SIZE == 2
#define SUFFIX w
#define USUFFIX uw
#define DATA_TYPE uint16_t
#define DATA_STYPE int16_t
#elif DATA_SIZE == 1
#define SUFFIX b
#define USUFFIX ub
#define DATA_TYPE uint8_t
#define DATA_STYPE int8_t
#else
#error unsupported data size
#endif

#if DATA_SIZE == 8
#define RES_TYPE uint64_t
#else
#define RES_TYPE uint32_t
#endif

//
// declarations
//

RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr);

RES_TYPE
glue(glue(glue(cpu_ld, USUFFIX), MEMSUFFIX),
     _ra)(CPUArchState *env, target_ulong ptr, uintptr_t retaddr);

#if DATA_SIZE <= 2
int glue(glue(cpu_lds, SUFFIX), MEMSUFFIX)(CPUArchState *env,
                                           target_ulong ptr);

int glue(glue(glue(cpu_lds, SUFFIX), MEMSUFFIX),
         _ra)(CPUArchState *env, target_ulong ptr, uintptr_t retaddr);
#endif

#ifndef CODE_ACCESS
void glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr,
                                           RES_TYPE v);

void glue(glue(glue(cpu_st, SUFFIX), MEMSUFFIX),
          _ra)(CPUArchState *env, target_ulong ptr, RES_TYPE v,
               uintptr_t retaddr);
#endif

//
// definitions
//

RES_TYPE
glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr) {
  unsigned off = ptr - code_pc;
  if (unlikely(off > code_len)) {
    unsigned over = (off - code_len) % 8;
    return glue(glue(ld, USUFFIX), _p)(oobb + over);
  }

  return glue(glue(ld, USUFFIX), _p)(code + off);
}

RES_TYPE
glue(glue(glue(cpu_ld, USUFFIX), MEMSUFFIX),
     _ra)(CPUArchState *env, target_ulong ptr, uintptr_t retaddr) {
  return glue(glue(cpu_ld, USUFFIX), MEMSUFFIX)(env, ptr);
}

#if DATA_SIZE <= 2
int glue(glue(cpu_lds, SUFFIX), MEMSUFFIX)(CPUArchState *env,
                                           target_ulong ptr) {
  unsigned off = ptr - code_pc;
  if (unlikely(off > code_len)) {
    unsigned over = (off - code_len) % 8;
    return glue(glue(ld, USUFFIX), _p)(oobb + over);
  }

  return glue(glue(lds, SUFFIX), _p)(code + off);
}

int glue(glue(glue(cpu_lds, SUFFIX), MEMSUFFIX),
         _ra)(CPUArchState *env, target_ulong ptr, uintptr_t retaddr) {
  return glue(glue(cpu_lds, SUFFIX), MEMSUFFIX)(env, ptr);
}
#endif

#ifndef CODE_ACCESS
void glue(glue(cpu_st, SUFFIX), MEMSUFFIX)(CPUArchState *env, target_ulong ptr,
                                           RES_TYPE v) {}

void glue(glue(glue(cpu_st, SUFFIX), MEMSUFFIX),
          _ra)(CPUArchState *env, target_ulong ptr, RES_TYPE v,
               uintptr_t retaddr) {}
#endif

#undef RES_TYPE
#undef DATA_TYPE
#undef DATA_STYPE
#undef SUFFIX
#undef USUFFIX
#undef DATA_SIZE
