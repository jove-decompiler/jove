#include <config-target.h>
#include "qemu/osdep.h"
#include "cpu.h"

const uint8_t* code;
unsigned long code_len;
target_ulong code_pc;

static const uint8_t oobb[16] = {
#if defined(TARGET_AARCH64)
  0xc0, 0x03, 0x5f, 0xd6, /* ret */
  0xc0, 0x03, 0x5f, 0xd6, /* ret */
  0xc0, 0x03, 0x5f, 0xd6, /* ret */
  0xc0, 0x03, 0x5f, 0xd6, /* ret */
#elif defined(TARGET_ARM)
  0x47, 0x70,             /* bx lr */
  0x47, 0x70,             /* bx lr */
  0x47, 0x70,             /* bx lr */
  0x47, 0x70,             /* bx lr */
  0x47, 0x70,             /* bx lr */
  0x47, 0x70,             /* bx lr */
  0x47, 0x70,             /* bx lr */
  0x47, 0x70,             /* bx lr */
#elif defined(TARGET_X86_64)
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
  0xc3,                   /* retq */
#elif defined(TARGET_I386)
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
  0xc3,                   /* retl */
#elif defined(TARGET_MIPS)
  0x08, 0x00, 0xe0, 0x03, /* jr $ra */
  0x00, 0x00, 0x00, 0x00, /* nop */
  0x08, 0x00, 0xe0, 0x03, /* jr $ra */
  0x00, 0x00, 0x00, 0x00, /* nop */
#endif
};

#define MEMSUFFIX _data
#define DATA_SIZE 1
#include "translate_ldst_template.h"

#define DATA_SIZE 2
#include "translate_ldst_template.h"

#define DATA_SIZE 4
#include "translate_ldst_template.h"

#define DATA_SIZE 8
#include "translate_ldst_template.h"
#undef MEMSUFFIX

#define MEMSUFFIX _code
#define CODE_ACCESS
#define DATA_SIZE 1
#include "translate_ldst_template.h"

#define DATA_SIZE 2
#include "translate_ldst_template.h"

#define DATA_SIZE 4
#include "translate_ldst_template.h"

#define DATA_SIZE 8
#include "translate_ldst_template.h"
#undef MEMSUFFIX
#undef CODE_ACCESS
