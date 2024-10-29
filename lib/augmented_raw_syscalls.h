#pragma once
#include <stdint.h>

//
// magic
//
#ifdef MAGIC
#error
#endif

#if 0
/* lean and mean */
#define MAGIC(idx)
#else
/* four characters */
#define MAGIC(idx) char magic##idx[4]
#endif

//
// Note: MAXLEN_SHIFT=15u yields -E2BIG.
//
#define MAXLEN_SHIFT 14u
#define MAXLEN     (1u << MAXLEN_SHIFT)

#define HALFMAXLEN (1u << (MAXLEN_SHIFT - 1u))
#define HALFMAXMASK (HALFMAXLEN - 1u)

#define TWOTIMESMAXLEN (MAXLEN << 1u)
#define TWOTIMESMAXMASK (TWOTIMESMAXLEN - 1u)

#ifdef __cplusplus
namespace jove {
#endif

#define DECLARE_AUGMENTED_ARGS_PAYLOAD(bits)                                   \
  struct __attribute__((__packed__))                                           \
  augmented_syscall_payload##bits##_header {                                   \
    MAGIC(1);                      /* 'J' 'O' 'V' 'E' */                       \
    unsigned is32 : 1;                                                         \
    unsigned syscall_nr : 15;                                                  \
    uint32_t str_len;                                                          \
    uint##bits##_t ret;                                                        \
    uint##bits##_t args[6];                                                    \
    MAGIC(2);                      /* 'E' 'V' 'O' 'J' */                       \
  };                                                                           \
  struct __attribute__((__packed__)) augmented_syscall_payload##bits {         \
    struct augmented_syscall_payload##bits##_header hdr;                       \
    char str[MAXLEN];                                                          \
                                                                               \
    uint8_t __pad[TWOTIMESMAXLEN -                                             \
                  sizeof(struct augmented_syscall_payload##bits##_header) -    \
                  MAXLEN];                                                     \
  };

DECLARE_AUGMENTED_ARGS_PAYLOAD(32)
DECLARE_AUGMENTED_ARGS_PAYLOAD(64)

static_assert(sizeof(struct augmented_syscall_payload32) == TWOTIMESMAXLEN);
static_assert(sizeof(struct augmented_syscall_payload64) == TWOTIMESMAXLEN);

#ifdef __cplusplus
} /* namespace jove */
#endif
