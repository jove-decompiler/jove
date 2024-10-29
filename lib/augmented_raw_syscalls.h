#pragma once
#include <stdint.h>

#define MAXLEN_SHIFT 17u
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
    unsigned is32 : 1;                                                         \
    unsigned syscall_nr : 15;                                                  \
    uint32_t str_len;                                                          \
    int##bits##_t ret;                                                         \
    uint##bits##_t args[6];                                                    \
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

#ifdef __cplusplus
} /* namespace jove */
#endif
