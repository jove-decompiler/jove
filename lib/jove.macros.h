#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define _IOV_ENTRY(var) {.iov_base = &var, .iov_len = sizeof(var)}

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

#define _CTOR   __attribute__((constructor(0)))
#define _INL    __attribute__((always_inline))
#define _NAKED  __attribute__((naked))
#define _NOINL  __attribute__((noinline))
#define _NORET  __attribute__((noreturn))
#define _UNUSED __attribute__((unused))
#define _HIDDEN __attribute__((visibility("hidden")))

#ifdef __i386__
#define _REGPARM __attribute__((regparm(3)))
#endif

#define _UNREACHABLE(...)                                                      \
  do {                                                                         \
    char line_str[65];                                                         \
    _uint_to_string(__LINE__, line_str, 10);                                   \
                                                                               \
    char buff[256];                                                            \
    buff[0] = '\0';                                                            \
                                                                               \
    _strcat(buff, "JOVE UNREACHABLE: " __VA_ARGS__);                           \
    _strcat(buff, " (");                                                       \
    _strcat(buff, __FILE__);                                                   \
    _strcat(buff, ":");                                                        \
    _strcat(buff, line_str);                                                   \
    _strcat(buff, ")\n");                                                      \
    _jove_sys_write(2 /* stderr */, buff, _strlen(buff));                      \
                                                                               \
    _jove_sys_exit_group(1);                                                   \
                                                                               \
    __builtin_unreachable();                                                   \
  } while (false)
