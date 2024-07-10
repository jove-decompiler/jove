#if !defined(JOVE_TYPES_H) || !defined(JOVE_MACROS_H)
#error
#endif

extern struct jove_opts_t __jove_opts;

#define _UNREACHABLE(...) _UNREACHABLE_X(2, __jove_opts.OnCrash, __VA_ARGS__)
#define _DUMP(...) _DUMP_X(2, __VA_ARGS__)
