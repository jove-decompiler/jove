#if !defined(JOVE_TYPES_H) || !defined(JOVE_MACROS_H)
#error
#endif

static struct jove_opts_t *pOpts;

#define _UNREACHABLE(...) _UNREACHABLE_X(2, pOpts->OnCrash, __VA_ARGS__)
