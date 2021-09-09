/* __thread */ uint64_t *__jove_trace       = NULL;
/* __thread */ uint64_t *__jove_trace_begin = NULL;

/* __thread */ uint64_t *__jove_callstack       = NULL;
/* __thread */ uint64_t *__jove_callstack_begin = NULL;

uintptr_t *__jove_function_tables[_JOVE_MAX_BINARIES] = {
    [0 ... _JOVE_MAX_BINARIES - 1] = NULL
};

struct shadow_t __df32_shadow_mem[65536];

void (*__jove_dfsan_flush)(void) = NULL; /* XXX */
