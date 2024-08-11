#include "common.h"

#include <jove/jove.h> /* for TARGET_NUM_REG_ARGS */

#include "jove.constants.h"
#include "jove.macros.h"
#include "jove.options.h"

#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/arithmetic/inc.hpp>
#include <boost/preprocessor/cat.hpp>

#ifndef JOVE_COFF
#define JOVE_CLUNK
#endif

extern struct jove_opts_t __jove_opts;

extern void _jove_rt_track_alloc(uintptr_t beg, size_t len, const char *desc);
extern void _jove_rt_track_free(uintptr_t beg, size_t len);
