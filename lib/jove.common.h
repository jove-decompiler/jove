#include <jove/jove.h> /* for TARGET_NUM_REG_ARGS */

#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/arithmetic/inc.hpp>
#include <boost/preprocessor/cat.hpp>

#include "jove.constants.h"
#include "jove.macros.h"
#include "jove.types.h"

#ifndef JOVE_COFF
#define JOVE_CLUNK
#endif

extern struct jove_opts_t __jove_opts;
