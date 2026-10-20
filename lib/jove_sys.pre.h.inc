#ifndef JOVE_SYSCALL_NO_PARAM_TYPES
#define __KERNEL__
#include "linux.copy.h"
#undef __KERNEL__
#endif

#include <boost/preprocessor/facilities/is_empty.hpp>
#include <boost/preprocessor/control/iif.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/arithmetic/dec.hpp>
#include <boost/preprocessor/arithmetic/inc.hpp>

#ifndef JOVE_SYS_H
#error
#endif

#ifndef JOVE_SYS_ATTR
#error
#endif

#ifdef JOVE_SYSCALL_NO_PARAM_TYPES
#define JOVE_SYSCALL_PARAM_TYPES 0
#else
#define JOVE_SYSCALL_PARAM_TYPES 1
#endif

#define __EXPAND(X) X
#define EXPANDXV(X) EXPANDV_(X)
#define EXPANDV_(...) __VA_ARGS__

#define __PARAM_TY(n, i, data) BOOST_PP_COMMA_IF(i) typename BOOST_PP_CAT(T,EXPANDV_(BOOST_PP_INC(i)))

#if defined(JOVE_SYSCALL_NO_PARAM_TYPES) && defined(__cplusplus)
#define __HEADER(n) template < BOOST_PP_REPEAT(n, __PARAM_TY, void) >
#else
#define __HEADER(n)
#endif

#ifdef __cplusplus
#define __PARAM(i, t) BOOST_PP_IIF(JOVE_SYSCALL_PARAM_TYPES,t,BOOST_PP_CAT(T,EXPANDV_(i)))
#else
#define __PARAM(i, t) BOOST_PP_IIF(JOVE_SYSCALL_PARAM_TYPES,t,unsigned long)
#endif

// XXX
#undef __user
#define __user
