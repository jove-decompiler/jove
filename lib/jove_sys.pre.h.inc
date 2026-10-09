#include <boost/vmd/is_empty.hpp>
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
#define JOVE_SYSCALL_ARG_SUFFIX ___u
#else
#define JOVE_SYSCALL_ARG_SUFFIX
#endif

#if 0
#define __TYPEDEF(n, i, data) typedef uint64_t BOOST_PP_CAT(BOOST_PP_CAT(t,BOOST_PP_INC(i)),___u)
BOOST_PP_REPEAT(6, __REG_ARG, void)
#else
typedef uint64_t _t1___u;
typedef uint64_t _t2___u;
typedef uint64_t _t3___u;
typedef uint64_t _t4___u;
typedef uint64_t _t5___u;
typedef uint64_t _t6___u;
#endif

//#define t1 BOOST_PP_CAT(_t1,JOVE_SYSCALL_ARG_SUFFIX)
//#define t2 BOOST_PP_CAT(_t2,JOVE_SYSCALL_ARG_SUFFIX)
//#define t3 BOOST_PP_CAT(_t3,JOVE_SYSCALL_ARG_SUFFIX)
//#define t4 BOOST_PP_CAT(_t4,JOVE_SYSCALL_ARG_SUFFIX)
//#define t5 BOOST_PP_CAT(_t5,JOVE_SYSCALL_ARG_SUFFIX)
//#define t6 BOOST_PP_CAT(_t6,JOVE_SYSCALL_ARG_SUFFIX)

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
#define __PARAM(i, t) BOOST_PP_IIF(BOOST_VMD_IS_EMPTY(JOVE_SYSCALL_NO_PARAM_TYPES),BOOST_PP_CAT(T,EXPANDV_(i)),t)
#else
#define __PARAM(i, t) BOOST_PP_IIF(BOOST_VMD_IS_EMPTY(JOVE_SYSCALL_NO_PARAM_TYPES),uint64_t,t)
#endif
