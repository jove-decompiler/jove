#pragma once

#undef _NSIG       /* XXX */
#undef _NSIG_BPW   /* XXX */
#undef _NSIG_WORDS /* XXX */

#if defined(__mips64)

# define _NSIG		128
# define _NSIG_BPW	64
# define __ARCH_HAS_IRIX_SIGACTION

#elif defined(__mips__)

# define _NSIG		128
# define _NSIG_BPW	32
# define __ARCH_HAS_IRIX_SIGACTION

#elif defined(__x86_64__)

# define _NSIG		64
# define _NSIG_BPW	64
# define __ARCH_HAS_SA_RESTORER

#elif defined(__i386__)

# define _NSIG		64
# define _NSIG_BPW	32
# define __ARCH_HAS_SA_RESTORER

#elif defined(__aarch64__)

#define _NSIG		64
#define _NSIG_BPW	64
#define __ARCH_HAS_SA_RESTORER

#else
#error
#endif

#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} kernel_sigset_t;

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t(void);

typedef __restorefn_t *__sigrestore_t;

struct kernel_sigaction {
#ifndef __ARCH_HAS_IRIX_SIGACTION
	__sighandler_t	k_sa_handler;
	unsigned long	k_sa_flags;
#else
	unsigned int	k_sa_flags;
	__sighandler_t	k_sa_handler;
#endif
#ifdef __ARCH_HAS_SA_RESTORER
	__sigrestore_t k_sa_restorer;
#endif
	kernel_sigset_t	k_sa_mask;	/* mask last for extensibility */
};
