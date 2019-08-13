#if defined(___SYSCALL0) && \
    defined(___SYSCALL1) && \
    defined(___SYSCALL2) && \
    defined(___SYSCALL3) && \
    defined(___SYSCALL4) && \
    defined(___SYSCALL5) && \
    defined(___SYSCALL6)

#ifdef ___SYSCALL
#error
#endif

#elif defined(___SYSCALL)

#if defined(___SYSCALL0) || \
    defined(___SYSCALL1) || \
    defined(___SYSCALL2) || \
    defined(___SYSCALL3) || \
    defined(___SYSCALL4) || \
    defined(___SYSCALL5) || \
    defined(___SYSCALL6)
#error
#endif

#define ___SYSCALL0(nr, nm)                                                    \
  ___SYSCALL(nr, nm)
#define ___SYSCALL1(nr, nm, t0, s0)                                            \
  ___SYSCALL(nr, nm)
#define ___SYSCALL2(nr, nm, t0, s0, t1, s1)                                    \
  ___SYSCALL(nr, nm)
#define ___SYSCALL3(nr, nm, t0, s0, t1, s1, t2, s2)                            \
  ___SYSCALL(nr, nm)
#define ___SYSCALL4(nr, nm, t0, s0, t1, s1, t2, s2, t3, s3)                    \
  ___SYSCALL(nr, nm)
#define ___SYSCALL5(nr, nm, t0, s0, t1, s1, t2, s2, t3, s3, t4, s4)            \
  ___SYSCALL(nr, nm)
#define ___SYSCALL6(nr, nm, t0, s0, t1, s1, t2, s2, t3, s3, t4, s4, t5, s5)    \
  ___SYSCALL(nr, nm)

#elif defined(___SYSCALL_PARAM)

#if defined(___SYSCALL0) || \
    defined(___SYSCALL1) || \
    defined(___SYSCALL2) || \
    defined(___SYSCALL3) || \
    defined(___SYSCALL4) || \
    defined(___SYSCALL5) || \
    defined(___SYSCALL6) || \
    defined(___SYSCALL)
#error
#endif

#define ___SYSCALL0(nr, nm)
#define ___SYSCALL1(nr, nm, t0, s0)                                            \
  ___SYSCALL_PARAM(nr, nm, 0, t0, s0)
#define ___SYSCALL2(nr, nm, t0, s0, t1, s1)                                    \
  ___SYSCALL_PARAM(nr, nm, 0, t0, s0)                                          \
  ___SYSCALL_PARAM(nr, nm, 1, t1, s1)
#define ___SYSCALL3(nr, nm, t0, s0, t1, s1, t2, s2)                            \
  ___SYSCALL_PARAM(nr, nm, 0, t0, s0)                                          \
  ___SYSCALL_PARAM(nr, nm, 1, t1, s1)                                          \
  ___SYSCALL_PARAM(nr, nm, 2, t2, s2)
#define ___SYSCALL4(nr, nm, t0, s0, t1, s1, t2, s2, t3, s3)                    \
  ___SYSCALL_PARAM(nr, nm, 0, t0, s0)                                          \
  ___SYSCALL_PARAM(nr, nm, 1, t1, s1)                                          \
  ___SYSCALL_PARAM(nr, nm, 2, t2, s2)                                          \
  ___SYSCALL_PARAM(nr, nm, 3, t3, s3)
#define ___SYSCALL5(nr, nm, t0, s0, t1, s1, t2, s2, t3, s3, t4, s4)            \
  ___SYSCALL_PARAM(nr, nm, 0, t0, s0)                                          \
  ___SYSCALL_PARAM(nr, nm, 1, t1, s1)                                          \
  ___SYSCALL_PARAM(nr, nm, 2, t2, s2)                                          \
  ___SYSCALL_PARAM(nr, nm, 3, t3, s3)                                          \
  ___SYSCALL_PARAM(nr, nm, 4, t4, s4)
#define ___SYSCALL6(nr, nm, t0, s0, t1, s1, t2, s2, t3, s3, t4, s4, t5, s5)    \
  ___SYSCALL_PARAM(nr, nm, 0, t0, s0)                                          \
  ___SYSCALL_PARAM(nr, nm, 1, t1, s1)                                          \
  ___SYSCALL_PARAM(nr, nm, 2, t2, s2)                                          \
  ___SYSCALL_PARAM(nr, nm, 3, t3, s3)                                          \
  ___SYSCALL_PARAM(nr, nm, 4, t4, s4)                                          \
  ___SYSCALL_PARAM(nr, nm, 5, t5, s5)

#else
#error
#endif
