#undef ___SYSCALL0
#undef ___SYSCALL1
#undef ___SYSCALL2
#undef ___SYSCALL3
#undef ___SYSCALL4
#undef ___SYSCALL5
#undef ___SYSCALL6

#ifdef ___SYSCALL
#undef ___SYSCALL
#endif

#ifdef ___SYSCALL_PARAM
#undef ___SYSCALL_PARAM
#endif

#ifdef ___DFSAN_SYSEXITS
#undef ___DFSAN_SYSEXITS
#endif
