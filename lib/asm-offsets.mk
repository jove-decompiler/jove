# ASM offsets (from linux/scripts/Makefile.lib)
# ---------------------------------------------------------------------------

# Default sed regexp - multiline due to syntax constraints
#
# Use [:space:] because LLVM's integrated assembler inserts <tab> around
# the .ascii directive whereas GCC keeps the <space> as-is.
define sed-offsets
	's:^[[:space:]]*\.ascii[[:space:]]*"\(.*\)".*:\1:; \
	/^->/{s:->#\(.*\):/* \1 */:; \
	s:^->\([^ ]*\) [\$$#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:; \
	s:->::; p;}'
endef
