#define CONFIG_MIPS_L1_CACHE_SHIFT 6

#define CONFIG_64BIT 1

#define __always_inline                 inline __attribute__((__always_inline__))

#define __attribute_const__             __attribute__((__const__))

# define __compiletime_error(msg)       __attribute__((__error__(msg)))

#define __gnu_inline                    __attribute__((__gnu_inline__))

#define __noreturn                      __attribute__((__noreturn__))

#define __maybe_unused                  __attribute__((__unused__))

#define __used                          __attribute__((__used__))

#define MIPS_ISA_LEVEL "mips64r2"

#define notrace			__attribute__((__no_instrument_function__))

#define inline inline __gnu_inline __inline_maybe_unused notrace

#define __inline_maybe_unused __maybe_unused

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0

#define __unqual_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(char)0,				\
			 __scalar_type_to_expr_cases(char),		\
			 __scalar_type_to_expr_cases(short),		\
			 __scalar_type_to_expr_cases(int),		\
			 __scalar_type_to_expr_cases(long),		\
			 __scalar_type_to_expr_cases(long long),	\
			 default: (x)))

#define __native_word(t) \
	(sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
	 sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))

# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		/*							\
		 * __noreturn is needed to give the compiler enough	\
		 * information to avoid certain possibly-uninitialized	\
		 * warnings (regardless of the build failing).		\
		 */							\
		__noreturn extern void prefix ## suffix(void)		\
			__compiletime_error(msg);			\
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)

#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")

# define barrier() __asm__ __volatile__("": : :"memory")

#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#define BITS_PER_LONG 64

typedef unsigned char __u8;

typedef unsigned short __u16;

typedef unsigned int __u32;

typedef unsigned long __u64;

typedef __u8  u8;

typedef __u16 u16;

typedef __u32 u32;

#define NULL ((void *)0)

typedef __u64 u64;

#define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)

enum {
	false	= 0,
	true	= 1
};

typedef _Bool			bool;

struct list_head {
	struct list_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

#define compiletime_assert_rwonce_type(t)					\
	compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long),	\
		"Unsupported access size for {READ,WRITE}_ONCE().")

#define __READ_ONCE(x)	(*(const volatile __unqual_scalar_typeof(x) *)&(x))

#define READ_ONCE(x)							\
({									\
	compiletime_assert_rwonce_type(x);				\
	__READ_ONCE(x);							\
})

#define __WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)

#define WRITE_ONCE(x, val)						\
do {									\
	compiletime_assert_rwonce_type(x);				\
	__WRITE_ONCE(x, val);						\
} while (0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int:(-!!(e)); })))

#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)

#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

#define MIPS_ISA_REV __mips_isa_rev

# define __smp_mb()	barrier()

#define __smp_load_acquire(p)						\
({									\
	__unqual_scalar_typeof(*p) ___p1 = READ_ONCE(*p);		\
	compiletime_assert_atomic_type(*p);				\
	__smp_mb();							\
	(typeof(*p))___p1;						\
})

#define smp_load_acquire(p) __smp_load_acquire(p)

#define ___constant_swahw32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x0000ffffUL) << 16) |		\
	(((__u32)(x) & (__u32)0xffff0000UL) >> 16)))

static inline __attribute_const__ __u32 __fswahw32(__u32 val)
{
#ifdef __arch_swahw32
	return __arch_swahw32(val);
#else
	return ___constant_swahw32(val);
#endif
}

#define __swahw32(x)				\
	(__builtin_constant_p((__u32)(x)) ?	\
	___constant_swahw32(x) :		\
	__fswahw32(x))

static inline __u32 __swahw32p(const __u32 *p)
{
#ifdef __arch_swahw32p
	return __arch_swahw32p(p);
#else
	return __swahw32(*p);
#endif
}

#define MIPS_CPU_ISA_M64R1	0x00000040

#define MIPS_CPU_ISA_M64R2	0x00000080

#define MIPS_CPU_ISA_M64R5	0x00000200

#define MIPS_CPU_ISA_M64R6	0x00000800

#define L1_CACHE_SHIFT		CONFIG_MIPS_L1_CACHE_SHIFT

#define L1_CACHE_BYTES		(1 << L1_CACHE_SHIFT)

#define SMP_CACHE_BYTES L1_CACHE_BYTES

struct cache_desc {
	unsigned int waysize;	/* Bytes per way */
	unsigned short sets;	/* Number of lines per set */
	unsigned char ways;	/* Number of ways */
	unsigned char linesz;	/* Size of line in bytes */
	unsigned char waybit;	/* Bits to select in a cache set */
	unsigned char flags;	/* Flags describing cache properties */
};

struct guest_info {
	unsigned long		ases;
	unsigned long		ases_dyn;
	unsigned long long	options;
	unsigned long long	options_dyn;
	int			tlbsize;
	u8			conf;
	u8			kscratch_mask;
};

struct cpuinfo_mips {
	u64			asid_cache;
#ifdef CONFIG_MIPS_ASID_BITS_VARIABLE
	unsigned long		asid_mask;
#endif

	/*
	 * Capability and feature descriptor structure for MIPS CPU
	 */
	unsigned long		ases;
	unsigned long long	options;
	unsigned int		udelay_val;
	unsigned int		processor_id;
	unsigned int		fpu_id;
	unsigned int		fpu_csr31;
	unsigned int		fpu_msk31;
	unsigned int		msa_id;
	unsigned int		cputype;
	int			isa_level;
	int			tlbsize;
	int			tlbsizevtlb;
	int			tlbsizeftlbsets;
	int			tlbsizeftlbways;
	struct cache_desc	icache; /* Primary I-cache */
	struct cache_desc	dcache; /* Primary D or combined I/D cache */
	struct cache_desc	vcache; /* Victim cache, between pcache and scache */
	struct cache_desc	scache; /* Secondary cache */
	struct cache_desc	tcache; /* Tertiary/split secondary cache */
	int			srsets; /* Shadow register sets */
	int			package;/* physical package number */
	unsigned int		globalnumber;
#ifdef CONFIG_64BIT
	int			vmbits; /* Virtual memory size in bits */
#endif
	void			*data;	/* Additional data */
	unsigned int		watch_reg_count;   /* Number that exist */
	unsigned int		watch_reg_use_cnt; /* Usable by ptrace */
#define NUM_WATCH_REGS 4
	u16			watch_reg_masks[NUM_WATCH_REGS];
	unsigned int		kscratch_mask; /* Usable KScratch mask. */
	/*
	 * Cache Coherency attribute for write-combine memory writes.
	 * (shifted by _CACHE_SHIFT)
	 */
	unsigned int		writecombine;
	/*
	 * Simple counter to prevent enabling HTW in nested
	 * htw_start/htw_stop calls
	 */
	unsigned int		htw_seq;

	/* VZ & Guest features */
	struct guest_info	guest;
	unsigned int		gtoffset_mask;
	unsigned int		guestid_mask;
	unsigned int		guestid_cache;

#ifdef CONFIG_CPU_LOONGSON3_CPUCFG_EMULATION
	/* CPUCFG data for this CPU, synthesized at probe time.
	 *
	 * CPUCFG select 0 is PRId, 4 and above are unimplemented for now.
	 * So the only stored values are for CPUCFG selects 1-3 inclusive.
	 */
	u32 loongson3_cpucfg_data[3];
#endif
} __attribute__((aligned(SMP_CACHE_BYTES)));

extern struct cpuinfo_mips cpu_data[];

#define cpu_has_clo_clz		1

#define __isa(isa)			(cpu_data[0].isa_level & (isa))

#define __isa_ge_and_flag(isa, flag)	((MIPS_ISA_REV >= (isa)) && __isa(flag))

#define __isa_range(ge, lt) \
	((MIPS_ISA_REV >= (ge)) && (MIPS_ISA_REV < (lt)))

#define __isa_range_or_flag(ge, lt, flag) \
	(__isa_range(ge, lt) || ((MIPS_ISA_REV < (lt)) && __isa(flag)))

# define cpu_has_mips64r1	(cpu_has_64bits && \
				 __isa_range_or_flag(1, 6, MIPS_CPU_ISA_M64R1))

# define cpu_has_mips64r2	(cpu_has_64bits && \
				 __isa_range_or_flag(2, 6, MIPS_CPU_ISA_M64R2))

# define cpu_has_mips64r5	(cpu_has_64bits && \
				 __isa_range_or_flag(5, 6, MIPS_CPU_ISA_M64R5))

# define cpu_has_mips64r6	__isa_ge_and_flag(6, MIPS_CPU_ISA_M64R6)

#define cpu_has_mips64	(cpu_has_mips64r1 | cpu_has_mips64r2 | \
			 cpu_has_mips64r5 | cpu_has_mips64r6)

# define cpu_has_64bits			1

static __always_inline unsigned long __fls(unsigned long word)
{
	int num;

	if (BITS_PER_LONG == 32 && !__builtin_constant_p(word) &&
	    __builtin_constant_p(cpu_has_clo_clz) && cpu_has_clo_clz) {
		__asm__(
		"	.set	push					\n"
		"	.set	"MIPS_ISA_LEVEL"			\n"
		"	clz	%0, %1					\n"
		"	.set	pop					\n"
		: "=r" (num)
		: "r" (word));

		return 31 - num;
	}

	if (BITS_PER_LONG == 64 && !__builtin_constant_p(word) &&
	    __builtin_constant_p(cpu_has_mips64) && cpu_has_mips64) {
		__asm__(
		"	.set	push					\n"
		"	.set	"MIPS_ISA_LEVEL"			\n"
		"	dclz	%0, %1					\n"
		"	.set	pop					\n"
		: "=r" (num)
		: "r" (word));

		return 63 - num;
	}

	num = BITS_PER_LONG - 1;

#if BITS_PER_LONG == 64
	if (!(word & (~0ul << 32))) {
		num -= 32;
		word <<= 32;
	}
#endif
	if (!(word & (~0ul << (BITS_PER_LONG-16)))) {
		num -= 16;
		word <<= 16;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-8)))) {
		num -= 8;
		word <<= 8;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-4)))) {
		num -= 4;
		word <<= 4;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-2)))) {
		num -= 2;
		word <<= 2;
	}
	if (!(word & (~0ul << (BITS_PER_LONG-1))))
		num -= 1;
	return num;
}

static inline int fls(unsigned int x)
{
	int r;

	if (!__builtin_constant_p(x) &&
	    __builtin_constant_p(cpu_has_clo_clz) && cpu_has_clo_clz) {
		__asm__(
		"	.set	push					\n"
		"	.set	"MIPS_ISA_LEVEL"			\n"
		"	clz	%0, %1					\n"
		"	.set	pop					\n"
		: "=r" (x)
		: "r" (x));

		return 32 - x;
	}

	r = 32;
	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

static __always_inline int fls64(__u64 x)
{
	if (x == 0)
		return 0;
	return __fls(x) + 1;
}

static __always_inline __attribute__((const))
int __ilog2_u32(u32 n)
{
	return fls(n) - 1;
}

static __always_inline __attribute__((const))
int __ilog2_u64(u64 n)
{
	return fls64(n) - 1;
}

#define ilog2(n) \
( \
	__builtin_constant_p(n) ?	\
	((n) < 2 ? 0 :			\
	 63 - __builtin_clzll(n)) :	\
	(sizeof(n) <= 4) ?		\
	__ilog2_u32(n) :		\
	__ilog2_u64(n)			\
 )

static inline __attribute_const__
int __order_base_2(unsigned long n)
{
	return n > 1 ? ilog2(n - 1) + 1 : 0;
}

# define POISON_POINTER_DELTA 0

#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)

#define LIST_POISON2  ((void *) 0x122 + POISON_POINTER_DELTA)

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	WRITE_ONCE(list->next, list);
	WRITE_ONCE(list->prev, list);
}

static inline bool __list_add_valid(struct list_head *new,
				struct list_head *prev,
				struct list_head *next)
{
	return true;
}

static inline bool __list_del_entry_valid(struct list_head *entry)
{
	return true;
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	if (!__list_add_valid(new, prev, next))
		return;

	next->prev = new;
	new->next = next;
	new->prev = prev;
	WRITE_ONCE(prev->next, new);
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	WRITE_ONCE(prev->next, next);
}

static inline void __list_del_entry(struct list_head *entry)
{
	if (!__list_del_entry_valid(entry))
		return;

	__list_del(entry->prev, entry->next);
}

static inline void list_del(struct list_head *entry)
{
	__list_del_entry(entry);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline int list_is_head(const struct list_head *list, const struct list_head *head)
{
	return list == head;
}

static inline int list_empty(const struct list_head *head)
{
	return READ_ONCE(head->next) == head;
}

static inline int list_empty_careful(const struct list_head *head)
{
	struct list_head *next = smp_load_acquire(&head->next);
	return list_is_head(next, head) && (next == READ_ONCE(head->prev));
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; \
	     !list_is_head(pos, (head)); \
	     pos = n, n = pos->next)

#define list_entry_is_head(pos, head, member)				\
	list_is_head(&pos->member, (head))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))

#define HLIST_HEAD_INIT { .first = NULL }

#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }

#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

static inline int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

static inline int hlist_unhashed_lockless(const struct hlist_node *h)
{
	return !READ_ONCE(h->pprev);
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !READ_ONCE(h->first);
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;

	WRITE_ONCE(*pprev, next);
	if (next)
		WRITE_ONCE(next->pprev, pprev);
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}

static inline void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	WRITE_ONCE(n->next, first);
	if (first)
		WRITE_ONCE(first->pprev, &n->next);
	WRITE_ONCE(h->first, n);
	WRITE_ONCE(n->pprev, &h->first);
}

static inline void hlist_add_before(struct hlist_node *n,
				    struct hlist_node *next)
{
	WRITE_ONCE(n->pprev, next->pprev);
	WRITE_ONCE(n->next, next);
	WRITE_ONCE(next->pprev, &n->next);
	WRITE_ONCE(*(n->pprev), n);
}

static inline void hlist_add_behind(struct hlist_node *n,
				    struct hlist_node *prev)
{
	WRITE_ONCE(n->next, prev->next);
	WRITE_ONCE(prev->next, n);
	WRITE_ONCE(n->pprev, &prev->next);

	if (n->next)
		WRITE_ONCE(n->next->pprev, &n->next);
}

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#define hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = hlist_entry_safe(n, typeof(*pos), member))

#define hash_long(val, bits) hash_64(val, bits)

#define GOLDEN_RATIO_32 0x61C88647

#define GOLDEN_RATIO_64 0x61C8864680B583EBull

#define __hash_32 __hash_32_generic

static inline u32 __hash_32_generic(u32 val)
{
	return val * GOLDEN_RATIO_32;
}

#define hash_64 hash_64_generic

static inline u32 hash_32(u32 val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return __hash_32(val) >> (32 - bits);
}

static __always_inline u32 hash_64_generic(u64 val, unsigned int bits)
{
#if BITS_PER_LONG == 64
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return val * GOLDEN_RATIO_64 >> (64 - bits);
#else
	/* Hash 64 bits using only 32x32-bit multiply. */
	return hash_32((u32)val ^ __hash_32(val >> 32), bits);
#endif
}

#define DEFINE_HASHTABLE(name, bits)						\
	struct hlist_head name[1 << (bits)] =					\
			{ [0 ... ((1 << (bits)) - 1)] = HLIST_HEAD_INIT }

#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]

#define HASH_SIZE(name) (ARRAY_SIZE(name))

#define HASH_BITS(name) ilog2(HASH_SIZE(name))

#define hash_min(val, bits)							\
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))

#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))

#define hash_add(hashtable, node, key)						\
	hlist_add_head(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])

static inline void __hash_init(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		INIT_HLIST_HEAD(&ht[i]);
}

static inline bool hash_hashed(struct hlist_node *node)
{
	return !hlist_unhashed(node);
}

#define hash_empty(hashtable) __hash_empty(hashtable, HASH_SIZE(hashtable))

static inline bool __hash_empty(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		if (!hlist_empty(&ht[i]))
			return false;

	return true;
}

static inline void hash_del(struct hlist_node *node)
{
	hlist_del_init(node);
}

#define hash_for_each(name, bkt, obj, member)				\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry(obj, &name[bkt], member)

#define hash_for_each_possible(name, obj, member, key)			\
	hlist_for_each_entry(obj, &name[hash_min(key, HASH_BITS(name))], member)

#define hash_for_each_possible_safe(name, obj, tmp, member, key)	\
	hlist_for_each_entry_safe(obj, tmp,\
		&name[hash_min(key, HASH_BITS(name))], member)
