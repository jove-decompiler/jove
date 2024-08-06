#define CONFIG_ARM64_ERRATUM_2658417 1

#define CONFIG_ARM64_PTR_AUTH 1

#define CONFIG_ARM64_ERRATUM_1742098 1

#define CONFIG_NVIDIA_CARMEL_CNP_ERRATUM 1

#define CONFIG_ARM64_TLB_RANGE 1

#define CONFIG_ARM64_BTI 1

#define CONFIG_ARM64_MTE 1

#define CONFIG_ARM64_WORKAROUND_SPECULATIVE_SSBS 1

#define CONFIG_ARM64_SVE 1

#define CONFIG_ARM64_CNP 1

#define CONFIG_ARM64_WORKAROUND_REPEAT_TLBI 1

#define CONFIG_ARM64_EPAN 1

#define CONFIG_ARM64_SME 1

#define CONFIG_UNMAP_KERNEL_AT_EL0 1

#define CONFIG_ARM64_ERRATUM_2645198 1

#define CONFIG_ARM64_ERRATUM_843419 1

#define CONFIG_ARM64_PAN 1

#define CONFIG_ILLEGAL_POINTER_VALUE 0xdead000000000000

#define CONFIG_CAVIUM_ERRATUM_23154 1

#define __ARG_PLACEHOLDER_1 0,

#define __take_second_arg(__ignored, val, ...) val

#define __or(x, y)			___or(x, y)

#define ___or(x, y)			____or(__ARG_PLACEHOLDER_##x, y)

#define ____or(arg1_or_junk, y)		__take_second_arg(arg1_or_junk 1, y)

#define __is_defined(x)			___is_defined(x)

#define ___is_defined(val)		____is_defined(__ARG_PLACEHOLDER_##val)

#define ____is_defined(arg1_or_junk)	__take_second_arg(arg1_or_junk 1, 0)

#define IS_BUILTIN(option) __is_defined(option)

#define IS_MODULE(option) __is_defined(option##_MODULE)

#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))

#define __always_inline                 inline __attribute__((__always_inline__))

#define __attribute_const__             __attribute__((__const__))

# define __compiletime_error(msg)       __attribute__((__error__(msg)))

#define __gnu_inline                    __attribute__((__gnu_inline__))

#define __noreturn                      __attribute__((__noreturn__))

#define __maybe_unused                  __attribute__((__unused__))

#define __used                          __attribute__((__used__))

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

#define __AC(X,Y)	(X##Y)

#define _AC(X,Y)	__AC(X,Y)

#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#define BITS_PER_LONG 64

typedef unsigned char __u8;

typedef unsigned short __u16;

typedef unsigned int __u32;

typedef unsigned long long __u64;

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

static inline bool kasan_check_read(const volatile void *p, unsigned int size)
{
	return true;
}

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

#define ARM64_BTI                                     	2

#define ARM64_HAS_ADDRESS_AUTH                        	5

#define ARM64_HAS_CNP                                 	13

#define ARM64_HAS_EPAN                                	21

#define ARM64_HAS_GENERIC_AUTH                        	26

#define ARM64_HAS_GIC_PRIO_MASKING                    	31

#define ARM64_HAS_PAN                                 	40

#define ARM64_HAS_TLB_RANGE                           	48

#define ARM64_MTE                                     	56

#define ARM64_SME                                     	58

#define ARM64_SME_FA64                                	59

#define ARM64_SME2                                    	60

#define ARM64_SVE                                     	66

#define ARM64_UNMAP_KERNEL_AT_EL0                     	67

#define ARM64_WORKAROUND_843419                       	69

#define ARM64_WORKAROUND_1742098                      	76

#define ARM64_WORKAROUND_2645198                      	82

#define ARM64_WORKAROUND_2658417                      	83

#define ARM64_WORKAROUND_CAVIUM_23154                 	88

#define ARM64_WORKAROUND_NVIDIA_CARMEL_CNP            	95

#define ARM64_WORKAROUND_REPEAT_TLBI                  	97

#define ARM64_WORKAROUND_SPECULATIVE_SSBS             	99

#define ARM64_NCAPS					101

static __always_inline bool
cpucap_is_possible(const unsigned int cap)
{
	compiletime_assert(__builtin_constant_p(cap),
			   "cap must be a constant");
	compiletime_assert(cap < ARM64_NCAPS,
			   "cap must be < ARM64_NCAPS");

	switch (cap) {
	case ARM64_HAS_PAN:
		return IS_ENABLED(CONFIG_ARM64_PAN);
	case ARM64_HAS_EPAN:
		return IS_ENABLED(CONFIG_ARM64_EPAN);
	case ARM64_SVE:
		return IS_ENABLED(CONFIG_ARM64_SVE);
	case ARM64_SME:
	case ARM64_SME2:
	case ARM64_SME_FA64:
		return IS_ENABLED(CONFIG_ARM64_SME);
	case ARM64_HAS_CNP:
		return IS_ENABLED(CONFIG_ARM64_CNP);
	case ARM64_HAS_ADDRESS_AUTH:
	case ARM64_HAS_GENERIC_AUTH:
		return IS_ENABLED(CONFIG_ARM64_PTR_AUTH);
	case ARM64_HAS_GIC_PRIO_MASKING:
		return IS_ENABLED(CONFIG_ARM64_PSEUDO_NMI);
	case ARM64_MTE:
		return IS_ENABLED(CONFIG_ARM64_MTE);
	case ARM64_BTI:
		return IS_ENABLED(CONFIG_ARM64_BTI);
	case ARM64_HAS_TLB_RANGE:
		return IS_ENABLED(CONFIG_ARM64_TLB_RANGE);
	case ARM64_UNMAP_KERNEL_AT_EL0:
		return IS_ENABLED(CONFIG_UNMAP_KERNEL_AT_EL0);
	case ARM64_WORKAROUND_843419:
		return IS_ENABLED(CONFIG_ARM64_ERRATUM_843419);
	case ARM64_WORKAROUND_1742098:
		return IS_ENABLED(CONFIG_ARM64_ERRATUM_1742098);
	case ARM64_WORKAROUND_2645198:
		return IS_ENABLED(CONFIG_ARM64_ERRATUM_2645198);
	case ARM64_WORKAROUND_2658417:
		return IS_ENABLED(CONFIG_ARM64_ERRATUM_2658417);
	case ARM64_WORKAROUND_CAVIUM_23154:
		return IS_ENABLED(CONFIG_CAVIUM_ERRATUM_23154);
	case ARM64_WORKAROUND_NVIDIA_CARMEL_CNP:
		return IS_ENABLED(CONFIG_NVIDIA_CARMEL_CNP_ERRATUM);
	case ARM64_WORKAROUND_REPEAT_TLBI:
		return IS_ENABLED(CONFIG_ARM64_WORKAROUND_REPEAT_TLBI);
	case ARM64_WORKAROUND_SPECULATIVE_SSBS:
		return IS_ENABLED(CONFIG_ARM64_WORKAROUND_SPECULATIVE_SSBS);
	}

	return true;
}

#define __smp_load_acquire(p)						\
({									\
	union { __unqual_scalar_typeof(*p) __val; char __c[1]; } __u;	\
	typeof(p) __p = (p);						\
	compiletime_assert_atomic_type(*p);				\
	kasan_check_read(__p, sizeof(*p));				\
	switch (sizeof(*p)) {						\
	case 1:								\
		asm volatile ("ldarb %w0, %1"				\
			: "=r" (*(__u8 *)__u.__c)			\
			: "Q" (*__p) : "memory");			\
		break;							\
	case 2:								\
		asm volatile ("ldarh %w0, %1"				\
			: "=r" (*(__u16 *)__u.__c)			\
			: "Q" (*__p) : "memory");			\
		break;							\
	case 4:								\
		asm volatile ("ldar %w0, %1"				\
			: "=r" (*(__u32 *)__u.__c)			\
			: "Q" (*__p) : "memory");			\
		break;							\
	case 8:								\
		asm volatile ("ldar %0, %1"				\
			: "=r" (*(__u64 *)__u.__c)			\
			: "Q" (*__p) : "memory");			\
		break;							\
	}								\
	(typeof(*p))__u.__val;						\
})

#define smp_load_acquire(p) __smp_load_acquire(p)

static __always_inline unsigned int __fls(unsigned long word)
{
	return (sizeof(word) * 8) - 1 - __builtin_clzl(word);
}

static __always_inline int fls(unsigned int x)
{
	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
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

# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)

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
