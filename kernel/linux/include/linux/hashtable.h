#ifndef __LINUX_HASHTABLE_H
#define __LINUX_HASHTABLE_H

#include <ktypes.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <asm-generic/bitops/fls_ffs.h>
#include <linux/build_bug.h>

#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

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

#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static inline u32 __hash_32_generic(u32 val)
{
	return val * GOLDEN_RATIO_32;
}

#define __hash_32 __hash_32_generic

static inline u32 hash_32(u32 val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return __hash_32(val) >> (32 - bits);
}

static __always_inline u32 hash_64_generic(u64 val, unsigned int bits)
{
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return val * GOLDEN_RATIO_64 >> (64 - bits);
}
#define hash_64 hash_64_generic

#define hash_long(val, bits) hash_64(val, bits)

#define HASH_SIZE(name) (ARRAY_SIZE(name))
#define HASH_BITS(name) ilog2(HASH_SIZE(name))
#define hash_min(val, bits)							\
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))

#define hash_for_each_possible_rcu(name, obj, member, key, cond...)	\
	hlist_for_each_entry_rcu(obj, &name[hash_min(key, HASH_BITS(name))],\
		member, ## cond)

#define hash_for_each_rcu(name, bkt, obj, member)			\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry_rcu(obj, &name[bkt], member)

#define hash_add_rcu(hashtable, node, key)					\
	hlist_add_head_rcu(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])

static inline void hash_del_rcu(struct hlist_node *node)
{
	hlist_del_init_rcu(node);
}

static inline void __hash_init(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		INIT_HLIST_HEAD(&ht[i]);
}

#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))

#endif