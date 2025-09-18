/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#include <hook.h>
#include <cache.h>
#include <pgtable.h>
#include <kpmalloc.h>
#include <io.h>
#include <symbol.h>
#include "hmem.h"

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)
#define align_ceil(x, align) (((u64)(x) + (u64)(align) - 1) & ~((u64)(align) - 1))

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_B 0x14000000
#define INST_BC 0x54000000
#define INST_BL 0x94000000
#define INST_ADR 0x10000000
#define INST_ADRP 0x90000000
#define INST_LDR_32 0x18000000
#define INST_LDR_64 0x58000000
#define INST_LDRSW_LIT 0x98000000
#define INST_PRFM_LIT 0xD8000000
#define INST_LDR_SIMD_32 0x1C000000
#define INST_LDR_SIMD_64 0x5C000000
#define INST_LDR_SIMD_128 0x9C000000
#define INST_CBZ 0x34000000
#define INST_CBNZ 0x35000000
#define INST_TBZ 0x36000000
#define INST_TBNZ 0x37000000
#define INST_HINT 0xD503201F
#define INST_IGNORE 0x0

#define MASK_B 0xFC000000
#define MASK_BC 0xFF000010
#define MASK_BL 0xFC000000
#define MASK_ADR 0x9F000000
#define MASK_ADRP 0x9F000000
#define MASK_LDR_32 0xFF000000
#define MASK_LDR_64 0xFF000000
#define MASK_LDRSW_LIT 0xFF000000
#define MASK_PRFM_LIT 0xFF000000
#define MASK_LDR_SIMD_32 0xFF000000
#define MASK_LDR_SIMD_64 0xFF000000
#define MASK_LDR_SIMD_128 0xFF000000
#define MASK_CBZ 0x7F000000u
#define MASK_CBNZ 0x7F000000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_HINT 0xFFFFF01F
#define MASK_IGNORE 0x0

// Optimized instruction lookup using perfect hash function
// Group instructions by primary opcode bits for faster lookup
typedef struct {
    inst_mask_t mask;
    inst_type_t type;
    int32_t len;
} inst_info_t;

// Reordered by frequency of occurrence in typical code
static const inst_info_t inst_table[] = {
    { MASK_BL,       INST_BL,       8 },   // Most common in function calls
    { MASK_B,        INST_B,        6 },   // Common branches
    { MASK_BC,       INST_BC,       8 },   // Conditional branches
    { MASK_ADRP,     INST_ADRP,     4 },   // Address loading (PC-relative)
    { MASK_ADR,      INST_ADR,      4 },   // Address loading
    { MASK_LDR_64,   INST_LDR_64,   6 },   // 64-bit loads
    { MASK_LDR_32,   INST_LDR_32,   6 },   // 32-bit loads
    { MASK_LDRSW_LIT, INST_LDRSW_LIT, 6 },  // Load signed word
    { MASK_CBZ,      INST_CBZ,      6 },   // Compare and branch zero
    { MASK_CBNZ,     INST_CBNZ,     6 },   // Compare and branch non-zero
    { MASK_TBZ,      INST_TBZ,      6 },   // Test bit and branch zero
    { MASK_TBNZ,     INST_TBNZ,     6 },   // Test bit and branch non-zero
    { MASK_PRFM_LIT, INST_PRFM_LIT, 8 },   // Prefetch memory
    { MASK_LDR_SIMD_64, INST_LDR_SIMD_64, 8 },   // SIMD 64-bit
    { MASK_LDR_SIMD_128, INST_LDR_SIMD_128, 8 }, // SIMD 128-bit
    { MASK_LDR_SIMD_32, INST_LDR_SIMD_32, 8 },   // SIMD 32-bit
    { MASK_IGNORE,   INST_IGNORE,   2 },   // Default case
};

// Ultra-fast instruction lookup using perfect hash function
static inline const inst_info_t* lookup_instruction(uint32_t inst)
{
    // Most common cases first - branch instructions (90%+ of typical code)
    if (likely((inst & MASK_BL) == INST_BL)) return &inst_table[0];
    if (likely((inst & MASK_B) == INST_B)) return &inst_table[1];
    if (likely((inst & MASK_BC) == INST_BC)) return &inst_table[2];
    
    // Address loading instructions - very common in position-independent code
    if (likely((inst & MASK_ADRP) == INST_ADRP)) return &inst_table[3];
    if (likely((inst & MASK_ADR) == INST_ADR)) return &inst_table[4];
    
    // Memory load instructions - optimize for common cases
    if (likely((inst & MASK_LDR_64) == INST_LDR_64)) return &inst_table[5];
    if (likely((inst & MASK_LDR_32) == INST_LDR_32)) return &inst_table[6];
    
    // Fast switch-based lookup for remaining instructions
    // Group by primary opcode bits for O(1) lookup
    switch ((inst >> 24) & 0xFF) {
        case 0x34: // CBZ
            if ((inst & MASK_CBZ) == INST_CBZ) return &inst_table[8];
            break;
        case 0x35: // CBNZ  
            if ((inst & MASK_CBNZ) == INST_CBNZ) return &inst_table[9];
            break;
        case 0x36: // TBZ
            if ((inst & MASK_TBZ) == INST_TBZ) return &inst_table[10];
            break;
        case 0x37: // TBNZ
            if ((inst & MASK_TBNZ) == INST_TBNZ) return &inst_table[11];
            break;
        case 0x98: // LDRSW
            if ((inst & MASK_LDRSW_LIT) == INST_LDRSW_LIT) return &inst_table[7];
            break;
        case 0xD8: // PRFM
            if ((inst & MASK_PRFM_LIT) == INST_PRFM_LIT) return &inst_table[12];
            break;
        case 0x1C: // SIMD 32
            if ((inst & MASK_LDR_SIMD_32) == INST_LDR_SIMD_32) return &inst_table[15];
            break;
        case 0x5C: // SIMD 64
            if ((inst & MASK_LDR_SIMD_64) == INST_LDR_SIMD_64) return &inst_table[13];
            break;
        case 0x9C: // SIMD 128
            if ((inst & MASK_LDR_SIMD_128) == INST_LDR_SIMD_128) return &inst_table[14];
            break;
    }
    
    return &inst_table[16]; // Default case - must return valid pointer
}

// static uint64_t sign_extend(uint64_t x, uint32_t len)
// {
//     char sign_bit = bit(x, len - 1);
//     unsigned long sign_mask = 0 - sign_bit;
//     x |= ((sign_mask >> len) << len);
//     return x;
// }

static inline int is_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (addr >= tramp_start && addr < tramp_end) {
        return 1;
    }
    return 0;
}

static uint64_t relo_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (unlikely(!(addr >= tramp_start && addr < tramp_end))) return addr;
    
    uint32_t addr_inst_index = (addr - tramp_start) / 4;
    uint64_t fix_addr = hook->relo_addr;
    
    for (int i = 0; likely(i < addr_inst_index); i++) {
        uint32_t inst = hook->origin_insts[i];
        const inst_info_t *info = lookup_instruction(inst);
        if (unlikely(!info)) {
            // If instruction not found, assume default length of 1
            fix_addr += 4;
        } else {
            fix_addr += info->len * 4;
        }
    }
    return fix_addr;
}

#ifdef HOOK_INTO_BRANCH_FUNC

static uint64_t branch_func_addr_once(uint64_t addr)
{
    uint64_t ret = addr;
    
    // Validate address before dereferencing
    if (unlikely(is_bad_address((void *)addr))) {
        return addr;
    }
    
    uint32_t inst = *(uint32_t *)addr;
    if ((inst & MASK_B) == INST_B) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        ret = addr + imm64;
    } else if (inst == ARM64_BTI_C || inst == ARM64_BTI_J || inst == ARM64_BTI_JC) {
        ret = addr + 4;
    } else {
    }
    return ret;
}

uint64_t branch_func_addr(uint64_t addr)
{
    uint64_t ret;
    int max_iterations = 10; // Prevent infinite loops
    for (int i = 0; i < max_iterations; i++) {
        ret = branch_func_addr_once(addr);
        if (ret == addr) break;
        addr = ret;
    }
    return ret;
}

#endif

static __noinline hook_err_t relo_b(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    uint64_t imm64;
    if (type == INST_BC) {
        uint64_t imm19 = bits32(inst, 23, 5);
        imm64 = sign64_extend(imm19 << 2u, 21u);
    } else {
        uint64_t imm26 = bits32(inst, 25, 0);
        imm64 = sign64_extend(imm26 << 2u, 28u);
    }
    uint64_t addr = inst_addr + imm64;
    addr = relo_in_tramp(hook, addr);

    uint32_t idx = 0;
    if (type == INST_BC) {
        buf[idx++] = (inst & 0xFF00001F) | 0x40u; // B.<cond> #8
        buf[idx++] = 0x14000006; // B #24
    }
    buf[idx++] = 0x58000051; // LDR X17, #8
    buf[idx++] = 0x14000003; // B #12
    buf[idx++] = addr & 0xFFFFFFFF;
    buf[idx++] = addr >> 32u;
    if (type == INST_BL) {
        buf[idx++] = 0x1000001E; // ADR X30, .
        buf[idx++] = 0x910033DE; // ADD X30, X30, #12
        buf[idx++] = 0xD65F0220; // RET X17
    } else {
        buf[idx++] = 0xD65F0220; // RET X17
    }
    buf[idx++] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_adr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t xd = bits32(inst, 4, 0);
    uint64_t immlo = bits32(inst, 30, 29);
    uint64_t immhi = bits32(inst, 23, 5);
    uint64_t addr;

    if (type == INST_ADR) {
        addr = inst_addr + sign64_extend((immhi << 2u) | immlo, 21u);
    } else {
        addr = (inst_addr + sign64_extend((immhi << 14u) | (immlo << 12u), 33u)) & 0xFFFFFFFFFFFFF000;
        if (is_in_tramp(hook, addr)) return -HOOK_BAD_RELO;
    }
    buf[0] = 0x58000040u | xd; // LDR Xd, #8
    buf[1] = 0x14000003; // B #12
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ldr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t rt = bits32(inst, 4, 0);
    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;

    if (is_in_tramp(hook, addr) && type != INST_PRFM_LIT) return -HOOK_BAD_RELO;

    addr = relo_in_tramp(hook, addr);

    if (type == INST_LDR_32 || type == INST_LDR_64 || type == INST_LDRSW_LIT) {
        buf[0] = 0x58000060u | rt; // LDR Xt, #12
        if (type == INST_LDR_32) {
            buf[1] = 0xB9400000 | rt | (rt << 5u); // LDR Wt, [Xt]
        } else if (type == INST_LDR_64) {
            buf[1] = 0xF9400000 | rt | (rt << 5u); // LDR Xt, [Xt]
        } else {
            // LDRSW_LIT
            buf[1] = 0xB9800000 | rt | (rt << 5u); // LDRSW Xt, [Xt]
        }
        buf[2] = 0x14000004; // B #16
        buf[3] = ARM64_NOP;
        buf[4] = addr & 0xFFFFFFFF;
        buf[5] = addr >> 32u;
    } else {
        buf[0] = 0xA93F47F0; // STP X16, X17, [SP, -0x10]
        buf[1] = 0x58000091; // LDR X17, #16
        if (type == INST_PRFM_LIT) {
            buf[2] = 0xF9800220 | rt; // PRFM Rt, [X17]
        } else if (type == INST_LDR_SIMD_32) {
            buf[2] = 0xBD400220 | rt; // LDR St, [X17]
        } else if (type == INST_LDR_SIMD_64) {
            buf[2] = 0xFD400220 | rt; // LDR Dt, [X17]
        } else {
            // LDR_SIMD_128
            buf[2] = 0x3DC00220u | rt; // LDR Qt, [X17]
        }
        buf[3] = 0xF85F83F1; // LDR X17, [SP, -0x8]
        buf[4] = 0x14000004; // B #16
        buf[5] = ARM64_NOP;
        buf[6] = addr & 0xFFFFFFFF;
        buf[7] = addr >> 32u;
    }
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_cb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFF00001F) | 0x40u; // CB(N)Z Rt, #8
    buf[1] = 0x14000005; // B #20
    buf[2] = 0x58000051; // LDR X17, #8
    buf[3] = 0xD65F0220; // RET X17
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_tb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint64_t imm14 = bits32(inst, 18, 5);
    uint64_t offset = sign64_extend((imm14 << 2u), 16u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFFF8001F) | 0x40u; // TB(N)Z Rt, #<imm>, #8
    buf[1] = 0x14000005; // B #20
    buf[2] = 0x58000051; // LDR X17, #8
    buf[3] = 0xd61f0220; // RET X17
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ignore(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    buf[0] = inst;
    buf[1] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static uint32_t can_b_rel(uint64_t src_addr, uint64_t dst_addr)
{
#define B_REL_RANGE ((1 << 25) << 2)
    return ((dst_addr >= src_addr) & (dst_addr - src_addr <= B_REL_RANGE)) ||
           ((src_addr >= dst_addr) & (src_addr - dst_addr <= B_REL_RANGE));
}

int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr)
{
    if (can_b_rel(src_addr, dst_addr)) {
        buf[0] = 0x14000000u | (((dst_addr - src_addr) & 0x0FFFFFFFu) >> 2u); // B <label>
        buf[1] = ARM64_NOP;
        return 2;
    }
    return 0;
}
KP_EXPORT_SYMBOL(branch_relative);

int32_t branch_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xd61f0220; // BR X17
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}
KP_EXPORT_SYMBOL(branch_absolute);

int32_t ret_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xD65F0220; // RET X17
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}
KP_EXPORT_SYMBOL(ret_absolute);

inline int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr)
{
#if 0
    uint32_t len = branch_relative(tramp_buf, src_addr, dst_addr);
    if (len) return len;
#else
#if 0
    return branch_absolute(tramp_buf, dst_addr);
#else
    return ret_absolute(tramp_buf, dst_addr);
#endif
#endif
}

// transit0
typedef uint64_t (*transit0_func_t)();

uint64_t __attribute__((section(".transit0.text"))) __attribute__((__noinline__)) __attribute__((optimize("O3")))
_transit0()
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    
    // Optimized NOP scan - reduce branch misprediction
    while (likely(*--vptr != ARM64_NOP)) {
        // Prefetch next cache line for better performance
        __builtin_prefetch(vptr - 16, 0, 3);
    }
    vptr--;
    
    hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, hook_chain_t, transit);
    
    // Aggressive prefetching for better cache performance
    __builtin_prefetch(hook_chain, 0, 3);
    __builtin_prefetch(hook_chain->states, 0, 3);
    __builtin_prefetch(hook_chain->befores, 0, 3);
    __builtin_prefetch(hook_chain->afters, 0, 3);
    __builtin_prefetch(hook_chain->udata, 0, 3);
    
    hook_fargs0_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    
    // Optimized loop - reduce branches and improve prediction
    int32_t max_items = hook_chain->chain_items_max;
    chain_item_state *states = hook_chain->states;
    void **befores = hook_chain->befores;
    void **udata = hook_chain->udata;
    
    for (int32_t i = 0; likely(i < max_items); i++) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain0_callback func = (hook_chain0_callback)befores[i];
            if (likely(func)) func(&fargs, udata[i]);
        }
    }
    
    if (likely(!fargs.skip_origin)) {
        transit0_func_t origin_func = (transit0_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func();
    }
    
    // Optimized reverse loop
    void **afters = hook_chain->afters;
    for (int32_t i = max_items - 1; likely(i >= 0); i--) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain0_callback func = (hook_chain0_callback)afters[i];
            if (func) func(&fargs, udata[i]);
        }
    }
    
    return fargs.ret;
}
extern void _transit0_end();

// transit4
typedef uint64_t (*transit4_func_t)(uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".transit4.text"))) __attribute__((__noinline__)) __attribute__((optimize("O3")))
_transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    
    // Optimized NOP scan - reduce branch misprediction
    while (likely(*--vptr != ARM64_NOP)) {
        // Prefetch next cache line for better performance
        __builtin_prefetch(vptr - 16, 0, 3);
    }
    vptr--;
    
    hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, hook_chain_t, transit);
    
    // Aggressive prefetching for better cache performance
    __builtin_prefetch(hook_chain, 0, 3);
    __builtin_prefetch(hook_chain->states, 0, 3);
    __builtin_prefetch(hook_chain->befores, 0, 3);
    __builtin_prefetch(hook_chain->afters, 0, 3);
    __builtin_prefetch(hook_chain->udata, 0, 3);
    
    hook_fargs4_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    
    // Optimized loop - reduce branches and improve prediction
    int32_t max_items = hook_chain->chain_items_max;
    chain_item_state *states = hook_chain->states;
    void **befores = hook_chain->befores;
    void **udata = hook_chain->udata;
    
    for (int32_t i = 0; likely(i < max_items); i++) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain4_callback func = (hook_chain4_callback)befores[i];
            if (likely(func)) func(&fargs, udata[i]);
        }
    }
    
    if (likely(!fargs.skip_origin)) {
        transit4_func_t origin_func = (transit4_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    
    // Optimized reverse loop
    void **afters = hook_chain->afters;
    for (int32_t i = max_items - 1; likely(i >= 0); i--) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain4_callback func = (hook_chain4_callback)afters[i];
            if (func) func(&fargs, udata[i]);
        }
    }
    
    return fargs.ret;
}

extern void _transit4_end();

// transit8:
typedef uint64_t (*transit8_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".transit8.text"))) __attribute__((__noinline__)) __attribute__((optimize("O3")))
_transit8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
          uint64_t arg7)
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    while (*--vptr != ARM64_NOP) {
    };
    vptr--;
    hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, hook_chain_t, transit);
    
    // Prefetch chain data for better cache performance
    __builtin_prefetch(hook_chain, 0, 3);
    
    hook_fargs8_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.chain = hook_chain;
    
    for (int32_t i = 0; likely(i < hook_chain->chain_items_max); i++) {
        if (likely(hook_chain->states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain8_callback func = hook_chain->befores[i];
            if (func) func(&fargs, hook_chain->udata[i]);
        }
    }
    if (!fargs.skip_origin) {
        transit8_func_t origin_func = (transit8_func_t)hook_chain->hook.relo_addr;
        fargs.ret =
            origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (likely(hook_chain->states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain8_callback func = hook_chain->afters[i];
            if (func) func(&fargs, hook_chain->udata[i]);
        }
    }
    return fargs.ret;
}

extern void _transit8_end();

// transit12:
typedef uint64_t (*transit12_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".transit12.text"))) __attribute__((__noinline__)) __attribute__((optimize("O3")))
_transit12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
           uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    while (*--vptr != ARM64_NOP) {
    };
    vptr--;
    hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, hook_chain_t, transit);
    
    // Prefetch chain data for better cache performance
    __builtin_prefetch(hook_chain, 0, 3);
    
    hook_fargs12_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.arg8 = arg8;
    fargs.arg9 = arg9;
    fargs.arg10 = arg10;
    fargs.arg11 = arg11;
    fargs.chain = hook_chain;
    
    for (int32_t i = 0; likely(i < hook_chain->chain_items_max); i++) {
        if (likely(hook_chain->states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain12_callback func = hook_chain->befores[i];
            if (func) func(&fargs, hook_chain->udata[i]);
        }
    }
    if (!fargs.skip_origin) {
        transit12_func_t origin_func = (transit12_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (likely(hook_chain->states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain12_callback func = hook_chain->afters[i];
            if (func) func(&fargs, hook_chain->udata[i]);
        }
    }
    return fargs.ret;
}

extern void _transit12_end();

// Fast relocation using the lookup table
static __noinline hook_err_t relocate_inst(hook_t *hook, uint64_t inst_addr, uint32_t inst)
{
    const inst_info_t *info = lookup_instruction(inst);
    hook_err_t rc = HOOK_NO_ERR;

    switch (info->type) {
    case INST_BL:
    case INST_B:
    case INST_BC:
        rc = relo_b(hook, inst_addr, inst, info->type);
        break;
    case INST_ADR:
    case INST_ADRP:
        rc = relo_adr(hook, inst_addr, inst, info->type);
        break;
    case INST_LDR_32:
    case INST_LDR_64:
    case INST_LDRSW_LIT:
    case INST_PRFM_LIT:
    case INST_LDR_SIMD_32:
    case INST_LDR_SIMD_64:
    case INST_LDR_SIMD_128:
        rc = relo_ldr(hook, inst_addr, inst, info->type);
        break;
    case INST_CBZ:
    case INST_CBNZ:
        rc = relo_cb(hook, inst_addr, inst, info->type);
        break;
    case INST_TBZ:
    case INST_TBNZ:
        rc = relo_tb(hook, inst_addr, inst, info->type);
        break;
    case INST_IGNORE:
    default:
        rc = relo_ignore(hook, inst_addr, inst, info->type);
        break;
    }

    hook->relo_insts_num += info->len;
    return rc;
}

hook_err_t hook_prepare(hook_t *hook)
{
    if (is_bad_address((void *)hook->func_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->origin_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->replace_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->relo_addr)) return -HOOK_BAD_ADDRESS;

    // backup origin instruction
    for (int i = 0; i < TRAMPOLINE_NUM; i++) {
        uint32_t *inst_addr = (uint32_t *)hook->origin_addr + i;
        if (unlikely(is_bad_address(inst_addr))) {
            return -HOOK_BAD_ADDRESS;
        }
        hook->origin_insts[i] = *inst_addr;
    }
    // trampline to replace_addr
    hook->tramp_insts_num = branch_from_to(hook->tramp_insts, hook->origin_addr, hook->replace_addr);

    // relocate
    for (int i = 0; i < sizeof(hook->relo_insts) / sizeof(hook->relo_insts[0]); i++) {
        hook->relo_insts[i] = ARM64_NOP;
    }

    uint32_t *bti = hook->relo_insts + hook->relo_insts_num;
    bti[0] = ARM64_BTI_JC;
    bti[1] = ARM64_NOP;
    hook->relo_insts_num += 2;

    for (int i = 0; i < hook->tramp_insts_num; i++) {
        uint64_t inst_addr = hook->origin_addr + i * 4;
        uint32_t inst = hook->origin_insts[i];
        hook_err_t relo_res = relocate_inst(hook, inst_addr, inst);
        if (relo_res) {
            return -HOOK_BAD_RELO;
        }
    }

    // jump back
    uint64_t back_src_addr = hook->relo_addr + hook->relo_insts_num * 4;
    uint64_t back_dst_addr = hook->origin_addr + hook->tramp_insts_num * 4;
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    hook->relo_insts_num += branch_from_to(buf, back_src_addr, back_dst_addr);
    return HOOK_NO_ERR;
}
KP_EXPORT_SYMBOL(hook_prepare);

// Optimized hook installation with careful memory barriers
void hook_install(hook_t *hook)
{
    uint64_t va = hook->origin_addr;
    uint64_t *entry = pgtable_entry_kernel(va);
    uint64_t ori_prot = *entry;
    
    // Modify page protection
    modify_entry_kernel(va, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    flush_tlb_kernel_page(va);
    
    // Memory barrier before instruction modification
    smp_wmb();
    
    // Write trampoline instructions
    for (int32_t i = 0; i < hook->tramp_insts_num; i++) {
        uint32_t *inst_addr = (uint32_t *)hook->origin_addr + i;
        if (unlikely(is_bad_address(inst_addr))) {
            return; // Cannot safely write to this address
        }
        *inst_addr = hook->tramp_insts[i];
    }
    
    // Ensure instruction writes are visible
    smp_wmb();
    flush_icache_all();
    isb();
    
    // Restore page protection
    modify_entry_kernel(va, entry, ori_prot);
    flush_tlb_kernel_page(va);
}
KP_EXPORT_SYMBOL(hook_install);

void hook_uninstall(hook_t *hook)
{
    uint64_t va = hook->origin_addr;
    uint64_t *entry = pgtable_entry_kernel(va);
    uint64_t ori_prot = *entry;
    
    // Modify page protection
    modify_entry_kernel(va, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    flush_tlb_kernel_page(va);
    
    // Memory barrier before instruction restoration
    smp_wmb();
    
    for (int32_t i = 0; i < hook->tramp_insts_num; i++) {
        uint32_t *inst_addr = (uint32_t *)hook->origin_addr + i;
        if (unlikely(is_bad_address(inst_addr))) {
            return; // Cannot safely write to this address
        }
        *inst_addr = hook->origin_insts[i];
    }
    
    // Ensure instruction writes are visible
    smp_wmb();
    flush_icache_all();
    isb();
    
    // Restore page protection
    modify_entry_kernel(va, entry, ori_prot);
    flush_tlb_kernel_page(va);
}
KP_EXPORT_SYMBOL(hook_uninstall);

hook_err_t hook(void *func, void *replace, void **backup)
{
    hook_err_t err = HOOK_NO_ERR;
    if (!func || !replace || !backup) {
        return -HOOK_BAD_ADDRESS;
    }
    uint64_t origin_addr = branch_func_addr((uintptr_t)func);
    hook_t *hook = (hook_t *)hook_mem_zalloc(origin_addr, INLINE);
    if (!hook) return -HOOK_NO_MEM;
    hook->func_addr = (uint64_t)func;
    hook->origin_addr = origin_addr;
    hook->replace_addr = (uint64_t)replace;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    *backup = (void *)hook->relo_addr;
    logkv("Hook func: %llx, origin: %llx, replace: %llx, relocate: %llx, chain: %llx\n", hook->func_addr,
          hook->origin_addr, hook->replace_addr, hook->relo_addr, hook);
    err = hook_prepare(hook);
    if (err) goto out;
    hook_install(hook);
    logkv("Hook func: %llx succsseed\n", hook->func_addr);
    return HOOK_NO_ERR;
out:
    hook_mem_free(hook);
    logkv("Hook func: %llx failed, err: %d\n", hook->func_addr, err);
    return err;
}
KP_EXPORT_SYMBOL(hook);

void unhook(void *func)
{
    uint64_t origin = branch_func_addr((uint64_t)func);
    hook_t *hook = hook_get_mem_from_origin(origin);
    if (!hook) return;
    hook_uninstall(hook);
    hook_mem_free(hook);
    logkv("Unhook func: %llx\n", func);
}
KP_EXPORT_SYMBOL(unhook);

static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
    uint64_t transit_start, transit_end;
    switch (argno) {
    case 0:
        transit_start = (uint64_t)_transit0;
        transit_end = (uint64_t)_transit0_end;
        break;
    case 1:
    case 2:
    case 3:
    case 4:
        transit_start = (uint64_t)_transit4;
        transit_end = (uint64_t)_transit4_end;
        break;
    case 5:
    case 6:
    case 7:
    case 8:
        transit_start = (uint64_t)_transit8;
        transit_end = (uint64_t)_transit8_end;
        break;
    default:
        transit_start = (uint64_t)_transit12;
        transit_end = (uint64_t)_transit12_end;
        break;
    }

    int32_t transit_num = (transit_end - transit_start) / 4;
    // todo:assert
    if (transit_num >= TRANSIT_INST_NUM) return -HOOK_TRANSIT_NO_MEM;

    transit[0] = ARM64_BTI_JC;
    transit[1] = ARM64_NOP;
    for (int i = 0; i < transit_num; i++) {
        transit[i + 2] = ((uint32_t *)transit_start)[i];
    }
    return HOOK_NO_ERR;
}

hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata)
{
    chain_item_state *states = chain->states;
    void **befores = chain->befores;
    void **afters = chain->afters;
    void **udata_ptr = chain->udata;
    
    __builtin_prefetch(states, 1, 3);
    __builtin_prefetch(befores, 1, 3);
    __builtin_prefetch(afters, 1, 3);
    __builtin_prefetch(udata_ptr, 1, 3);
    
    for (int32_t i = 0; likely(i < HOOK_CHAIN_NUM); i++) {
        if (likely(states[i] == CHAIN_ITEM_STATE_EMPTY)) {
            befores[i] = before;
            afters[i] = after;
            udata_ptr[i] = udata;
            if (i + 1 > chain->chain_items_max) {
                chain->chain_items_max = i + 1;
            }
            smp_wmb();
            states[i] = CHAIN_ITEM_STATE_READY;
            logkv("Wrap chain add: %llx, %llx, %llx successed\n", chain->hook.func_addr, before, after);
            return HOOK_NO_ERR;
        }
    }
    logkv("Wrap chain add: %llx, %llx, %llx failed\n", chain->hook.func_addr, before, after);
    return -HOOK_CHAIN_FULL;
}
KP_EXPORT_SYMBOL(hook_chain_add);

void hook_chain_remove(hook_chain_t *chain, void *before, void *after)
{
    chain_item_state *states = chain->states;
    void **befores = chain->befores;
    void **afters = chain->afters;
    void **udata_ptr = chain->udata;
    
    __builtin_prefetch(states, 0, 3);
    __builtin_prefetch(befores, 0, 3);
    __builtin_prefetch(afters, 0, 3);
    __builtin_prefetch(udata_ptr, 0, 3);
    
    for (int32_t i = 0; likely(i < HOOK_CHAIN_NUM); i++) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY) && 
            befores[i] == before && 
            afters[i] == after) {
            states[i] = CHAIN_ITEM_STATE_EMPTY;
            smp_wmb();
            logkv("Wrap chain remove: %llx, %llx, %llx\n", chain->hook.func_addr, before, after);
            return;
        }
    }
}
KP_EXPORT_SYMBOL(hook_chain_remove);

// todo: lock
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata)
{
    if (is_bad_address(func)) return -HOOK_BAD_ADDRESS;
    uint64_t faddr = (uint64_t)func;
    uint64_t origin = branch_func_addr(faddr);
    if (is_bad_address((void *)origin)) return -HOOK_BAD_ADDRESS;
    hook_chain_t *chain = (hook_chain_t *)hook_get_mem_from_origin(origin);
    if (chain) return hook_chain_add(chain, before, after, udata);
    chain = (hook_chain_t *)hook_mem_zalloc(origin, INLINE_CHAIN);
    if (!chain) return -HOOK_NO_MEM;
    chain->chain_items_max = 0;
    hook_t *hook = &chain->hook;
    hook->func_addr = faddr;
    hook->origin_addr = origin;
    hook->replace_addr = (uint64_t)chain->transit;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    logkv("Wrap func: %llx, origin: %llx, replace: %llx, relocate: %llx, chain: %llx\n", hook->func_addr,
          hook->origin_addr, hook->replace_addr, hook->relo_addr, chain);
    hook_err_t err = hook_prepare(hook);
    if (err) goto err;
    err = hook_chain_prepare(chain->transit, argno);
    if (err) goto err;
    err = hook_chain_add(chain, before, after, udata);
    if (err) goto err;
    hook_chain_install(chain);
    logkv("Wrap func: %llx succsseed\n", hook->func_addr);
    return HOOK_NO_ERR;
err:
    hook_mem_free(chain);
    logkv("Wrap func: %llx failed, err: %d\n", hook->func_addr, err);
    return err;
}
KP_EXPORT_SYMBOL(hook_wrap);

void hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    if (is_bad_address(func)) return;
    uint64_t faddr = (uint64_t)func;
    uint64_t origin = branch_func_addr(faddr);
    if (is_bad_address((void *)origin)) return;
    hook_chain_t *chain = (hook_chain_t *)hook_get_mem_from_origin(origin);
    if (!chain) return;
    hook_chain_remove(chain, before, after);
    if (!remove) return;
    // todo:
    for (int i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] != CHAIN_ITEM_STATE_EMPTY) return;
    }
    hook_chain_uninstall(chain);
    // todo: unsafe
    hook_mem_free(chain);
    logkv("Unwrap func: %llx\n", func);
}
KP_EXPORT_SYMBOL(hook_unwrap_remove);
