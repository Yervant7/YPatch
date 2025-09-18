/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#include <hook.h>
#include <symbol.h>
#include <pgtable.h>
#include <cache.h>
#include "hmem.h"

// transit0
typedef uint64_t (*transit0_func_t)();

uint64_t __attribute__((section(".fp.transit0.text"))) __attribute__((__noinline__)) __attribute__((optimize("O3"))) _fp_transit0()
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
    
    fp_hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);
    
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
    const int32_t max_items = hook_chain->chain_items_max;
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
        transit0_func_t origin_func = (transit0_func_t)hook_chain->hook.origin_fp;
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
extern void _fp_transit0_end();

// transit4
typedef uint64_t (*transit4_func_t)(uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit4.text"))) __attribute__((__noinline__)) __attribute__((optimize("O3")))
_fp_transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
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
    
    fp_hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);
    
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
        transit4_func_t origin_func = (transit4_func_t)hook_chain->hook.origin_fp;
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

extern void _fp_transit4_end();

// transit8:
typedef uint64_t (*transit8_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit8.text"))) __attribute__((__noinline__)) __attribute__((optimize("O3")))
_fp_transit8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
             uint64_t arg7)
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
    
    fp_hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);
    
    // Aggressive prefetching for better cache performance
    __builtin_prefetch(hook_chain, 0, 3);
    __builtin_prefetch(hook_chain->states, 0, 3);
    __builtin_prefetch(hook_chain->befores, 0, 3);
    __builtin_prefetch(hook_chain->afters, 0, 3);
    __builtin_prefetch(hook_chain->udata, 0, 3);
    
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
    
    // Optimized loop - reduce branches and improve prediction
    int32_t max_items = hook_chain->chain_items_max;
    chain_item_state *states = hook_chain->states;
    void **befores = hook_chain->befores;
    void **udata = hook_chain->udata;
    
    for (int32_t i = 0; likely(i < max_items); i++) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain8_callback func = (hook_chain8_callback)befores[i];
            if (likely(func)) func(&fargs, udata[i]);
        }
    }
    
    if (likely(!fargs.skip_origin)) {
        transit8_func_t origin_func = (transit8_func_t)hook_chain->hook.origin_fp;
        fargs.ret =
            origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
    }
    
    // Optimized reverse loop
    void **afters = hook_chain->afters;
    for (int32_t i = max_items - 1; likely(i >= 0); i--) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain8_callback func = (hook_chain8_callback)afters[i];
            if (func) func(&fargs, udata[i]);
        }
    }
    
    return fargs.ret;
}

extern void _fp_transit8_end();

// transit12:
typedef uint64_t (*transit12_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit12.text"))) __attribute__((__noinline__)) __attribute__((optimize("O3")))
_fp_transit12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
              uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
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
    
    fp_hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);
    
    // Aggressive prefetching for better cache performance
    __builtin_prefetch(hook_chain, 0, 3);
    __builtin_prefetch(hook_chain->states, 0, 3);
    __builtin_prefetch(hook_chain->befores, 0, 3);
    __builtin_prefetch(hook_chain->afters, 0, 3);
    __builtin_prefetch(hook_chain->udata, 0, 3);
    
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
    
    // Optimized loop - reduce branches and improve prediction
    int32_t max_items = hook_chain->chain_items_max;
    chain_item_state *states = hook_chain->states;
    void **befores = hook_chain->befores;
    void **udata = hook_chain->udata;
    
    for (int32_t i = 0; likely(i < max_items); i++) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain12_callback func = (hook_chain12_callback)befores[i];
            if (likely(func)) func(&fargs, udata[i]);
        }
    }
    
    if (likely(!fargs.skip_origin)) {
        transit12_func_t origin_func = (transit12_func_t)hook_chain->hook.origin_fp;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    
    // Optimized reverse loop
    void **afters = hook_chain->afters;
    for (int32_t i = max_items - 1; likely(i >= 0); i--) {
        if (likely(states[i] == CHAIN_ITEM_STATE_READY)) {
            hook_chain12_callback func = (hook_chain12_callback)afters[i];
            if (func) func(&fargs, udata[i]);
        }
    }
    
    return fargs.ret;
}

extern void _fp_transit12_end();

static inline hook_err_t __attribute__((optimize("O3"))) hook_chain_prepare(uint32_t *transit, int32_t argno)
{
    uint64_t transit_start, transit_end;
    switch (argno) {
    case 0:
        transit_start = (uint64_t)_fp_transit0;
        transit_end = (uint64_t)_fp_transit0_end;
        break;
    case 1:
    case 2:
    case 3:
    case 4:
        transit_start = (uint64_t)_fp_transit4;
        transit_end = (uint64_t)_fp_transit4_end;
        break;
    case 5:
    case 6:
    case 7:
    case 8:
        transit_start = (uint64_t)_fp_transit8;
        transit_end = (uint64_t)_fp_transit8_end;
        break;
    default:
        transit_start = (uint64_t)_fp_transit12;
        transit_end = (uint64_t)_fp_transit12_end;
        break;
    }

    int32_t transit_num = (transit_end - transit_start) / 4;

    // todo: assert
    if (transit_num >= TRANSIT_INST_NUM) return -HOOK_TRANSIT_NO_MEM;

    transit[0] = ARM64_BTI_JC;
    transit[1] = ARM64_NOP;
    for (int i = 0; i < transit_num; i++) {
        transit[i + 2] = ((uint32_t *)transit_start)[i];
    }
    return HOOK_NO_ERR;
}

void fp_hook(uintptr_t fp_addr, void *replace, void **backup)
{
    uint64_t *entry = pgtable_entry_kernel(fp_addr);
    uint64_t ori_prot = *entry;
    modify_entry_kernel(fp_addr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    flush_tlb_kernel_page(fp_addr);
    *(uintptr_t *)backup = *(uintptr_t *)fp_addr;
    *(uintptr_t *)fp_addr = (uintptr_t)replace;
    dsb(ish);
    modify_entry_kernel(fp_addr, entry, ori_prot);
}
KP_EXPORT_SYMBOL(fp_hook);

void fp_unhook(uintptr_t fp_addr, void *backup)
{
    uint64_t *entry = pgtable_entry_kernel(fp_addr);
    uint64_t ori_prot = *entry;
    modify_entry_kernel(fp_addr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    *(uintptr_t *)fp_addr = (uintptr_t)backup;
    dsb(ish);
    isb();
    flush_icache_all();
    modify_entry_kernel(fp_addr, entry, ori_prot);
}
KP_EXPORT_SYMBOL(fp_unhook);

hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata)
{
    hook_err_t err = HOOK_NO_ERR;
    if (is_bad_address((void *)fp_addr)) return -HOOK_BAD_ADDRESS;
    fp_hook_chain_t *chain = hook_get_mem_from_origin(fp_addr);
    if (!chain) {
        chain = (fp_hook_chain_t *)hook_mem_zalloc(fp_addr, FUNCTION_POINTER_CHAIN);
        if (!chain) return -HOOK_NO_MEM;
        chain->hook.fp_addr = fp_addr;
        chain->hook.replace_addr = (uint64_t)chain->transit;
        err = hook_chain_prepare(chain->transit, argno);
        if (err) return err;
        flush_icache_all();
        fp_hook(chain->hook.fp_addr, (void *)chain->hook.replace_addr, (void **)&chain->hook.origin_fp);
    }

    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if ((before && chain->befores[i] == before) || (after && chain->afters[i] == after)) return -HOOK_DUPLICATED;

        // todo: atomic or lock
        if (chain->states[i] == CHAIN_ITEM_STATE_EMPTY) {
            chain->states[i] = CHAIN_ITEM_STATE_BUSY;
            dsb(ish);
            chain->udata[i] = udata;
            chain->befores[i] = before;
            chain->afters[i] = after;
            if (i + 1 > chain->chain_items_max) {
                chain->chain_items_max = i + 1;
            }
            dsb(ish);
            chain->states[i] = CHAIN_ITEM_STATE_READY;
            logkv("Wrap func pointer add: %llx, %llx, %llx successed\n", chain->hook.fp_addr, before, after);
            return HOOK_NO_ERR;
        }
    }
    logkv("Wrap func pointer add: %llx, %llx, %llx failed\n", chain->hook.fp_addr, before, after);
    return -HOOK_CHAIN_FULL;
}
KP_EXPORT_SYMBOL(fp_hook_wrap);

void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after)
{
    if (is_bad_address((void *)fp_addr)) return;
    fp_hook_chain_t *chain = (fp_hook_chain_t *)hook_get_mem_from_origin(fp_addr);
    if (!chain) return;
    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] == CHAIN_ITEM_STATE_READY)
            if ((before && chain->befores[i] == before) || (after && chain->afters[i] == after)) {
                chain->states[i] = CHAIN_ITEM_STATE_BUSY;
                dsb(ish);
                chain->udata[i] = 0;
                chain->befores[i] = 0;
                chain->afters[i] = 0;
                dsb(ish);
                chain->states[i] = CHAIN_ITEM_STATE_EMPTY;
                break;
            }
    }
    logkv("Wrap func pointer remove: %llx, %llx, %llx\n", chain->hook.fp_addr, before, after);

    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] != CHAIN_ITEM_STATE_EMPTY) return;
    }
    fp_unhook(chain->hook.fp_addr, (void *)chain->hook.origin_fp);
    // todo: unsafe
    hook_mem_free(chain);
    logkv("Unwrap func pointer: %llx, %llx, %llx\n", fp_addr, before, after);
}
KP_EXPORT_SYMBOL(fp_hook_unwrap);