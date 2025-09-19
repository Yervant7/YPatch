/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#define _GNU_SOURCE
#define __USE_GNU

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "kallsym.h"
#include "order.h"
#include "insn.h"
#include "common.h"

#define IKCFG_ST "IKCFG_ST"
#define IKCFG_ED "IKCFG_ED"
#include "zlib.h"

#ifdef _WIN32
#include <string.h>
static void *memmem(const void *haystack, size_t haystack_len, const void *const needle, const size_t needle_len)
{
    if (haystack == NULL) return NULL; // or assert(haystack != NULL);
    if (haystack_len == 0) return NULL;
    if (needle == NULL) return NULL; // or assert(needle != NULL);
    if (needle_len == 0) return NULL;

    for (const char *h = haystack; haystack_len >= needle_len; ++h, --haystack_len) {
        if (!memcmp(h, needle, needle_len)) {
            return (void *)h;
        }
    }
    return NULL;
}
#endif

static int decompress_symbol_name(kallsym_t *info, char *img, int32_t *pos_to_next, char *out_type, char *out_symbol);

static int find_linux_banner(kallsym_t *info, char *img, int32_t imglen)
{
    char linux_banner_prefix[] = "Linux version ";
    size_t prefix_len = strlen(linux_banner_prefix);

    char *imgend = img + imglen;
    char *scan = img;
    info->banner_num = 0;

    /* find all occurrences */
    while ((scan = (char *)memmem(scan, imgend - scan, linux_banner_prefix, prefix_len)) != NULL) {
        /* ensure we have at least two chars after prefix to check "digit '.'" */
        if ((scan + prefix_len + 1) < imgend && isdigit((unsigned char)*(scan + prefix_len)) &&
            *(scan + prefix_len + 1) == '.') {
            if (info->banner_num < (int)(sizeof(info->linux_banner_offset) / sizeof(info->linux_banner_offset[0]))) {
                info->linux_banner_offset[info->banner_num++] = (int32_t)(scan - img);
                tools_logi("linux_banner %d: %s", info->banner_num, scan);
                tools_logi("linux_banner offset: 0x%lx\n", scan - img);
            } else {
                tools_logw("linux_banner: too many banners found, ignoring extras\n");
                break;
            }
        }
        /* advance at least one byte to avoid infinite loop on same match */
        scan++;
    }

    if (info->banner_num == 0) {
        tools_logw("no linux_banner found in image\n");
        return -1;
    }

    /* use last found banner (as original code intended) */
    char *banner = img + info->linux_banner_offset[info->banner_num - 1];

    /* safe parsing: ensure banner + prefix exists inside image */
    if (banner < img || banner >= imgend || (banner + prefix_len) >= imgend) {
        tools_loge("linux_banner pointer out of bounds\n");
        return -1;
    }

    char *uts_release_start = banner + prefix_len;
    /* find space after release field (guard against NULL) */
    char *space = memchr(uts_release_start, ' ', imgend - uts_release_start);
    if (!space) {
        tools_logw("linux_banner: malformed banner, missing space after release\n");
        return -1;
    }

    /* parse version numbers robustly */
    char *dot = NULL;
    errno = 0;
    unsigned long major = strtoul(uts_release_start, &dot, 10);
    if (dot == uts_release_start || errno == ERANGE) {
        tools_logw("linux_banner: cannot parse major version\n");
        return -1;
    }

    unsigned long minor = 0;
    unsigned long patch = 0;
    if (dot && *dot == '.') {
        errno = 0;
        minor = strtoul(dot + 1, &dot, 10);
        if (dot == (dot - 1) || errno == ERANGE) {
            tools_logw("linux_banner: cannot parse minor version\n");
            return -1;
        }
        if (dot && *dot == '.') {
            errno = 0;
            patch = strtoul(dot + 1, &dot, 10);
            if (errno == ERANGE) patch = 0;
        }
    }

    /* clamp/assign */
    info->version.major = (uint8_t)(major & 0xff);
    info->version.minor = (uint8_t)(minor & 0xff);
    info->version.patch = (int)((patch <= 256) ? patch : 255);

    tools_logi("kernel version major: %d, minor: %d, patch: %d\n",
               info->version.major, info->version.minor, info->version.patch);

    return 0;
}

static int dump_kernel_config(kallsym_t *info, char *img, int32_t imglen)
{
    // todo:
    /*
  kernel configuration
  when CONFIG_IKCONFIG is enabled
  archived in GZip format between the magic string 'IKCFG_ST' and 'IKCFG_ED' in
  the built kernel.
  */
    tools_logw("not implemented\n");
    return 0;
}

static int find_token_table(kallsym_t *info, char *img, int32_t imglen)
{
    char nums_syms[20] = { '\0' };
    for (int32_t i = 0; i < 10; i++)
        nums_syms[i * 2] = '0' + i;

    // We just check first 10 letters, not all letters are guaranteed to appear,
    // In fact, the previous numbers may not always appear too.
    char letters_syms[20] = { '\0' };
    for (int32_t i = 0; i < 10; i++)
        letters_syms[i * 2] = 'a' + i;

    char *pos = img;
    char *num_start = NULL;
    char *imgend = img + imglen;
    for (; pos < imgend; pos = num_start + 1) {
        num_start = (char *)memmem(pos, imgend - pos, nums_syms, sizeof(nums_syms));
        if (!num_start) {
            tools_loge("find token_table error\n");
            return -1;
        }
        char *num_end = num_start + sizeof(nums_syms);
        if (!*num_end || !*(num_end + 1)) continue;

        char *letter = num_end;
        for (int32_t i = 0; letter < imgend && i < 'a' - '9' - 1; letter++) {
            if (!*letter) i++;
        }
        if (letter != (char *)memmem(letter, sizeof(letters_syms), letters_syms, sizeof(letters_syms))) continue;
        break;
    }

    // backward to start
    pos = num_start;
    for (int32_t i = 0; pos > img && i < '0' + 1; pos--) {
        if (!*pos) i++;
    }
    int32_t offset = pos + 2 - img;

    // align
    offset = align_ceil(offset, 4);

    info->kallsyms_token_table_offset = offset;

    tools_logi("kallsyms_token_table offset: 0x%08x\n", offset);

    // rebuild token_table
    pos = img + info->kallsyms_token_table_offset;
    for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
        info->kallsyms_token_table[i] = pos;
        while (*(pos++)) {
        };
    }
    // tools_logi("token table: ");
    // for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
    //   printf("%s ", info->kallsyms_token_table[i]);
    // }
    // printf("\n");
    return 0;
}

static int find_token_index(kallsym_t *info, char *img, int32_t imglen)
{
    uint16_t le_index[KSYM_TOKEN_NUMS] = { 0 };
    uint16_t be_index[KSYM_TOKEN_NUMS] = { 0 };

    int32_t start = info->kallsyms_token_table_offset;
    int32_t offset = start;

    // build kallsyms_token_index according to kallsyms_token_table
    for (int32_t i = 0; i < KSYM_TOKEN_NUMS; i++) {
        uint16_t token_index = offset - start;
        le_index[i] = u16le(token_index);
        be_index[i] = u16be(token_index);
        while (img[offset++]) {
        };
    }
    // find kallsyms_token_index
    char *lepos = (char *)memmem(img, imglen, le_index, sizeof(le_index));
    char *bepos = (char *)memmem(img, imglen, be_index, sizeof(be_index));

    if (!lepos && !bepos) {
        tools_loge("kallsyms_token_index error\n");
        return -1;
    }
    tools_logi("endian: %s\n", lepos ? "little" : "big");

    char *pos = lepos ? lepos : bepos;
    info->is_be = lepos ? 0 : 1;

    info->kallsyms_token_index_offset = pos - img;

    tools_logi("kallsyms_token_index offset: 0x%08x\n", info->kallsyms_token_index_offset);
    return 0;
}

static int get_markers_elem_size(kallsym_t *info)
{
    if (info->kallsyms_markers_elem_size) return info->kallsyms_markers_elem_size;

    int32_t elem_size = info->asm_long_size;
    if (info->version.major < 4 || (info->version.major == 4 && info->version.minor < 20))
        elem_size = info->asm_PTR_size;

    return elem_size;
}

static int get_num_syms_elem_size(kallsym_t *info)
{
    // the same as kallsyms_markers
    int32_t elem_size = info->asm_long_size;
    if (info->version.major < 4 || (info->version.major == 4 && info->version.minor < 20))
        elem_size = info->asm_PTR_size;
    return elem_size;
}

static inline int get_addresses_elem_size(kallsym_t *info)
{
    return info->asm_PTR_size;
}

static inline int get_offsets_elem_size(kallsym_t *info)
{
    /* since 4.6 offsets are 32-bit even on 64-bit machines */
    if (info->has_relative_base)
        return 4;
    return info->asm_long_size;
}

static int try_find_arm64_relo_table(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info->try_relo) return 0;

    uint64_t min_va = ELF64_KERNEL_MIN_VA;
    uint64_t max_va = ELF64_KERNEL_MAX_VA;
    uint64_t kernel_va = max_va;
    int32_t cand = 0;
    int rela_num = 0;
    while (cand < imglen - 24) {
        uint64_t r_offset = uint_unpack(img + cand, 8, info->is_be);
        uint64_t r_info = uint_unpack(img + cand + 8, 8, info->is_be);
        uint64_t r_addend = uint_unpack(img + cand + 16, 8, info->is_be);
        if ((r_offset & 0xffff000000000000) == 0xffff000000000000 && r_info == 0x403) {
            if (!(r_addend & 0xfff) && r_addend >= min_va && r_addend < kernel_va) kernel_va = r_addend;
            cand += 24;
            rela_num++;
        } else if (rela_num && !r_offset && !r_info && !r_addend) {
            cand += 24;
            rela_num++;
        } else {
            if (rela_num >= ARM64_RELO_MIN_NUM) break;
            cand += 8;
            rela_num = 0;
            kernel_va = max_va;
        }
    }

    if (info->kernel_base) {
        tools_logi("arm64 relocation kernel_va: 0x%" PRIx64 ", try: %" PRIx64 "\n", kernel_va, info->kernel_base);
        kernel_va = info->kernel_base;
    } else {
        info->kernel_base = kernel_va;
        tools_logi("arm64 relocation kernel_va: 0x%" PRIx64 "\n", kernel_va);
    }

    int32_t cand_start = cand - 24 * rela_num;
    int32_t cand_end = cand - 24;
    while (1) {
        if (*(uint64_t *)(img + cand_end) && *(uint64_t *)(img + cand_end + 8) && *(uint64_t *)(img + cand_end + 16))
            break;
        cand_end -= 24;
    }
    cand_end += 24;

    rela_num = (cand_end - cand_start) / 24;
    if (rela_num < ARM64_RELO_MIN_NUM) {
        tools_logw("can't find arm64 relocation table\n");
        return 0;
    }

    tools_logi("arm64 relocation table range: [0x%08x, 0x%08x), count: 0x%08x\n", cand_start, cand_end, rela_num);

    // apply relocations
    int32_t max_offset = imglen - 8;
    int32_t apply_num = 0;
    for (cand = cand_start; cand < cand_end; cand += 24) {
        uint64_t r_offset = uint_unpack(img + cand, 8, info->is_be);
        uint64_t r_info = uint_unpack(img + cand + 8, 8, info->is_be);
        uint64_t r_addend = uint_unpack(img + cand + 16, 8, info->is_be);
        if (!r_offset && !r_info && !r_addend) continue;
        if (r_offset <= kernel_va || r_offset >= max_va - imglen) {
            // tools_logw("warn ignore arm64 relocation r_offset: 0x%08lx at 0x%08x\n", r_offset, cand);
            continue;
        }

        int32_t offset = r_offset - kernel_va;
        if (offset < 0 || offset >= max_offset) {
            tools_logw("bad rela offset: 0x%" PRIx64 "\n", r_offset);
            info->try_relo = 0;
            return -1;
        }

        uint64_t value = uint_unpack(img + offset, 8, info->is_be);
        if (value == r_addend) continue;
        *(uint64_t *)(img + offset) = value + r_addend;
        apply_num++;
    }
    if (apply_num) apply_num--;
    tools_logi("apply 0x%08x relocation entries\n", apply_num);

    if (apply_num) info->relo_applied = 1;

#if 0
#include <stdio.h>
    FILE *frelo = fopen("./kernel.relo", "wb+");
    int w_len = fwrite(img, 1, imglen, frelo);
    tools_logi("===== write relo kernel image: %d ====\n", w_len);
    fclose(frelo);
#endif

    return 0;
}

static int32_t find_kallsyms_addresses_or_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    if (info->kallsyms_num_syms_offset == 0) {
        return -1;
    }

    // Heuristic for has_relative_base
    info->has_relative_base = 0;
    if (info->version.major > 4 || (info->version.major == 4 && info->version.minor >= 6)) {
        info->has_relative_base = 1;
    }

    int32_t pos = info->kallsyms_num_syms_offset;
    // Skip padding zeros backwards from num_syms_offset
    while (pos > 0 && img[pos - 1] == 0) {
        pos--;
    }

    if (info->has_relative_base) {
        int32_t relative_base_size = get_addresses_elem_size(info);
        int32_t offsets_table_size = info->kallsyms_num_syms * get_offsets_elem_size(info);

        pos -= relative_base_size;
        if (pos < 0)
            return -1;
        info->kallsyms_relative_base_offset = pos;
        info->relative_base = uint_unpack(img + pos, relative_base_size, info->is_be);

        /* workaround: ignore corrupted relative_base, use known kernel_base */
        /* reject the dummy 0xffffffffffffffff picked up on some Android-15 kernels */
        if ((info->relative_base & 0xffff000000000000ULL) == 0xffff000000000000ULL) {
            tools_logw("relative_base looks like a dummy value (0x%llx), ignoring\n", info->relative_base);
            info->relative_base = 0;          /* force fallback below */
        }
        if ((info->relative_base & 0xffff000000000000ULL) != 0xffff000000000000ULL || info->relative_base == 0xffffffffffffffffULL) {
            info->relative_base = info->kernel_base;
        }

        /* FIX: Set kernel_base to relative_base if not already set */
        if (info->kernel_base == 0 || info->kernel_base == 0xffffffffffffffff) {
            info->kernel_base = info->relative_base;
            tools_logi("Setting kernel_base to relative_base: 0x%016" PRIx64 "\n", info->kernel_base);
        }

        while (pos > 0 && img[pos - 1] == 0) {
            pos--;
        }

        pos -= offsets_table_size;
        if (pos < 0)
            return -1;

        info->kallsyms_offsets_offset = pos;
        tools_logi("kallsyms_offsets offset: 0x%08x\n", info->kallsyms_offsets_offset);
        tools_logi("kallsyms_relative_base offset: 0x%08x, value: 0x%llx\n", info->kallsyms_relative_base_offset,
                   info->relative_base);
    } else {
        int32_t addrs_table_size = info->kallsyms_num_syms * get_addresses_elem_size(info);
        pos -= addrs_table_size;
        if (pos < 0)
            return -1;
        info->kallsyms_addresses_offset = pos;
        tools_logi("kallsyms_addresses offset: 0x%08x\n", info->kallsyms_addresses_offset);
    }

    // count negative offsets to check for ABSOLUTE_PERCPU
    if (info->has_relative_base) {
        int negative_count = 0;
        for (int i = 0; i < info->kallsyms_num_syms; i++) {
            int64_t offset = 
                int_unpack(img + info->kallsyms_offsets_offset + i * get_offsets_elem_size(info), 
                           get_offsets_elem_size(info), info->is_be);
            if (offset < 0) {
                negative_count++;
            }
        }
        if (negative_count * 2 > info->kallsyms_num_syms) {
            info->has_absolute_percpu = 1;
            tools_logi("kallsyms_absolute_percpu detected\n");
        }
    }

    return 0;
}

static int find_approx_addresses(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t sym_num = 0;
    int32_t elem_size = info->asm_PTR_size;
    uint64_t prev_offset = 0;
    int32_t cand = 0;

    for (; cand < imglen - KSYM_MIN_NEQ_SYMS * elem_size; cand += elem_size) {
        uint64_t address = uint_unpack(img + cand, elem_size, info->is_be);
        if (!sym_num) { // first address
            if (address & 0xff) continue;
            if (elem_size == 4 && (address & 0xff800000) != 0xff800000) continue;
            if (elem_size == 8 && (address & 0xffff000000000000) != 0xffff000000000000) continue;
            prev_offset = address;
            sym_num++;
            continue;
        }
        if (address >= prev_offset) {
            prev_offset = address;
            if (sym_num++ >= KSYM_MIN_NEQ_SYMS) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }
    if (sym_num < KSYM_MIN_NEQ_SYMS) {
        tools_loge("find approximate kallsyms_addresses error\n");
        return -1;
    }

    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    int32_t approx_offset = cand;
    info->_approx_addresses_or_offsets_offset = approx_offset;

    // approximate kallsyms_addresses end
    prev_offset = 0;
    for (; cand < imglen; cand += elem_size) {
        uint64_t offset = uint_unpack(img + cand, elem_size, info->is_be);
        if (offset < prev_offset) break;
        prev_offset = offset;
    }
    // end is not include
    info->_approx_addresses_or_offsets_end = cand;
    info->has_relative_base = 0;
    int32_t approx_num_syms = (cand - approx_offset) / elem_size;
    info->_approx_addresses_or_offsets_num = approx_num_syms;
    tools_logi("approximate kallsyms_addresses range: [0x%08x, 0x%08x) "
               "count: 0x%08x\n",
               approx_offset, cand, approx_num_syms);

    //
    if (info->relo_applied) {
        tools_logw("mismatch relo applied, subsequent operations may be undefined\n");
    }

    return 0;
}

static int find_approx_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t sym_num = 0;
    int32_t elem_size = info->asm_long_size;
    int64_t prev_offset = 0;
    int32_t cand = 0;
    int32_t MAX_ZERO_OFFSET_NUM = 10;
    int32_t zero_offset_num = 0;
    for (; cand < imglen - KSYM_MIN_NEQ_SYMS * elem_size; cand += elem_size) {
        int64_t offset = int_unpack(img + cand, elem_size, info->is_be);
        if (offset == prev_offset) { // 0 offset
            continue;
        } else if (offset > prev_offset) {
            prev_offset = offset;
            if (sym_num++ >= KSYM_MIN_NEQ_SYMS) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }
    if (sym_num < KSYM_MIN_NEQ_SYMS) {
        tools_logw("find approximate kallsyms_offsets error\n");
        return -1;
    }
    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    for (;; cand -= elem_size)
        if (!int_unpack(img + cand, elem_size, info->is_be)) break;
    for (;; cand -= elem_size) {
        if (int_unpack(img + cand, elem_size, info->is_be)) break;
        if (zero_offset_num++ >= MAX_ZERO_OFFSET_NUM) break;
    }
    cand += elem_size;
    int32_t approx_offset = cand;
    info->_approx_addresses_or_offsets_offset = approx_offset;

    // approximate kallsyms_offsets end
    prev_offset = 0;
    for (; cand < imglen; cand += elem_size) {
        int64_t offset = int_unpack(img + cand, elem_size, info->is_be);
        if (offset < prev_offset) break;
        prev_offset = offset;
    }
    // the last symbol may not 4k alinged
    // end is not include
    int32_t end = cand;
    info->_approx_addresses_or_offsets_end = end;
    info->has_relative_base = 1;
    int32_t approx_num_syms = (end - approx_offset) / elem_size;
    info->_approx_addresses_or_offsets_num = approx_num_syms;
    // The real interval is contained in this approximate interval
    tools_logi("approximate kallsyms_offsets range: [0x%08x, 0x%08x) "
               "count: 0x%08x\n",
               approx_offset, end, approx_num_syms);
    /* --- last-resort base estimation --- */
    if (info->banner_num > 0) {
        uint32_t banner_off = info->linux_banner_offset[info->banner_num - 1];
        info->kernel_base = banner_off - approx_offset;   /* banner VA == banner file offset + base */
    }
    return 0;
}

static int32_t find_approx_addresses_or_offset(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info || !img || imglen <= 0) return -1;

    int rc = -1;

    if (info->version.major > 4 || (info->version.major == 4 && info->version.minor >= 6)) {
        rc = find_approx_offsets(info, img, imglen);
        if (rc == 0) {
            int32_t off = info->_approx_addresses_or_offsets_offset;
            int32_t end = info->_approx_addresses_or_offsets_end;
            int32_t num = info->_approx_addresses_or_offsets_num;
            int32_t elem_size = get_offsets_elem_size(info);

            if (off < 0 || end <= off || end > imglen) {
                tools_loge("approx_offsets: range invalid [0x%08x,0x%08x) imglen 0x%08x\n", off, end, imglen);
                rc = -1;
            } else if (num <= 0 || num > 0x200000) {
                tools_loge("approx_offsets: suspicious num_syms: 0x%08x\n", num);
                rc = -1;
            } else if ((int64_t)off + (int64_t)num * elem_size > imglen) {
                tools_loge("approx_offsets: table overruns image (off + num*elem_size > imglen)\n");
                rc = -1;
            } else {
                /* OK */
                info->has_relative_base = 1;
                return 0;
            }
        }
    }

    rc = find_approx_addresses(info, img, imglen);
    if (rc == 0) {
        int32_t off = info->_approx_addresses_or_offsets_offset;
        int32_t end = info->_approx_addresses_or_offsets_end;
        int32_t num = info->_approx_addresses_or_offsets_num;
        int32_t elem_size = get_addresses_elem_size(info);

        if (off < 0 || end <= off || end > imglen) {
            tools_loge("approx_addresses: range invalid [0x%08x,0x%08x) imglen 0x%08x\n", off, end, imglen);
            return -1;
        }
        if (num <= 0 || num > 0x200000) {
            tools_loge("approx_addresses: suspicious num_syms: 0x%08x\n", num);
            return -1;
        }
        if ((int64_t)off + (int64_t)num * elem_size > imglen) {
            tools_loge("approx_addresses: table overruns image (off + num*elem_size > imglen)\n");
            return -1;
        }

        info->has_relative_base = 0;
        return 0;
    }

    tools_loge("find_approx_addresses_or_offset: both approximate methods failed\n");
    return -1;
}

static int32_t find_addresses_or_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    int rc = find_kallsyms_addresses_or_offsets(info, img, imglen);
    if (rc == 0) {
        return 0;
    }

    tools_logw("fallback: trying old heuristic method\n");
    return find_approx_addresses_or_offset(info, img, imglen);
}

static int find_num_syms(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t pos = info->kallsyms_names_offset;
    int32_t num_syms = 0;
    while (pos < info->kallsyms_markers_offset) {
        int32_t next_pos = pos;
        uint8_t len = *(uint8_t *)(img + next_pos);
        if (len == 0)
            break;

        decompress_symbol_name(info, img, &next_pos, NULL, NULL);
        if (next_pos <= pos)
            break; // error or end
        pos = next_pos;
        num_syms++;
    }

    if (num_syms == 0) {
        tools_loge("counted 0 symbols from names table\n");
        return -1;
    }

    // Now search for num_syms before kallsyms_names_offset
    int32_t num_syms_elem_size = 4;
    int32_t search_end = info->kallsyms_names_offset;
    int32_t search_start = search_end - 4096;
    if (search_start < 0)
        search_start = 0;

    for (int32_t cand = search_end; cand >= search_start; cand--) {
        if ((cand % num_syms_elem_size) != 0)
            continue;
        if (cand + num_syms_elem_size > imglen)
            continue;
        int nsyms = (int)uint_unpack(img + cand, num_syms_elem_size, info->is_be);
        if (nsyms == num_syms) {
            info->kallsyms_num_syms = nsyms;
            info->kallsyms_num_syms_offset = cand;
            tools_logi("kallsyms_num_syms offset: 0x%08x, value: 0x%08x\n", info->kallsyms_num_syms_offset,
                       info->kallsyms_num_syms);
            return 0;
        }
    }

    tools_logw("Could not find kallsyms_num_syms\n");
    return -1;
}

static int find_markers_internal(kallsym_t *info, char *img, int32_t imglen, int32_t elem_size)
{
    int32_t cand = info->kallsyms_token_table_offset;

    int64_t marker, last_marker = imglen;
    int count = 0;
    while (cand > 0x10000) {
        marker = int_unpack(img + cand, elem_size, info->is_be);
        if (last_marker > marker) {
            count++;
            if (!marker && count > KSYM_MIN_MARKER) break;
        } else {
            count = 0;
            last_marker = imglen;
        }

        last_marker = marker;
        cand -= elem_size;
    }

    if (count < KSYM_MIN_MARKER) {
        tools_logw("find kallsyms_markers error\n");
        return -1;
    }

    int32_t marker_end = cand + count * elem_size + elem_size;
    info->kallsyms_markers_offset = cand;
    info->_marker_num = count;
    info->kallsyms_markers_elem_size = elem_size;

    tools_logi("kallsyms_markers range: [0x%08x, 0x%08x), count: 0x%08x\n", cand, marker_end, count);
    return 0;
}

static int find_markers(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t elem_size = get_markers_elem_size(info);
    int rc = find_markers_internal(info, img, imglen, elem_size);
    if (rc && elem_size == 8) {
        return find_markers_internal(info, img, imglen, 4);
    }
    return rc;
}

static int decompress_symbol_name(kallsym_t *info, char *img, int32_t *pos_to_next, char *out_type, char *out_symbol)
{
    if (!info || !img || !pos_to_next) return -1;

    int32_t pos = *pos_to_next;
    int32_t names_end = info->kallsyms_markers_offset ? info->kallsyms_markers_offset : INT32_MAX;
    
    /* Additional safety check */
    if (names_end <= 0 || names_end > INT32_MAX/2) {
        tools_logw("decompress: suspicious kallsyms_markers_offset: 0x%08x\n", names_end);
        return -1;
    }

    if (pos < 0 || pos >= names_end) {
        tools_logw("decompress: pos out of range: 0x%08x >= names_end 0x%08x\n", pos, names_end);
        return -1;
    }

    /* Ensure we can read the length byte */
    if (pos + 1 > names_end) {
        tools_logw("decompress: cannot read length byte at pos 0x%08x\n", pos);
        return -1;
    }

    uint8_t len8 = *(uint8_t *)(img + pos++);
    int32_t len = len8;
    if (len8 > 0x7F) {
        if (pos >= names_end) {
            tools_logw("decompress: cannot read extended length at pos 0x%08x\n", pos);
            return -1;
        }
        uint8_t b = *(uint8_t *)(img + pos++);
        len = (len8 & 0x7F) + (b << 7);
    }

    if (!len || len >= KSYM_SYMBOL_LEN) {
        tools_logw("decompress: invalid length: %d at pos 0x%08x\n", len, pos);
        return -1;
    }
    if (pos + len > names_end) {
        tools_logw("decompress: symbol data extends beyond bounds: pos=0x%08x len=%d names_end=0x%08x\n", 
                   pos, len, names_end);
        return -1;
    }

    char tmp[KSYM_SYMBOL_LEN];
    int tpos = 0;
    if (out_symbol) out_symbol[0] = '\0';

    for (int32_t i = 0; i < len; i++) {
        uint8_t tokidx = *(uint8_t *)(img + pos + i);
        if (tokidx >= KSYM_TOKEN_NUMS) {
            tools_logw("decompress: invalid token index %d at pos 0x%08x+%d\n", tokidx, pos, i);
            return -1;
        }
        char *token = info->kallsyms_token_table[tokidx];
        if (!token) {
            tools_logw("decompress: null token at index %d\n", tokidx);
            return -1;
        }

        if (!i) {
            if (out_type) {
                *out_type = *token;
            }
            token++;
        }
        size_t tlen = strlen(token);
        if ((int)tpos + (int)tlen >= KSYM_SYMBOL_LEN - 1) {
            tools_logw("decompress: symbol too long, truncating\n");
            break;
        }
        memcpy(tmp + tpos, token, tlen);
        tpos += tlen;
    }
    tmp[tpos] = '\0';
    if (out_symbol) strncpy(out_symbol, tmp, KSYM_SYMBOL_LEN-1);
    *pos_to_next = pos + len;
    return 0;
}

static int is_symbol_name_pos(kallsym_t *info, char *img, int32_t pos, char *symbol)
{
    int32_t len = *(uint8_t *)(img + pos++);
    if (len > 0x7F) len = (len & 0x7F) + (*(uint8_t *)(img + pos++) << 7);
    if (!len || len >= KSYM_SYMBOL_LEN) return 0;
    int32_t symidx = 0;
    for (int32_t i = 0; i < len; i++) {
        int32_t tokidx = *(uint8_t *)(img + pos + i);
        char *token = info->kallsyms_token_table[tokidx];
        if (!i) token++; // ignore symbol type
        int32_t toklen = strlen(token);
        if (strncmp(symbol + symidx, token, toklen)) break;
        symidx += toklen;
    }
    return (int32_t)strlen(symbol) == symidx;
}

static int find_names(kallsym_t *info, char *img, int32_t imglen)
{
    int32_t marker_elem_size = get_markers_elem_size(info);
    // int32_t cand = info->_approx_addresses_or_offsets_offset;
    int32_t cand = 0x4000;
    int32_t test_marker_num = -1;
    for (; cand < info->kallsyms_markers_offset; cand++) {
        int32_t pos = cand;
        test_marker_num = KSYM_FIND_NAMES_USED_MARKER; // check n * 256 symbols
        for (int32_t i = 0;; i++) {
            int32_t len = *(uint8_t *)(img + pos++);
            if (len > 0x7F) len = (len & 0x7F) + (*(uint8_t *)(img + pos++) << 7);
            if (!len || len >= KSYM_SYMBOL_LEN) break;
            pos += len;
            if (pos >= info->kallsyms_markers_offset) break;

            if (i && (i & 0xFF) == 0xFF) { // every 256 symbols
                int32_t mark_len = int_unpack(img + info->kallsyms_markers_offset + ((i >> 8) + 1) * marker_elem_size,
                                              marker_elem_size, info->is_be);
                if (pos - cand != mark_len) break;
                if (!--test_marker_num) break;
            }
        }
        if (!test_marker_num) break;
    }
    if (test_marker_num) {
        tools_loge("find kallsyms_names error\n");
        return -1;
    }
    info->kallsyms_names_offset = cand;
    tools_logi("kallsyms_names offset: 0x%08x\n", cand);

#if 0
    // print all symbol for test
    // if CONFIG_KALLSYMS=y and CONFIG_KALLSYMS_ALL=n
    // kallsyms_names table in kernel image will be truncated, and only functions exported
    int32_t pos = info->kallsyms_names_offset;
    int32_t index = 0;
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    while (pos < info->kallsyms_markers_offset) {
        memset(symbol, 0, sizeof(symbol));
        int32_t ret = decompress_symbol_name(info, img, &pos, NULL, symbol);
        if (ret) break;
        tools_logi("index: %d, %08x, symbol: %s\n", index, pos, symbol);
        index++;
    }
#endif
    return 0;
}

static int arm64_verify_pid_vnr(kallsym_t *info, char *img, int32_t offset)
{
    for (int i = 0; i < 6; i++) {
        int32_t insn_offset = offset + i * 4;
        uint32_t insn = uint_unpack(img + insn_offset, 4, 0);
        enum aarch64_insn_encoding_class enc = aarch64_get_insn_class(insn);
        if (enc == AARCH64_INSN_CLS_BR_SYS) {
            if (aarch64_insn_extract_system_reg(insn) == AARCH64_INSN_SPCLREG_SP_EL0) {
                tools_logi("pid_vnr verfied sp_el0, insn: 0x%x\n", insn);
                info->current_type = SP_EL0;
                return 0;
            }
        } else if (enc == AARCH64_INSN_CLS_DP_IMM) {
            u32 rn = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, insn);
            if (rn == AARCH64_INSN_REG_SP) {
                tools_logi("pid_vnr verfied sp, insn: 0x%x\n", insn);
                info->current_type = SP;
                return 0;
            }
        }
    }
    return -1;
}

static int correct_addresses_or_offsets_by_vectors(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info || !img || imglen <= 0) return -1;

    int32_t pos = info->kallsyms_names_offset;
    int32_t index = 0, vector_index = -1, pid_vnr_index = -1;
    char symbol[KSYM_SYMBOL_LEN];

    while (pos < info->kallsyms_markers_offset) {
        memset(symbol, 0, sizeof(symbol));
        int32_t ret = decompress_symbol_name(info, img, &pos, NULL, symbol);
        if (ret) return ret;

        if (vector_index < 0 && !strcmp(symbol, "vectors")) vector_index = index;
        if (pid_vnr_index < 0 && !strcmp(symbol, "pid_vnr")) pid_vnr_index = index;
        if (vector_index >= 0 && pid_vnr_index >= 0) {
            tools_logi("names table vector index: 0x%08x, pid_vnr index: 0x%08x\n", vector_index, pid_vnr_index);
            break;
        }
        index++;
    }

    if (vector_index < 0 || pid_vnr_index < 0) {
        tools_loge("no verify symbol in names table\n");
        return -1;
    }

    int32_t elem_size = info->has_relative_base ? get_offsets_elem_size(info) : get_addresses_elem_size(info);

    uint64_t base_cand[3] = { 0 };
    int base_cand_num = 1;
    if (!info->has_relative_base) {
        /* ensure kallsyms_addresses_offset is valid */
        if (info->kallsyms_addresses_offset < 0 || info->kallsyms_addresses_offset + elem_size > imglen) {
            tools_logw("invalid kallsyms_addresses_offset\n");
            return -1;
        }
        uint64_t base = uint_unpack(img + info->kallsyms_addresses_offset, elem_size, info->is_be);
        base_cand[0] = base;
        if (info->kernel_base) base_cand[base_cand_num++] = info->kernel_base;
        if (info->kernel_base != ELF64_KERNEL_MIN_VA) base_cand[base_cand_num++] = ELF64_KERNEL_MIN_VA;
    }

    int32_t search_start = info->has_relative_base ? info->kallsyms_offsets_offset : info->kallsyms_addresses_offset;
    if (search_start < 0 || search_start >= imglen) {
        tools_logw("invalid search_start for vectors: 0x%08x\n", search_start);
        return -1;
    }
    int32_t search_end = search_start + 4096;
    if (search_end > imglen) search_end = imglen;

    int found = 0;
    int32_t found_pos = -1;

    for (int i = 0; i < base_cand_num && !found; i++) {
        uint64_t base = base_cand[i];

        for (pos = search_start; pos + elem_size * ( (vector_index>pid_vnr_index?vector_index:pid_vnr_index) + 2) <= search_end; pos += elem_size) {
            uint64_t vector_addr = 0, vector_next_addr = 0;

            /* safe reads */
            int32_t vec_off = pos + vector_index * elem_size;
            int32_t vec_next_off = vec_off + elem_size;
            if (vec_next_off + elem_size > imglen) break;

            if (info->has_relative_base) {
                if (info->relative_base == 0) continue;
                int64_t v = int_unpack(img + vec_off, elem_size, info->is_be);
                int64_t vn = int_unpack(img + vec_next_off, elem_size, info->is_be);
                vector_addr = (uint64_t)(v + info->relative_base);
                vector_next_addr = (uint64_t)(vn + info->relative_base);
            } else {
                vector_addr = uint_unpack(img + vec_off, elem_size, info->is_be) - base;
                vector_next_addr = uint_unpack(img + vec_next_off, elem_size, info->is_be) - base;
            }

            if (vector_next_addr > vector_addr && vector_next_addr - vector_addr >= 0x600 && (vector_addr & ((1 << 11) - 1)) == 0) {
                /* compute pid_vnr addr safely */
                int32_t pid_off = pos + pid_vnr_index * elem_size;
                if (pid_off + elem_size > imglen) continue;

                uint64_t pid_vnr_addr;
                if (info->has_relative_base) {
                    int64_t rel = int_unpack(img + pid_off, elem_size, info->is_be);
                    pid_vnr_addr = (uint64_t)(rel + info->relative_base);
                } else {
                    pid_vnr_addr = uint_unpack(img + pid_off, elem_size, info->is_be);
                }

                if (info->kernel_base == 0) {
                    tools_logw("kernel_base unknown, skipping pid_vnr verification candidate\n");
                    continue;
                }

                if (pid_vnr_addr < info->kernel_base) continue;
                uint64_t pid_vnr_file_offset_u = pid_vnr_addr - info->kernel_base;
                if (pid_vnr_file_offset_u > (uint64_t)INT32_MAX) continue;
                int32_t pid_vnr_file_offset = (int32_t)pid_vnr_file_offset_u;

                /* arm64_verify_pid_vnr reads up to 6*4 bytes */
                if (pid_vnr_file_offset < 0 || (uint64_t)pid_vnr_file_offset + 6 * 4 > (uint64_t)imglen) {
                    tools_logw("pid_vnr offset out of bounds: 0x%08x\n", pid_vnr_file_offset);
                    continue;
                }

                if (!arm64_verify_pid_vnr(info, img, pid_vnr_file_offset)) {
                    tools_logi("vectors index: %d, offset: 0x%08x\n", vector_index, (int32_t)(vector_addr - info->kernel_base));
                    tools_logi("pid_vnr offset: 0x%08x\n", pid_vnr_file_offset);
                    if (!info->has_relative_base) info->kernel_base = base;
                    found = 1;
                    found_pos = pos;
                    break;
                }
            }
        }
    }

    if (!found) {
        tools_loge("can't locate vectors\n");
        return -1;
    }

    /* final checks before storing */
    if (found_pos < 0 || found_pos >= imglen) {
        tools_loge("computed kallsyms table pos invalid\n");
        return -1;
    }

    if (info->has_relative_base) {
        info->kallsyms_offsets_offset = found_pos;
        tools_logi("kallsyms_offsets offset: 0x%08x\n", info->kallsyms_offsets_offset);
    } else {
        info->kallsyms_addresses_offset = found_pos;
        tools_logi("kallsyms_addresses offset: 0x%08x\n", info->kallsyms_addresses_offset);
        tools_logi("kernel base address: 0x%08" PRIx64 "\n", info->kernel_base);
    }

    return 0;
}

static int correct_addresses_or_offsets_by_banner(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info || !img || imglen <= 0) return -1;

    /* Additional validation of key structures */
    if (info->kallsyms_num_syms <= 0 || info->kallsyms_num_syms > 0x200000) {
        tools_loge("invalid kallsyms_num_syms: 0x%x\n", info->kallsyms_num_syms);
        return -1;
    }
    
    if (info->relative_base == 0 && info->has_relative_base) {
        tools_loge("relative_base is zero but has_relative_base is set\n");
        return -1;
    }

    if (info->kallsyms_names_offset < 0 || info->kallsyms_names_offset >= imglen ||
        info->kallsyms_markers_offset <= 0 || info->kallsyms_markers_offset > imglen ||
        info->kallsyms_names_offset >= info->kallsyms_markers_offset) {
        tools_loge("invalid kallsyms names/markers offsets\n");
        return -1;
    }

    int32_t pos = info->kallsyms_names_offset;
    int32_t index = 0;
    char symbol[KSYM_SYMBOL_LEN];

    /* find linux_banner symbol index in names table with limits */
    int max_search_symbols = info->kallsyms_num_syms < 100000 ? info->kallsyms_num_syms : 100000;
    
    while (pos < info->kallsyms_markers_offset && index < max_search_symbols) {
        memset(symbol, 0, sizeof(symbol));
        
        if (pos >= imglen || pos < 0) {
            tools_loge("pos out of bounds in banner search: 0x%08x\n", pos);
            return -1;
        }
        
        int32_t old_pos = pos;
        int32_t ret = decompress_symbol_name(info, img, &pos, NULL, symbol);
        if (ret) {
            tools_loge("decompress_symbol_name failed: %d at pos 0x%08x\n", ret, old_pos);
            return ret;
        }
        
        if (pos <= old_pos || pos > info->kallsyms_markers_offset) {
            tools_loge("invalid pos advancement: old=0x%08x new=0x%08x\n", old_pos, pos);
            return -1;
        }
        
        if (!strcmp(symbol, "linux_banner")) {
            tools_logi("names table linux_banner index: 0x%08x\n", index);
            break;
        }
        index++;
    }

    if (pos >= info->kallsyms_markers_offset || index >= max_search_symbols) {
        tools_loge("no linux_banner in names table (pos=0x%08x, index=0x%08x)\n", pos, index);
        return -1;
    }

    /* Validate that the found index makes sense */
    if (index > info->kallsyms_num_syms) {
        tools_loge("linux_banner index %d exceeds num_syms %d\n", index, info->kallsyms_num_syms);
        return -1;
    }

    info->symbol_banner_idx = -1;

    int32_t elem_size = info->has_relative_base ? get_offsets_elem_size(info) : get_addresses_elem_size(info);
    if (elem_size <= 0 || elem_size > 8) {
        tools_loge("invalid elem_size: %d\n", elem_size);
        return -1;
    }

    int32_t search_start = info->has_relative_base ? info->kallsyms_offsets_offset : info->kallsyms_addresses_offset;
    if (search_start < 0 || search_start >= imglen) {
        tools_logw("invalid search_start in banner method: 0x%08x\n", search_start);
        return -1;
    }

    if (info->banner_num <= 0) {
        tools_logw("no linux_banner offsets recorded (banner_num=%d)\n", info->banner_num);
        return -1;
    }

    /* Try each found banner with more conservative search range */
    for (int i = 0; i < info->banner_num; i++) {
        int32_t target_file_offset = info->linux_banner_offset[i];
        if (target_file_offset < 0 || target_file_offset >= imglen) {
            tools_logw("linux_banner file offset out of range: 0x%08x\n", target_file_offset);
            continue;
        }

        int32_t start = search_start >= 128 ? search_start - 128 : 0;
        int32_t end = search_start + 128;
        if (end > imglen) end = imglen;

        /* Limit the table access to prevent overflow */
        int64_t max_safe_pos = (int64_t)imglen - (int64_t)elem_size * (index + 2);
        if (max_safe_pos < 0) {
            tools_logw("image too small for banner table access\n");
            continue;
        }
        if (end > (int32_t)max_safe_pos) {
            end = (int32_t)max_safe_pos;
        }

        for (pos = start; pos <= end && pos + (int64_t)elem_size * (index + 1) <= imglen; pos += elem_size) {
            int32_t field_off = pos + (int64_t)index * elem_size;
            if (field_off < 0 || field_off + elem_size > imglen) break;

            uint64_t banner_addr = 0;
            if (info->has_relative_base) {
                int64_t banner_rel_offset = int_unpack(img + field_off, elem_size, info->is_be);
                
                /* Sanity check the relative offset */
                if (banner_rel_offset > 0x7fffffff || banner_rel_offset < -0x7fffffff) {
                    continue; /* Skip obviously bogus values */
                }
                
                if (info->has_absolute_percpu && banner_rel_offset < 0) {
                    if (banner_rel_offset == INT64_MIN) continue;
                    banner_addr = (uint64_t)(info->relative_base - 1 - banner_rel_offset);
                } else {
                    banner_addr = (uint64_t)(banner_rel_offset + info->relative_base);
                }
            } else {
                banner_addr = uint_unpack(img + field_off, elem_size, info->is_be);
            }

            if (banner_addr == 0) continue;

            /* Kernel base estimation and validation */
            if (info->kernel_base == 0) {
                if ((uint64_t)target_file_offset > banner_addr) continue;
                uint64_t guessed = banner_addr - (uint32_t)target_file_offset;
                if (guessed == 0 || guessed > 0xffffffffc0000000ULL) continue;
                info->kernel_base = guessed;
                tools_logi("Guessed kernel_base = 0x%016" PRIx64 "\n", info->kernel_base);
            }

            if (banner_addr < info->kernel_base) continue;
            uint64_t banner_file_offset_u = banner_addr - info->kernel_base;
            if (banner_file_offset_u > (uint64_t)INT32_MAX) continue;
            int32_t banner_file_offset = (int32_t)banner_file_offset_u;

            if (banner_file_offset == target_file_offset) {
                if (info->has_relative_base) {
                    info->kallsyms_offsets_offset = pos;
                } else {
                    info->kallsyms_addresses_offset = pos;
                }
                info->symbol_banner_idx = i;

                /* --- re-estimate kernel base  --- */
                info->kernel_base = banner_addr - target_file_offset;

                /* sanity check: banner must map back to the same file offset */
                uint64_t check = info->kernel_base + target_file_offset;
                if (check != banner_addr) continue;          /* wrong table – try next candidate */

                tools_logi("linux_banner index: %d, found correct table offset at 0x%08x\n", i, pos);
                return 0; /* Success */
            }
        }
    }

    tools_loge("correct address or offsets error\n");
    return -1;
}

static int correct_addresses_or_offsets(kallsym_t *info, char *img, int32_t imglen)
{
    if (!info || !img || imglen <= 0) return -1;

    int rc;

    /* Android-15 kernels sometimes store a dummy value – skip broken paths */
    if (info->has_relative_base &&
        info->relative_base == 0xffffffffffffffffULL)
        goto fallback;

    rc = correct_addresses_or_offsets_by_banner(info, img, imglen);
    if (rc == 0) return 0;

    tools_logw("banner method failed, trying vectors method\n");

    rc = correct_addresses_or_offsets_by_vectors(info, img, imglen);
    if (rc == 0) return 0;

fallback:
    tools_logw("vectors method failed, fallback to heuristic approx method\n");

    rc = find_approx_addresses_or_offset(info, img, imglen);
    if (rc == 0) {
        tools_logi("approximate kallsyms_offsets range: [0x%08x, 0x%08x) count: 0x%08x\n",
                   info->_approx_addresses_or_offsets_offset, info->_approx_addresses_or_offsets_end,
                   info->_approx_addresses_or_offsets_num);
        if (info->kernel_base == 0 || info->kernel_base == 0xffffffffffffffff) {
            info->kernel_base = 0xffffc00080000000ULL; // Safe fallback for Android15 ARM64
            tools_logw("fallback: using default Android15 ARM64 kernel_base: 0x%llx\n", info->kernel_base);
        }
    }
    return rc;
}

void init_arm64_kallsym_t(kallsym_t *info)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = 1;
    info->asm_long_size = 4;
    info->asm_PTR_size = 8;
    info->try_relo = 1;
    /* Initialize kernel_base to 0, not to -1 */
    info->kernel_base = 0;
}

void init_not_tested_arch_kallsym_t(kallsym_t *info, int32_t is_64)
{
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = is_64;
    info->asm_long_size = 4;
    info->asm_PTR_size = 4;
    info->try_relo = 0;
    if (is_64) info->asm_PTR_size = 8;
    /* Initialize kernel_base to 0, not to -1 */
    info->kernel_base = 0;
}

static int retry_relo(kallsym_t *info, char *img, int32_t imglen)
{
    int rc = -1;
    static int32_t (*funcs[])(kallsym_t *, char *, int32_t) = { try_find_arm64_relo_table, find_markers, find_names,
                                                                  find_num_syms, find_kallsyms_addresses_or_offsets,
                                                                  correct_addresses_or_offsets };

    for (int i = 0; i < (int)(sizeof(funcs) / sizeof(funcs[0])); i++) {
        if ((rc = funcs[i](info, img, imglen))) break;
    }

    return rc;
}

/*
R kallsyms_offsets
R kallsyms_relative_base
R kallsyms_num_syms
R kallsyms_names
R kallsyms_markers
R kallsyms_token_table
R kallsyms_token_index
*/
int analyze_kallsym_info(kallsym_t *info, char *img, int32_t imglen, enum arch_type arch, int32_t is_64)
{
    if (!info || !img || imglen <= 0) {
        tools_loge("analyze_kallsym_info: invalid parameters\n");
        return -1;
    }
    
    memset(info, 0, sizeof(kallsym_t));
    info->is_64 = is_64;
    info->asm_long_size = 4;
    info->asm_PTR_size = 4;
    if (arch == ARM64) info->try_relo = 1;
    if (is_64) info->asm_PTR_size = 8;
    /* Explicitly initialize kernel_base to 0 */
    info->kernel_base = 0;

    int rc = -1;
    static int32_t (*base_funcs[])(kallsym_t *, char *, int32_t) = {
        find_linux_banner,
        find_token_table,
        find_token_index,
    };
    for (int i = 0; i < (int)(sizeof(base_funcs) / sizeof(base_funcs[0])); i++) {
        if ((rc = base_funcs[i](info, img, imglen))) {
            tools_loge("base function %d failed with rc=%d\n", i, rc);
            return rc;
        }
    }

    char *copied_img = (char *)malloc(imglen);
    if (!copied_img) {
        tools_loge("analyze_kallsym_info: failed to allocate memory\n");
        return -1;
    }
    memcpy(copied_img, img, imglen);

    // 1st
    rc = retry_relo(info, copied_img, imglen);
    if (!rc) goto out;

    // 2nd
    if (!info->try_relo) {
        memcpy(copied_img, img, imglen);
        rc = retry_relo(info, copied_img, imglen);
        if (!rc) goto out;
    }

    // 3rd
    if (info->kernel_base != ELF64_KERNEL_MIN_VA) {
        info->kernel_base = ELF64_KERNEL_MIN_VA;
        memcpy(copied_img, img, imglen);
        rc = retry_relo(info, copied_img, imglen);
    }

out:
    if (!rc) {
        memcpy(img, copied_img, imglen);

        /* if we succeeded with the approximate table, ignore the (possibly
           wrong) exact tables from now on */
        if (info->_approx_addresses_or_offsets_offset >= 0) {
            info->kallsyms_addresses_offset = -1;
            info->kallsyms_offsets_offset   = -1;
        }
        
        /* Final validation and fix of kernel_base */
        if (info->has_relative_base && (info->kernel_base == 0 || info->kernel_base == 0xffffffffffffffff)) {
            if (info->relative_base != 0) {
                info->kernel_base = info->relative_base;
                tools_logi("Final fix: set kernel_base to relative_base: 0x%016" PRIx64 "\n", info->kernel_base);
            }
        }
    }
    free(copied_img);
    return rc;
}

int32_t get_symbol_index_offset(kallsym_t *info, char *img, int32_t index)
{
    if (!info || !img) {
        tools_loge("get_symbol_index_offset: null parameters\n");
        return -1;
    }

    if (info->_approx_addresses_or_offsets_offset >= 0) {
        int32_t elem = get_offsets_elem_size(info);
        int64_t off = info->_approx_addresses_or_offsets_offset + (int64_t)index * elem;
        if (off < 0 || off + elem > info->_approx_addresses_or_offsets_end)
            return -1;
        return (int32_t)int_unpack(img + off, elem, info->is_be);
    }
    
    if (index < 0 || index >= info->kallsyms_num_syms) {
        tools_loge("get_symbol_index_offset: index %d out of range [0, %d)\n", 
                   index, info->kallsyms_num_syms);
        return -1;
    }
    
    int32_t elem_size;
    int32_t pos;
    if (info->has_relative_base) {
        elem_size = get_offsets_elem_size(info);
        pos = info->kallsyms_offsets_offset;
    } else {
        elem_size = get_addresses_elem_size(info);
        pos = info->kallsyms_addresses_offset;
    }
    
    if (elem_size <= 0 || elem_size > 8) {
        tools_loge("get_symbol_index_offset: invalid elem_size: %d\n", elem_size);
        return -1;
    }
    
    /* Check for multiplication overflow */
    if (index > 0 && elem_size > INT32_MAX / index) {
        tools_loge("get_symbol_index_offset: index * elem_size would overflow\n");
        return -1;
    }
    
    int32_t table_offset = pos + (int64_t)index * elem_size;
    if (table_offset < 0 || table_offset < pos) {
        tools_loge("get_symbol_index_offset: table offset overflow: pos=0x%x index=%d elem_size=%d\n", 
                   pos, index, elem_size);
        return -1;
    }
    
    if (info->has_relative_base) {
        /* Fix kernel_base if it's invalid */
        if (info->kernel_base == 0 || info->kernel_base == 0xffffffffffffffff) {
            if (info->relative_base != 0) {
                info->kernel_base = info->relative_base;
                tools_logi("Fixed kernel_base to relative_base: 0x%016" PRIx64 "\n", info->kernel_base);
            } else {
                tools_loge("get_symbol_index_offset: both kernel_base and relative_base are invalid\n");
                return -1;
            }
        }
        
        int64_t offset = int_unpack(img + table_offset, elem_size, info->is_be);
        
        if (info->has_absolute_percpu && offset < 0) {
            /* Handle absolute percpu case: relative_base - 1 - offset */
            if (offset == INT64_MIN) {
                tools_loge("get_symbol_index_offset: offset is INT64_MIN, cannot handle safely\n");
                return -1;
            }
            
            uint64_t result = info->relative_base - 1 - offset;
            if (result > INT32_MAX) {
                tools_loge("get_symbol_index_offset: absolute_percpu result too large: 0x%llx\n", 
                           (long long)result);
                return -1;
            }
            return (int32_t)result;
        } else {
            /* Normal relative case: offset + relative_base - kernel_base */
            /* Since kernel_base == relative_base, this simplifies to just offset */
            if (info->kernel_base == info->relative_base) {
                /* Simplified calculation when kernel_base == relative_base */
                if (offset < 0 || offset > INT32_MAX) {
                    tools_loge("get_symbol_index_offset: offset out of range when kb==rb: %lld\n", 
                               (long long)offset);
                    return -1;
                }
                return (int32_t)offset;
            } else {
                /* Full calculation */
                int64_t temp_result = offset + info->relative_base;
                int64_t final_result = temp_result - info->kernel_base;
                
                if (final_result < 0 || final_result > INT32_MAX) {
                    tools_loge("get_symbol_index_offset: final result out of range: %lld\n", 
                               (long long)final_result);
                    return -1;
                }
                return (int32_t)final_result;
            }
        }
    } else {
        /* Absolute address case */
        uint64_t target = uint_unpack(img + table_offset, elem_size, info->is_be);
        if (target < info->kernel_base) {
            tools_loge("get_symbol_index_offset: target address 0x%llx less than kernel_base 0x%llx\n", 
                       (long long)target, (long long)info->kernel_base);
            return -1;
        }
        uint64_t result = target - info->kernel_base;
        if (result > INT32_MAX) {
            tools_loge("get_symbol_index_offset: absolute result too large: 0x%llx\n", (long long)result);
            return -1;
        }
        return (int32_t)result;
    }
}

int get_symbol_offset_and_size(kallsym_t *info, char *img, char *symbol, int32_t *size)
{
    char decomp[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    *size = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(decomp, 0, sizeof(decomp));
        decompress_symbol_name(info, img, &pos, &type, decomp);
        if (!strcmp(decomp, symbol)) {
            int32_t offset = get_symbol_index_offset(info, img, i);
            int32_t next_offset = offset;
            for (int32_t j = i + 1; j < info->kallsyms_num_syms; j++) {
                next_offset = get_symbol_index_offset(info, img, j);
                if (next_offset != offset) {
                    *size = next_offset - offset;
                    break;
                }
            }
            tools_logi("%s: type: %c, offset: 0x%08x, size: 0x%x\n", symbol, type, offset, *size);
            return offset;
        }
    }
    tools_logw("no symbol: %s\n", symbol);
    return -1;
}

int get_symbol_offset(kallsym_t *info, char *img, char *symbol)
{
    if (!info || !img || !symbol) {
        tools_logw("get_symbol_offset: null parameters\n");
        return -1;
    }
    
    char decomp[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    int32_t pos = info->kallsyms_names_offset;
    
    /* Validate initial position */
    if (pos < 0 || pos >= info->kallsyms_markers_offset) {
        tools_logw("get_symbol_offset: invalid names offset\n");
        return -1;
    }
    
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(decomp, 0, sizeof(decomp));
        int32_t old_pos = pos;
        int ret = decompress_symbol_name(info, img, &pos, &type, decomp);
        if (ret) {
            tools_logw("get_symbol_offset: decompress failed at index %d, pos 0x%08x\n", i, old_pos);
            return -1;
        }
        
        /* Ensure pos advanced */
        if (pos <= old_pos) {
            tools_logw("get_symbol_offset: pos did not advance at index %d\n", i);
            return -1;
        }
        
        if (!strcmp(decomp, symbol)) {
            int32_t offset = get_symbol_index_offset(info, img, i);
            if (offset >= 0) {
                tools_logi("%s: type: %c, offset: 0x%08x\n", symbol, type, offset);
            }
            return offset;
        }
        
        /* Safety break if we've gone too far */
        if (pos >= info->kallsyms_markers_offset) {
            tools_logw("get_symbol_offset: reached markers before finding symbol\n");
            break;
        }
    }
    tools_logw("no symbol: %s\n", symbol);
    return -1;
}

int dump_all_symbols(kallsym_t *info, char *img)
{
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(symbol, 0, sizeof(symbol));
        decompress_symbol_name(info, img, &pos, &type, symbol);
        int32_t offset = get_symbol_index_offset(info, img, i);
        fprintf(stdout, "0x%08x %c %s\n", offset, type, symbol);
    }
    return 0;
}
int decompress_data(const unsigned char *compressed_data, size_t compressed_size)
{
    FILE *temp = fopen("temp.gz", "wb");
    if (!temp) {
        fprintf(stderr, "Failed to create temp file\n");
        return -1;
    }

    fwrite(compressed_data, 1, compressed_size, temp);
    fclose(temp);

    gzFile gz = gzopen("temp.gz", "rb");
    if (!gz) {
        fprintf(stderr, "Failed to open temp file for decompression\n");
        return -1;
    }

    char buffer[1024];
    int bytes_read;
    while ((bytes_read = gzread(gz, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes_read, stdout);
    }

    gzclose(gz);
    return 0;
}

int dump_all_ikconfig(char *img, int32_t imglen)
{
    char *pos_start = memmem(img, imglen, IKCFG_ST, strlen(IKCFG_ST));
    if (pos_start == NULL) {
        fprintf(stderr, "Cannot find kernel config start (IKCFG_ST).\n");
        return 1;
    }
    size_t kcfg_start = pos_start - img + 8;

    // 查找 "IKCFG_ED"
    char *pos_end = memmem(img, imglen, IKCFG_ED, strlen(IKCFG_ED));
    if (pos_end == NULL) {
        fprintf(stderr, "Cannot find kernel config end (IKCFG_ED).\n");
        return 1;
    }
    size_t kcfg_end = pos_end - img - 1;
    size_t kcfg_bytes = kcfg_end - kcfg_start + 1;

    printf("Kernel config start: %zu, end: %zu, bytes: %zu\n", kcfg_start, kcfg_end, kcfg_bytes);

    unsigned char *extracted_data = (unsigned char *)malloc(kcfg_bytes);
    if (!extracted_data) {
        fprintf(stderr, "Memory allocation for extracted data failed.\n");
        return 1;
    }

    memcpy(extracted_data, img + kcfg_start, kcfg_bytes);

    int ret = decompress_data(extracted_data, kcfg_bytes);

    free(extracted_data);

    return 0;
}

int on_each_symbol(kallsym_t *info, char *img, void *userdata,
                   int32_t (*fn)(int32_t index, char type, const char *symbol, int32_t offset, void *userdata))
{
    char symbol[KSYM_SYMBOL_LEN] = { '\0' };
    char type = 0;
    char **tokens = info->kallsyms_token_table;
    int32_t pos = info->kallsyms_names_offset;
    for (int32_t i = 0; i < info->kallsyms_num_syms; i++) {
        memset(symbol, 0, sizeof(symbol));
        decompress_symbol_name(info, img, &pos, &type, symbol);
        int32_t offset = get_symbol_index_offset(info, img, i);
        int rc = fn(i, type, symbol, offset, userdata);
        if (rc) return rc;
    }
    return 0;
}
