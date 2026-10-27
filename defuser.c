#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

/* ---- 通用辅助：32 位循环移位 ---- */

static uint32_t rol32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t ror32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

/* ================= 第 1 关 =================
 * phase_01 只读 1 个整数，与 p1_compute(challenge) 的返回值比较。
 * p1_compute 分析：
 *   - 记 L = challenge 低 32 位，H = 高 32 位，M = (challenge >> 16) 的低 32 位；
 *   - 依次调用三个 step 函数（传参、返回值都是 32 位）：
 *       step0(edi=L, esi=H)：      eax = 3*rdi + rsi（lea (%rdi,%rdi,2)），再 eax ^= 0x3956；
 *       step1(edi=H, esi=M)：      eax = rdi + 8*rsi（lea (%rdi,%rsi,8)），再 eax ^= 0x6082；
 *       step2(edi=step1结果, esi=L)：eax = (esi ^ 0xbb05) + 8*rdi（lea (%rsi,%rdi,8)）；
 *   - p1_compute 最后把 step0 的结果（保留在 ecx 里）与 step2 的结果 xor，作为返回值。
 * 所有运算都是 uint32_t（无符号回绕模 2^32）。
 */
int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    uint32_t L = (uint32_t)challenge;
    uint32_t H = (uint32_t)(challenge >> 32);
    uint32_t M = (uint32_t)(challenge >> 16);
    uint32_t s0 = (UINT32_C(3) * L + H) ^ UINT32_C(0x3956);
    uint32_t s1 = (H + UINT32_C(8) * M) ^ UINT32_C(0x6082);
    values[0] = ((L ^ UINT32_C(0xbb05)) + UINT32_C(8) * s1) ^ s0;
    size_t count = 1;
    return write_answer(out, cap, values, count);
}

/* ================= 第 2 关 =================
 * phase_02 检查 6 个整数 v0..v5。
 *   - 循环外先检查 v0：challenge 右移 1 位（shr $1）、& 31（and $0x1f）、
 *     乘 3（lea (%rax,%rax,2)），与 v0 比较；
 *   - 循环（rdx = i 从 1 到 5）：
 *       ecx = 23 + i（lea 0x17(%rdx),%ecx）作为移位量；
 *       rax = challenge >> ecx，再 & 15（and $0xf），再 + 4（add $0x4）；
 *       ecx = 5 * 上一个值（lea (%rsi,%rsi,4)），再减 i（sub %edx,%ecx）；
 *       期望值 = 前者的 rax 与 ecx 异或（xor %ecx,%eax），与 v[i] 比较；
 *   - 上一个值就是 v[i-1]（esi 每轮从 -0x40(%rbp,%rdx,4) 重新载入 v[i]）。
 * 全部按 uint32_t 回绕。
 */
int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    values[0] = (uint32_t)((challenge >> 1) & UINT64_C(31)) * UINT32_C(3);
    for (unsigned i = 1; i <= 5; ++i) {
        uint32_t part = (uint32_t)(((challenge >> (23 + i)) & UINT64_C(15)) + 4);
        values[i] = part ^ ((UINT32_C(5) * values[i - 1]) - i);
    }
    size_t count = 6;
    return write_answer(out, cap, values, count);
}

/* ================= 第 3 关 =================
 * phase_03 检查 2 个整数 v0、v1。
 *   - v0 必须等于 challenge & 7（and $0x7,%edi），也就是 0..7 之间的数；
 *   - op = v0 查跳转表（jmp *0x405820(,%rax,8)），8 个表项对应 case 编号依次为
 *     [3, 1, 7, 5, 2, 0, 4, 6]（可用 GDB x/8gx 0x405820 查看）；
 *   - 传给 case 的值 value = (challenge >> 3) ^ (challenge >> 32)（取低 32 位）；
 *   - 8 个 case 函数（输入 edi=value，输出 eax，均 32 位）：
 *       case0: (4*v) ^ 0xa3c0        case1: (v ^ 0xf6ee) + (v >> 2)
 *       case2: 3*v + 0xa84d          case3: 5*v + 0x19636
 *       case4: (2*v) ^ 0x8fd7        case5: (v ^ 0x6d) + (v >> 1)
 *       case6: 3*v + 0x678a          case7: 5*v + 0x457bd
 *   - v1 = 对应 case 的返回值。
 */
static uint32_t p3_case(unsigned c, uint32_t v) {
    switch (c) {
        case 0: return (UINT32_C(4) * v) ^ UINT32_C(0xa3c0);
        case 1: return (v ^ UINT32_C(0xf6ee)) + (v >> 2);
        case 2: return UINT32_C(3) * v + UINT32_C(0xa84d);
        case 3: return UINT32_C(5) * v + UINT32_C(0x19636);
        case 4: return (UINT32_C(2) * v) ^ UINT32_C(0x8fd7);
        case 5: return (v ^ UINT32_C(0x6d)) + (v >> 1);
        case 6: return UINT32_C(3) * v + UINT32_C(0x678a);
        default: return UINT32_C(5) * v + UINT32_C(0x457bd);
    }
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    static const unsigned p3_perm[8] = {3, 1, 7, 5, 2, 0, 4, 6};
    uint32_t op = (uint32_t)(challenge & UINT64_C(7));
    uint32_t value = (uint32_t)((challenge >> 3) ^ (challenge >> 32));
    values[0] = op;
    values[1] = p3_case(p3_perm[op], value);
    size_t count = 2;
    return write_answer(out, cap, values, count);
}

/* ================= 第 4 关 =================
 * p4_walk(target, low, high, key)：
 *   mid = low + (high - low) / 2；
 *   target == mid            -> 返回 (mid + 0xa5) ^ key；
 *   target <  mid            -> 返回 ((5 * 递归(target, low, mid-1, key)) ^ (mid + key)) ^ 0x9；
 *   target >  mid            -> 返回 ((5 * 递归(target, mid+1, high, key)) ^ (mid + key)) ^ 0x14；
 * 全部 32 位无符号运算；入口参数：target = challenge & 0x7f，low = 0，
 * high = 0x7f，key = (challenge >> 7) ^ (challenge >> 32)（低 32 位）。
 */
static uint32_t p4_walk(uint32_t target, uint32_t low, uint32_t high, uint32_t key) {
    uint32_t mid = low + (high - low) / 2u;
    if (target == mid) {
        return (mid + UINT32_C(0xa5)) ^ key;
    }
    uint32_t mid_key = mid + key;
    if (target < mid) {
        return ((p4_walk(target, low, mid - 1u, key) * UINT32_C(5)) ^ mid_key) ^ UINT32_C(0x9);
    }
    return ((p4_walk(target, mid + 1u, high, key) * UINT32_C(5)) ^ mid_key) ^ UINT32_C(0x14);
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    values[0] = p4_walk((uint32_t)(challenge & UINT64_C(0x7f)), 0u, 0x7fu,
                        (uint32_t)((challenge >> 7) ^ (challenge >> 32)));
    size_t count = 1;
    return write_answer(out, cap, values, count);
}

/* ================= 第 5 关 =================
 * p5_traverse(challenge, &slot)：
 *   起点 head = p5_heads[challenge & 7]（8 个表头，见 .rodata 0x405b60）；
 *   步数 steps = (challenge >> 3) & 3；
 *   acc = ((((challenge >> 6) ^ (challenge >> 32)) ^ head->tag) ^ 0x34fa) + head->val；
 *   slot = head->val；
 *   重复 steps 次：node = node->next；acc = (acc ^ node->tag) + node->val；slot = node->val；
 *   返回 acc；关卡比较 v0 == acc 且 v1 == slot。
 * 节点数据（13 个，每项 16 字节：next / val / tag）取自本炸弹 .rodata 0x405ba0。
 */
typedef struct P5Node P5Node;
struct P5Node {
    const P5Node *next;
    uint32_t val;
    uint32_t tag;
};

static const P5Node p5_nodes[13] = {
    { &p5_nodes[9],  UINT32_C(0x632), UINT32_C(0xb295) }, /* 0x405ba0 */
    { &p5_nodes[6],  UINT32_C(0x026), UINT32_C(0xdfb5) }, /* 0x405bb0 */
    { &p5_nodes[7],  UINT32_C(0x340), UINT32_C(0xc887) }, /* 0x405bc0 */
    { &p5_nodes[1],  UINT32_C(0xa62), UINT32_C(0x8783) }, /* 0x405bd0 */
    { &p5_nodes[10], UINT32_C(0x756), UINT32_C(0x463d) }, /* 0x405be0 */
    { &p5_nodes[3],  UINT32_C(0xb31), UINT32_C(0x8d77) }, /* 0x405bf0 */
    { NULL,          UINT32_C(0x453), UINT32_C(0x6073) }, /* 0x405c00 */
    { &p5_nodes[0],  UINT32_C(0x121), UINT32_C(0x179f) }, /* 0x405c10 */
    { &p5_nodes[4],  UINT32_C(0x96a), UINT32_C(0x75a6) }, /* 0x405c20 */
    { &p5_nodes[5],  UINT32_C(0x548), UINT32_C(0x3eb5) }, /* 0x405c30 */
    { &p5_nodes[11], UINT32_C(0x814), UINT32_C(0xd755) }, /* 0x405c40 */
    { &p5_nodes[2],  UINT32_C(0x236), UINT32_C(0xc76e) }, /* 0x405c50 */
};

static const P5Node *const p5_heads[8] = {
    &p5_nodes[8],  &p5_nodes[4],  &p5_nodes[10], &p5_nodes[11],
    &p5_nodes[2],  &p5_nodes[7],  &p5_nodes[0],  &p5_nodes[9],
};

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    const P5Node *node = p5_heads[challenge & UINT64_C(7)];
    uint32_t acc = ((uint32_t)((challenge >> 6) ^ (challenge >> 32)) ^ node->tag) ^ UINT32_C(0x34fa);
    acc += node->val;
    uint32_t last = node->val;
    unsigned steps = (unsigned)((challenge >> 3) & UINT64_C(3));
    for (unsigned i = 0; i < steps; ++i) {
        node = node->next;
        acc = (acc ^ node->tag) + node->val;
        last = node->val;
    }
    uint32_t values[MAX_FIELDS] = {0};
    values[0] = acc;
    values[1] = last;
    size_t count = 2;
    return write_answer(out, cap, values, count);
}

/* ================= 第 6 关 =================
 * p6_dispatch(challenge)：
 *   x = (challenge >> 6) ^ (challenge >> 32)（低 32 位）；
 *   y = table[challenge & 7](x) ^ 0x1b8c；
 *   返回值 = table[(challenge >> 3) & 7](y) + 0x4287；
 * 函数表 table = [op2, op4, op1, op5, op0, op5, op0, op3]（.rodata 0x405e00）。
 */
typedef uint32_t (*P6Op)(uint32_t);

static uint32_t p6_op0(uint32_t v) { return ((v >> 1) ^ v) + UINT32_C(0x65a2); }
static uint32_t p6_op1(uint32_t v) { return rol32(v, 5) ^ UINT32_C(0x6652); }
static uint32_t p6_op2(uint32_t v) { return (v ^ UINT32_C(0x84f9)) + (v << 7); }
static uint32_t p6_op3(uint32_t v) { return ror32(v, 5); }
static uint32_t p6_op4(uint32_t v) { return (v + UINT32_C(0xe2af)) ^ (v >> 2); }
static uint32_t p6_op5(uint32_t v) { return ((v << 7) + UINT32_C(0xb6f6)) ^ (v * UINT32_C(3)); }

static const P6Op p6_ops[8] = {
    p6_op2, p6_op4, p6_op1, p6_op5, p6_op0, p6_op5, p6_op0, p6_op3,
};

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t x = (uint32_t)((challenge >> 6) ^ (challenge >> 32));
    uint32_t y = p6_ops[challenge & UINT64_C(7)](x) ^ UINT32_C(0x1b8c);
    uint32_t values[MAX_FIELDS] = {0};
    values[0] = p6_ops[(challenge >> 3) & UINT64_C(7)](y) + UINT32_C(0x4287);
    size_t count = 1;
    return write_answer(out, cap, values, count);
}

/* ================= Honor =================
 * 第 7 行格式：前 32 个字符任意（用空格填充），第 33~36 字节必须是 "OPEN"，
 * 之后是 3 个空格分隔的 u32 整数 w0 w1 w2（secret_phase 的检查）。
 * 记 cL/cH 为 challenge 的低/高 32 位，kL/kH 为 context 的低/高 32 位：
 *   w0 = context & 3；
 *   t1 = cH ^ cL；t2 = kH ^ kL；
 *   w1 = secret_mix(t1 ^ t2) ^ ((w0 * 0x8c4d) ^ (uint32_t)(context >> 16))；
 *   w2 = w1 ^ ((t2 + w0 + 0xed8e) + (t1 >> 7))；   // 注意这里用 t2 而不是 kH！
 *   secret_mix(x) = (rol(x,7) + 0x8c4d) ^ 0xed8e。
 * 全部 32 位无符号回绕。
 */
int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t w0 = (uint32_t)(context & UINT64_C(3));
    uint32_t cL = (uint32_t)challenge;
    uint32_t cH = (uint32_t)(challenge >> 32);
    uint32_t kL = (uint32_t)context;
    uint32_t kH = (uint32_t)(context >> 32);
    uint32_t t1 = cH ^ cL;
    uint32_t t2 = kH ^ kL;
    uint32_t mix = (rol32(t1 ^ t2, 7) + UINT32_C(0x8c4d)) ^ UINT32_C(0xed8e);
    uint32_t w1 = mix ^ ((w0 * UINT32_C(0x8c4d)) ^ (uint32_t)(context >> 16));
    uint32_t w2 = w1 ^ ((t2 + w0 + UINT32_C(0xed8e)) + (t1 >> 7));
    int size = snprintf(out, cap, "                                OPEN %" PRIu32 " %" PRIu32 " %" PRIu32,
                        w0, w1, w2);
    return size < 0 || (size_t)size >= cap;
}
