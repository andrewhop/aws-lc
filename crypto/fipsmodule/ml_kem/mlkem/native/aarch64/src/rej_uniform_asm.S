/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/*************************************************
 * Name:        mlk_rej_uniform_asm
 *
 * Description: Run rejection sampling on uniform random bytes to generate
 *              uniform random integers mod q
 *
 * Arguments:   - int16_t *r:          pointer to output buffer of MLKEM_N
 *                                     16-bit coefficients.
 *              - const uint8_t *buf:  pointer to input buffer
 *                                     (assumed to be uniform random bytes)
 *              - unsigned buflen:     length of input buffer in bytes.
 *                                     Must be a multiple of 24.
 *
 * Returns number of sampled 16-bit integers (at most MLKEM_N).
 **************************************************/
#include "_internal_s2n_bignum.h"

/*
 * WARNING: This file is auto-derived from the mlkem-native source file
 *   dev/aarch64_opt/src/rej_uniform_asm.S using scripts/simpasm. Do not modify it directly.
 */


.text
.balign 4
        S2N_BN_SYM_VISIBILITY_DIRECTIVE(mlkem_rej_uniform_asm)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(mlkem_rej_uniform_asm)
S2N_BN_SYMBOL(mlkem_rej_uniform_asm):

        sub	sp, sp, #0x240
        mov	x7, #0x1                // =1
        movk	x7, #0x2, lsl #16
        movk	x7, #0x4, lsl #32
        movk	x7, #0x8, lsl #48
        mov	v31.d[0], x7
        mov	x7, #0x10               // =16
        movk	x7, #0x20, lsl #16
        movk	x7, #0x40, lsl #32
        movk	x7, #0x80, lsl #48
        mov	v31.d[1], x7
        mov	w11, #0xd01             // =3329
        dup	v30.8h, w11
        mov	x8, sp
        mov	x7, x8
        mov	x11, #0x0               // =0
        eor	v16.16b, v16.16b, v16.16b

rej_uniform_initial_zero:
        str	q16, [x7], #0x40
        stur	q16, [x7, #-0x30]
        stur	q16, [x7, #-0x20]
        stur	q16, [x7, #-0x10]
        add	x11, x11, #0x20
        cmp	x11, #0x100
        b.lt	rej_uniform_initial_zero
        mov	x7, x8
        mov	x9, #0x0                // =0
        mov	x4, #0x100              // =256
        cmp	x2, #0x30
        b.lo	rej_uniform_loop48_end

rej_uniform_loop48:
        cmp	x9, x4
        b.hs	rej_uniform_memory_copy
        sub	x2, x2, #0x30
        ld3	{ v0.16b, v1.16b, v2.16b }, [x1], #48
        zip1	v4.16b, v0.16b, v1.16b
        zip2	v5.16b, v0.16b, v1.16b
        zip1	v6.16b, v1.16b, v2.16b
        zip2	v7.16b, v1.16b, v2.16b
        bic	v4.8h, #0xf0, lsl #8
        bic	v5.8h, #0xf0, lsl #8
        ushr	v6.8h, v6.8h, #0x4
        ushr	v7.8h, v7.8h, #0x4
        zip1	v16.8h, v4.8h, v6.8h
        zip2	v17.8h, v4.8h, v6.8h
        zip1	v18.8h, v5.8h, v7.8h
        zip2	v19.8h, v5.8h, v7.8h
        cmhi	v4.8h, v30.8h, v16.8h
        cmhi	v5.8h, v30.8h, v17.8h
        cmhi	v6.8h, v30.8h, v18.8h
        cmhi	v7.8h, v30.8h, v19.8h
        and	v4.16b, v4.16b, v31.16b
        and	v5.16b, v5.16b, v31.16b
        and	v6.16b, v6.16b, v31.16b
        and	v7.16b, v7.16b, v31.16b
        uaddlv	s20, v4.8h
        uaddlv	s21, v5.8h
        uaddlv	s22, v6.8h
        uaddlv	s23, v7.8h
        fmov	w12, s20
        fmov	w13, s21
        fmov	w14, s22
        fmov	w15, s23
        ldr	q24, [x3, x12, lsl #4]
        ldr	q25, [x3, x13, lsl #4]
        ldr	q26, [x3, x14, lsl #4]
        ldr	q27, [x3, x15, lsl #4]
        cnt	v4.16b, v4.16b
        cnt	v5.16b, v5.16b
        cnt	v6.16b, v6.16b
        cnt	v7.16b, v7.16b
        uaddlv	s20, v4.8h
        uaddlv	s21, v5.8h
        uaddlv	s22, v6.8h
        uaddlv	s23, v7.8h
        fmov	w12, s20
        fmov	w13, s21
        fmov	w14, s22
        fmov	w15, s23
        tbl	v16.16b, { v16.16b }, v24.16b
        tbl	v17.16b, { v17.16b }, v25.16b
        tbl	v18.16b, { v18.16b }, v26.16b
        tbl	v19.16b, { v19.16b }, v27.16b
        str	q16, [x7]
        add	x7, x7, x12, lsl #1
        str	q17, [x7]
        add	x7, x7, x13, lsl #1
        str	q18, [x7]
        add	x7, x7, x14, lsl #1
        str	q19, [x7]
        add	x7, x7, x15, lsl #1
        add	x12, x12, x13
        add	x14, x14, x15
        add	x9, x9, x12
        add	x9, x9, x14
        cmp	x2, #0x30
        b.hs	rej_uniform_loop48

rej_uniform_loop48_end:
        cmp	x9, x4
        b.hs	rej_uniform_memory_copy
        cmp	x2, #0x18
        b.lo	rej_uniform_memory_copy
        sub	x2, x2, #0x18
        ld3	{ v0.8b, v1.8b, v2.8b }, [x1], #24
        zip1	v4.16b, v0.16b, v1.16b
        zip1	v5.16b, v1.16b, v2.16b
        bic	v4.8h, #0xf0, lsl #8
        ushr	v5.8h, v5.8h, #0x4
        zip1	v16.8h, v4.8h, v5.8h
        zip2	v17.8h, v4.8h, v5.8h
        cmhi	v4.8h, v30.8h, v16.8h
        cmhi	v5.8h, v30.8h, v17.8h
        and	v4.16b, v4.16b, v31.16b
        and	v5.16b, v5.16b, v31.16b
        uaddlv	s20, v4.8h
        uaddlv	s21, v5.8h
        fmov	w12, s20
        fmov	w13, s21
        ldr	q24, [x3, x12, lsl #4]
        ldr	q25, [x3, x13, lsl #4]
        cnt	v4.16b, v4.16b
        cnt	v5.16b, v5.16b
        uaddlv	s20, v4.8h
        uaddlv	s21, v5.8h
        fmov	w12, s20
        fmov	w13, s21
        tbl	v16.16b, { v16.16b }, v24.16b
        tbl	v17.16b, { v17.16b }, v25.16b
        str	q16, [x7]
        add	x7, x7, x12, lsl #1
        str	q17, [x7]
        add	x7, x7, x13, lsl #1
        add	x9, x9, x12
        add	x9, x9, x13

rej_uniform_memory_copy:
        cmp	x9, x4
        csel	x9, x9, x4, lo
        mov	x11, #0x0               // =0
        mov	x7, x8

rej_uniform_final_copy:
        ldr	q16, [x7], #0x40
        ldur	q17, [x7, #-0x30]
        ldur	q18, [x7, #-0x20]
        ldur	q19, [x7, #-0x10]
        str	q16, [x0], #0x40
        stur	q17, [x0, #-0x30]
        stur	q18, [x0, #-0x20]
        stur	q19, [x0, #-0x10]
        add	x11, x11, #0x20
        cmp	x11, #0x100
        b.lt	rej_uniform_final_copy
        mov	x0, x9
        b	rej_uniform_return

rej_uniform_return:
        add	sp, sp, #0x240
        ret

