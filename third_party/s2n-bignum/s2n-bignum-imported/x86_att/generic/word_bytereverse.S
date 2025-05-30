// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ----------------------------------------------------------------------------
// Reverse the order of bytes in a 64-bit word
//
//    extern uint64_t word_bytereverse (uint64_t a);
//
// Standard x86-64 ABI: RDI = a, returns RAX
// Microsoft x64 ABI:   RCX = a, returns RAX
// ----------------------------------------------------------------------------

#include "_internal_s2n_bignum.h"


        S2N_BN_SYM_VISIBILITY_DIRECTIVE(word_bytereverse)
        S2N_BN_SYM_PRIVACY_DIRECTIVE(word_bytereverse)
        .text

// Just uses the x86 BSWAP instruction, which does the job directly

S2N_BN_SYMBOL(word_bytereverse):
        _CET_ENDBR

#if WINDOWS_ABI
        pushq   %rdi
        pushq   %rsi
        movq    %rcx, %rdi
#endif

        movq    %rdi, %rax
        bswapq  %rax
#if WINDOWS_ABI
        popq   %rsi
        popq   %rdi
#endif
        ret

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
