#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(label_break_value)]
extern "C" {
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type size_t = libc::c_ulong;
static mut rhotates: [[uint8_t; 5]; 5] = [
    [
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        62 as libc::c_int as uint8_t,
        28 as libc::c_int as uint8_t,
        27 as libc::c_int as uint8_t,
    ],
    [
        36 as libc::c_int as uint8_t,
        44 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        55 as libc::c_int as uint8_t,
        20 as libc::c_int as uint8_t,
    ],
    [
        3 as libc::c_int as uint8_t,
        10 as libc::c_int as uint8_t,
        43 as libc::c_int as uint8_t,
        25 as libc::c_int as uint8_t,
        39 as libc::c_int as uint8_t,
    ],
    [
        41 as libc::c_int as uint8_t,
        45 as libc::c_int as uint8_t,
        15 as libc::c_int as uint8_t,
        21 as libc::c_int as uint8_t,
        8 as libc::c_int as uint8_t,
    ],
    [
        18 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        61 as libc::c_int as uint8_t,
        56 as libc::c_int as uint8_t,
        14 as libc::c_int as uint8_t,
    ],
];
static mut iotas: [uint64_t; 24] = [0; 24];
unsafe extern "C" fn ROL64(mut val: uint64_t, mut offset: libc::c_int) -> uint64_t {
    if offset == 0 as libc::c_int {
        return val
    } else if 0 as libc::c_int == 0 {
        return val << offset | val >> 64 as libc::c_int - offset
    } else {
        let mut hi: uint32_t = (val >> 32 as libc::c_int) as uint32_t;
        let mut lo: uint32_t = val as uint32_t;
        if offset & 1 as libc::c_int != 0 as libc::c_int {
            let mut tmp: uint32_t = hi;
            offset >>= 1 as libc::c_int;
            hi = lo << offset | lo >> (32 as libc::c_int - offset & 31 as libc::c_int);
            lo = tmp << offset + 1 as libc::c_int
                | tmp
                    >> (32 as libc::c_int - (offset + 1 as libc::c_int)
                        & 31 as libc::c_int);
        } else {
            offset >>= 1 as libc::c_int;
            lo = lo << offset | lo >> (32 as libc::c_int - offset & 31 as libc::c_int);
            hi = hi << offset | hi >> (32 as libc::c_int - offset & 31 as libc::c_int);
        }
        return (hi as uint64_t) << 32 as libc::c_int | lo as uint64_t;
    };
}
unsafe extern "C" fn Round(
    mut R: *mut [uint64_t; 5],
    mut A: *mut [uint64_t; 5],
    mut i: size_t,
) {
    let mut C: [uint64_t; 5] = [0; 5];
    let mut D: [uint64_t; 5] = [0; 5];
    if i
        < (::core::mem::size_of::<[uint64_t; 24]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong)
    {} else {
        __assert_fail(
            b"i < (sizeof(iotas) / sizeof(iotas[0]))\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/keccak1600.c\0"
                as *const u8 as *const libc::c_char,
            113 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 53],
                &[libc::c_char; 53],
            >(b"void Round(uint64_t (*)[5], uint64_t (*)[5], size_t)\0"))
                .as_ptr(),
        );
    }
    'c_9146: {
        if i
            < (::core::mem::size_of::<[uint64_t; 24]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<uint64_t>() as libc::c_ulong)
        {} else {
            __assert_fail(
                b"i < (sizeof(iotas) / sizeof(iotas[0]))\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/keccak1600.c\0"
                    as *const u8 as *const libc::c_char,
                113 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 53],
                    &[libc::c_char; 53],
                >(b"void Round(uint64_t (*)[5], uint64_t (*)[5], size_t)\0"))
                    .as_ptr(),
            );
        }
    };
    C[0 as libc::c_int
        as usize] = (*A.offset(0 as libc::c_int as isize))[0 as libc::c_int as usize]
        ^ (*A.offset(1 as libc::c_int as isize))[0 as libc::c_int as usize]
        ^ (*A.offset(2 as libc::c_int as isize))[0 as libc::c_int as usize]
        ^ (*A.offset(3 as libc::c_int as isize))[0 as libc::c_int as usize]
        ^ (*A.offset(4 as libc::c_int as isize))[0 as libc::c_int as usize];
    C[1 as libc::c_int
        as usize] = (*A.offset(0 as libc::c_int as isize))[1 as libc::c_int as usize]
        ^ (*A.offset(1 as libc::c_int as isize))[1 as libc::c_int as usize]
        ^ (*A.offset(2 as libc::c_int as isize))[1 as libc::c_int as usize]
        ^ (*A.offset(3 as libc::c_int as isize))[1 as libc::c_int as usize]
        ^ (*A.offset(4 as libc::c_int as isize))[1 as libc::c_int as usize];
    C[2 as libc::c_int
        as usize] = (*A.offset(0 as libc::c_int as isize))[2 as libc::c_int as usize]
        ^ (*A.offset(1 as libc::c_int as isize))[2 as libc::c_int as usize]
        ^ (*A.offset(2 as libc::c_int as isize))[2 as libc::c_int as usize]
        ^ (*A.offset(3 as libc::c_int as isize))[2 as libc::c_int as usize]
        ^ (*A.offset(4 as libc::c_int as isize))[2 as libc::c_int as usize];
    C[3 as libc::c_int
        as usize] = (*A.offset(0 as libc::c_int as isize))[3 as libc::c_int as usize]
        ^ (*A.offset(1 as libc::c_int as isize))[3 as libc::c_int as usize]
        ^ (*A.offset(2 as libc::c_int as isize))[3 as libc::c_int as usize]
        ^ (*A.offset(3 as libc::c_int as isize))[3 as libc::c_int as usize]
        ^ (*A.offset(4 as libc::c_int as isize))[3 as libc::c_int as usize];
    C[4 as libc::c_int
        as usize] = (*A.offset(0 as libc::c_int as isize))[4 as libc::c_int as usize]
        ^ (*A.offset(1 as libc::c_int as isize))[4 as libc::c_int as usize]
        ^ (*A.offset(2 as libc::c_int as isize))[4 as libc::c_int as usize]
        ^ (*A.offset(3 as libc::c_int as isize))[4 as libc::c_int as usize]
        ^ (*A.offset(4 as libc::c_int as isize))[4 as libc::c_int as usize];
    D[0 as libc::c_int
        as usize] = ROL64(C[1 as libc::c_int as usize], 1 as libc::c_int)
        ^ C[4 as libc::c_int as usize];
    D[1 as libc::c_int
        as usize] = ROL64(C[2 as libc::c_int as usize], 1 as libc::c_int)
        ^ C[0 as libc::c_int as usize];
    D[2 as libc::c_int
        as usize] = ROL64(C[3 as libc::c_int as usize], 1 as libc::c_int)
        ^ C[1 as libc::c_int as usize];
    D[3 as libc::c_int
        as usize] = ROL64(C[4 as libc::c_int as usize], 1 as libc::c_int)
        ^ C[2 as libc::c_int as usize];
    D[4 as libc::c_int
        as usize] = ROL64(C[0 as libc::c_int as usize], 1 as libc::c_int)
        ^ C[3 as libc::c_int as usize];
    C[0 as libc::c_int
        as usize] = (*A.offset(0 as libc::c_int as isize))[0 as libc::c_int as usize]
        ^ D[0 as libc::c_int as usize];
    C[1 as libc::c_int
        as usize] = ROL64(
        (*A.offset(1 as libc::c_int as isize))[1 as libc::c_int as usize]
            ^ D[1 as libc::c_int as usize],
        rhotates[1 as libc::c_int as usize][1 as libc::c_int as usize] as libc::c_int,
    );
    C[2 as libc::c_int
        as usize] = ROL64(
        (*A.offset(2 as libc::c_int as isize))[2 as libc::c_int as usize]
            ^ D[2 as libc::c_int as usize],
        rhotates[2 as libc::c_int as usize][2 as libc::c_int as usize] as libc::c_int,
    );
    C[3 as libc::c_int
        as usize] = ROL64(
        (*A.offset(3 as libc::c_int as isize))[3 as libc::c_int as usize]
            ^ D[3 as libc::c_int as usize],
        rhotates[3 as libc::c_int as usize][3 as libc::c_int as usize] as libc::c_int,
    );
    C[4 as libc::c_int
        as usize] = ROL64(
        (*A.offset(4 as libc::c_int as isize))[4 as libc::c_int as usize]
            ^ D[4 as libc::c_int as usize],
        rhotates[4 as libc::c_int as usize][4 as libc::c_int as usize] as libc::c_int,
    );
    (*R
        .offset(
            0 as libc::c_int as isize,
        ))[0 as libc::c_int
        as usize] = C[0 as libc::c_int as usize]
        ^ (C[1 as libc::c_int as usize] | C[2 as libc::c_int as usize])
        ^ iotas[i as usize];
    (*R
        .offset(
            0 as libc::c_int as isize,
        ))[1 as libc::c_int
        as usize] = C[1 as libc::c_int as usize]
        ^ (!C[2 as libc::c_int as usize] | C[3 as libc::c_int as usize]);
    (*R
        .offset(
            0 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = C[2 as libc::c_int as usize]
        ^ C[3 as libc::c_int as usize] & C[4 as libc::c_int as usize];
    (*R
        .offset(
            0 as libc::c_int as isize,
        ))[3 as libc::c_int
        as usize] = C[3 as libc::c_int as usize]
        ^ (C[4 as libc::c_int as usize] | C[0 as libc::c_int as usize]);
    (*R
        .offset(
            0 as libc::c_int as isize,
        ))[4 as libc::c_int
        as usize] = C[4 as libc::c_int as usize]
        ^ C[0 as libc::c_int as usize] & C[1 as libc::c_int as usize];
    C[0 as libc::c_int
        as usize] = ROL64(
        (*A.offset(0 as libc::c_int as isize))[3 as libc::c_int as usize]
            ^ D[3 as libc::c_int as usize],
        rhotates[0 as libc::c_int as usize][3 as libc::c_int as usize] as libc::c_int,
    );
    C[1 as libc::c_int
        as usize] = ROL64(
        (*A.offset(1 as libc::c_int as isize))[4 as libc::c_int as usize]
            ^ D[4 as libc::c_int as usize],
        rhotates[1 as libc::c_int as usize][4 as libc::c_int as usize] as libc::c_int,
    );
    C[2 as libc::c_int
        as usize] = ROL64(
        (*A.offset(2 as libc::c_int as isize))[0 as libc::c_int as usize]
            ^ D[0 as libc::c_int as usize],
        rhotates[2 as libc::c_int as usize][0 as libc::c_int as usize] as libc::c_int,
    );
    C[3 as libc::c_int
        as usize] = ROL64(
        (*A.offset(3 as libc::c_int as isize))[1 as libc::c_int as usize]
            ^ D[1 as libc::c_int as usize],
        rhotates[3 as libc::c_int as usize][1 as libc::c_int as usize] as libc::c_int,
    );
    C[4 as libc::c_int
        as usize] = ROL64(
        (*A.offset(4 as libc::c_int as isize))[2 as libc::c_int as usize]
            ^ D[2 as libc::c_int as usize],
        rhotates[4 as libc::c_int as usize][2 as libc::c_int as usize] as libc::c_int,
    );
    (*R
        .offset(
            1 as libc::c_int as isize,
        ))[0 as libc::c_int
        as usize] = C[0 as libc::c_int as usize]
        ^ (C[1 as libc::c_int as usize] | C[2 as libc::c_int as usize]);
    (*R
        .offset(
            1 as libc::c_int as isize,
        ))[1 as libc::c_int
        as usize] = C[1 as libc::c_int as usize]
        ^ C[2 as libc::c_int as usize] & C[3 as libc::c_int as usize];
    (*R
        .offset(
            1 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = C[2 as libc::c_int as usize]
        ^ (C[3 as libc::c_int as usize] | !C[4 as libc::c_int as usize]);
    (*R
        .offset(
            1 as libc::c_int as isize,
        ))[3 as libc::c_int
        as usize] = C[3 as libc::c_int as usize]
        ^ (C[4 as libc::c_int as usize] | C[0 as libc::c_int as usize]);
    (*R
        .offset(
            1 as libc::c_int as isize,
        ))[4 as libc::c_int
        as usize] = C[4 as libc::c_int as usize]
        ^ C[0 as libc::c_int as usize] & C[1 as libc::c_int as usize];
    C[0 as libc::c_int
        as usize] = ROL64(
        (*A.offset(0 as libc::c_int as isize))[1 as libc::c_int as usize]
            ^ D[1 as libc::c_int as usize],
        rhotates[0 as libc::c_int as usize][1 as libc::c_int as usize] as libc::c_int,
    );
    C[1 as libc::c_int
        as usize] = ROL64(
        (*A.offset(1 as libc::c_int as isize))[2 as libc::c_int as usize]
            ^ D[2 as libc::c_int as usize],
        rhotates[1 as libc::c_int as usize][2 as libc::c_int as usize] as libc::c_int,
    );
    C[2 as libc::c_int
        as usize] = ROL64(
        (*A.offset(2 as libc::c_int as isize))[3 as libc::c_int as usize]
            ^ D[3 as libc::c_int as usize],
        rhotates[2 as libc::c_int as usize][3 as libc::c_int as usize] as libc::c_int,
    );
    C[3 as libc::c_int
        as usize] = ROL64(
        (*A.offset(3 as libc::c_int as isize))[4 as libc::c_int as usize]
            ^ D[4 as libc::c_int as usize],
        rhotates[3 as libc::c_int as usize][4 as libc::c_int as usize] as libc::c_int,
    );
    C[4 as libc::c_int
        as usize] = ROL64(
        (*A.offset(4 as libc::c_int as isize))[0 as libc::c_int as usize]
            ^ D[0 as libc::c_int as usize],
        rhotates[4 as libc::c_int as usize][0 as libc::c_int as usize] as libc::c_int,
    );
    (*R
        .offset(
            2 as libc::c_int as isize,
        ))[0 as libc::c_int
        as usize] = C[0 as libc::c_int as usize]
        ^ (C[1 as libc::c_int as usize] | C[2 as libc::c_int as usize]);
    (*R
        .offset(
            2 as libc::c_int as isize,
        ))[1 as libc::c_int
        as usize] = C[1 as libc::c_int as usize]
        ^ C[2 as libc::c_int as usize] & C[3 as libc::c_int as usize];
    (*R
        .offset(
            2 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = C[2 as libc::c_int as usize]
        ^ !C[3 as libc::c_int as usize] & C[4 as libc::c_int as usize];
    (*R
        .offset(
            2 as libc::c_int as isize,
        ))[3 as libc::c_int
        as usize] = !C[3 as libc::c_int as usize]
        ^ (C[4 as libc::c_int as usize] | C[0 as libc::c_int as usize]);
    (*R
        .offset(
            2 as libc::c_int as isize,
        ))[4 as libc::c_int
        as usize] = C[4 as libc::c_int as usize]
        ^ C[0 as libc::c_int as usize] & C[1 as libc::c_int as usize];
    C[0 as libc::c_int
        as usize] = ROL64(
        (*A.offset(0 as libc::c_int as isize))[4 as libc::c_int as usize]
            ^ D[4 as libc::c_int as usize],
        rhotates[0 as libc::c_int as usize][4 as libc::c_int as usize] as libc::c_int,
    );
    C[1 as libc::c_int
        as usize] = ROL64(
        (*A.offset(1 as libc::c_int as isize))[0 as libc::c_int as usize]
            ^ D[0 as libc::c_int as usize],
        rhotates[1 as libc::c_int as usize][0 as libc::c_int as usize] as libc::c_int,
    );
    C[2 as libc::c_int
        as usize] = ROL64(
        (*A.offset(2 as libc::c_int as isize))[1 as libc::c_int as usize]
            ^ D[1 as libc::c_int as usize],
        rhotates[2 as libc::c_int as usize][1 as libc::c_int as usize] as libc::c_int,
    );
    C[3 as libc::c_int
        as usize] = ROL64(
        (*A.offset(3 as libc::c_int as isize))[2 as libc::c_int as usize]
            ^ D[2 as libc::c_int as usize],
        rhotates[3 as libc::c_int as usize][2 as libc::c_int as usize] as libc::c_int,
    );
    C[4 as libc::c_int
        as usize] = ROL64(
        (*A.offset(4 as libc::c_int as isize))[3 as libc::c_int as usize]
            ^ D[3 as libc::c_int as usize],
        rhotates[4 as libc::c_int as usize][3 as libc::c_int as usize] as libc::c_int,
    );
    (*R
        .offset(
            3 as libc::c_int as isize,
        ))[0 as libc::c_int
        as usize] = C[0 as libc::c_int as usize]
        ^ C[1 as libc::c_int as usize] & C[2 as libc::c_int as usize];
    (*R
        .offset(
            3 as libc::c_int as isize,
        ))[1 as libc::c_int
        as usize] = C[1 as libc::c_int as usize]
        ^ (C[2 as libc::c_int as usize] | C[3 as libc::c_int as usize]);
    (*R
        .offset(
            3 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = C[2 as libc::c_int as usize]
        ^ (!C[3 as libc::c_int as usize] | C[4 as libc::c_int as usize]);
    (*R
        .offset(
            3 as libc::c_int as isize,
        ))[3 as libc::c_int
        as usize] = !C[3 as libc::c_int as usize]
        ^ C[4 as libc::c_int as usize] & C[0 as libc::c_int as usize];
    (*R
        .offset(
            3 as libc::c_int as isize,
        ))[4 as libc::c_int
        as usize] = C[4 as libc::c_int as usize]
        ^ (C[0 as libc::c_int as usize] | C[1 as libc::c_int as usize]);
    C[0 as libc::c_int
        as usize] = ROL64(
        (*A.offset(0 as libc::c_int as isize))[2 as libc::c_int as usize]
            ^ D[2 as libc::c_int as usize],
        rhotates[0 as libc::c_int as usize][2 as libc::c_int as usize] as libc::c_int,
    );
    C[1 as libc::c_int
        as usize] = ROL64(
        (*A.offset(1 as libc::c_int as isize))[3 as libc::c_int as usize]
            ^ D[3 as libc::c_int as usize],
        rhotates[1 as libc::c_int as usize][3 as libc::c_int as usize] as libc::c_int,
    );
    C[2 as libc::c_int
        as usize] = ROL64(
        (*A.offset(2 as libc::c_int as isize))[4 as libc::c_int as usize]
            ^ D[4 as libc::c_int as usize],
        rhotates[2 as libc::c_int as usize][4 as libc::c_int as usize] as libc::c_int,
    );
    C[3 as libc::c_int
        as usize] = ROL64(
        (*A.offset(3 as libc::c_int as isize))[0 as libc::c_int as usize]
            ^ D[0 as libc::c_int as usize],
        rhotates[3 as libc::c_int as usize][0 as libc::c_int as usize] as libc::c_int,
    );
    C[4 as libc::c_int
        as usize] = ROL64(
        (*A.offset(4 as libc::c_int as isize))[1 as libc::c_int as usize]
            ^ D[1 as libc::c_int as usize],
        rhotates[4 as libc::c_int as usize][1 as libc::c_int as usize] as libc::c_int,
    );
    (*R
        .offset(
            4 as libc::c_int as isize,
        ))[0 as libc::c_int
        as usize] = C[0 as libc::c_int as usize]
        ^ !C[1 as libc::c_int as usize] & C[2 as libc::c_int as usize];
    (*R
        .offset(
            4 as libc::c_int as isize,
        ))[1 as libc::c_int
        as usize] = !C[1 as libc::c_int as usize]
        ^ (C[2 as libc::c_int as usize] | C[3 as libc::c_int as usize]);
    (*R
        .offset(
            4 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = C[2 as libc::c_int as usize]
        ^ C[3 as libc::c_int as usize] & C[4 as libc::c_int as usize];
    (*R
        .offset(
            4 as libc::c_int as isize,
        ))[3 as libc::c_int
        as usize] = C[3 as libc::c_int as usize]
        ^ (C[4 as libc::c_int as usize] | C[0 as libc::c_int as usize]);
    (*R
        .offset(
            4 as libc::c_int as isize,
        ))[4 as libc::c_int
        as usize] = C[4 as libc::c_int as usize]
        ^ C[0 as libc::c_int as usize] & C[1 as libc::c_int as usize];
}
unsafe extern "C" fn KeccakF1600(mut A: *mut [uint64_t; 5]) {
    let mut T: [[uint64_t; 5]; 5] = [[0; 5]; 5];
    let mut i: size_t = 0;
    (*A
        .offset(
            0 as libc::c_int as isize,
        ))[1 as libc::c_int
        as usize] = !(*A.offset(0 as libc::c_int as isize))[1 as libc::c_int as usize];
    (*A
        .offset(
            0 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = !(*A.offset(0 as libc::c_int as isize))[2 as libc::c_int as usize];
    (*A
        .offset(
            1 as libc::c_int as isize,
        ))[3 as libc::c_int
        as usize] = !(*A.offset(1 as libc::c_int as isize))[3 as libc::c_int as usize];
    (*A
        .offset(
            2 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = !(*A.offset(2 as libc::c_int as isize))[2 as libc::c_int as usize];
    (*A
        .offset(
            3 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = !(*A.offset(3 as libc::c_int as isize))[2 as libc::c_int as usize];
    (*A
        .offset(
            4 as libc::c_int as isize,
        ))[0 as libc::c_int
        as usize] = !(*A.offset(4 as libc::c_int as isize))[0 as libc::c_int as usize];
    i = 0 as libc::c_int as size_t;
    while i < 24 as libc::c_int as size_t {
        Round(T.as_mut_ptr(), A, i);
        Round(A, T.as_mut_ptr(), i.wrapping_add(1 as libc::c_int as size_t));
        i = i.wrapping_add(2 as libc::c_int as size_t);
    }
    (*A
        .offset(
            0 as libc::c_int as isize,
        ))[1 as libc::c_int
        as usize] = !(*A.offset(0 as libc::c_int as isize))[1 as libc::c_int as usize];
    (*A
        .offset(
            0 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = !(*A.offset(0 as libc::c_int as isize))[2 as libc::c_int as usize];
    (*A
        .offset(
            1 as libc::c_int as isize,
        ))[3 as libc::c_int
        as usize] = !(*A.offset(1 as libc::c_int as isize))[3 as libc::c_int as usize];
    (*A
        .offset(
            2 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = !(*A.offset(2 as libc::c_int as isize))[2 as libc::c_int as usize];
    (*A
        .offset(
            3 as libc::c_int as isize,
        ))[2 as libc::c_int
        as usize] = !(*A.offset(3 as libc::c_int as isize))[2 as libc::c_int as usize];
    (*A
        .offset(
            4 as libc::c_int as isize,
        ))[0 as libc::c_int
        as usize] = !(*A.offset(4 as libc::c_int as isize))[0 as libc::c_int as usize];
}
unsafe extern "C" fn BitInterleave(mut Ai: uint64_t) -> uint64_t {
    return Ai;
}
unsafe extern "C" fn BitDeinterleave(mut Ai: uint64_t) -> uint64_t {
    return Ai;
}
#[no_mangle]
pub unsafe extern "C" fn Keccak1600_Absorb(
    mut A: *mut [uint64_t; 5],
    mut inp: *const uint8_t,
    mut len: size_t,
    mut r: size_t,
) -> size_t {
    let mut A_flat: *mut uint64_t = A as *mut uint64_t;
    let mut i: size_t = 0;
    let mut w: size_t = r / 8 as libc::c_int as size_t;
    if r
        < (25 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<uint64_t>() as libc::c_ulong)
        && r % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"r < (25 * sizeof(A[0][0])) && (r % 8) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/keccak1600.c\0"
                as *const u8 as *const libc::c_char,
            343 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 75],
                &[libc::c_char; 75],
            >(
                b"size_t Keccak1600_Absorb(uint64_t (*)[5], const uint8_t *, size_t, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    'c_9694: {
        if r
            < (25 as libc::c_int as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<uint64_t>() as libc::c_ulong)
            && r % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"r < (25 * sizeof(A[0][0])) && (r % 8) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/keccak1600.c\0"
                    as *const u8 as *const libc::c_char,
                343 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 75],
                    &[libc::c_char; 75],
                >(
                    b"size_t Keccak1600_Absorb(uint64_t (*)[5], const uint8_t *, size_t, size_t)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    while len >= r {
        i = 0 as libc::c_int as size_t;
        while i < w {
            let mut Ai: uint64_t = *inp.offset(0 as libc::c_int as isize) as uint64_t
                | (*inp.offset(1 as libc::c_int as isize) as uint64_t)
                    << 8 as libc::c_int
                | (*inp.offset(2 as libc::c_int as isize) as uint64_t)
                    << 16 as libc::c_int
                | (*inp.offset(3 as libc::c_int as isize) as uint64_t)
                    << 24 as libc::c_int
                | (*inp.offset(4 as libc::c_int as isize) as uint64_t)
                    << 32 as libc::c_int
                | (*inp.offset(5 as libc::c_int as isize) as uint64_t)
                    << 40 as libc::c_int
                | (*inp.offset(6 as libc::c_int as isize) as uint64_t)
                    << 48 as libc::c_int
                | (*inp.offset(7 as libc::c_int as isize) as uint64_t)
                    << 56 as libc::c_int;
            inp = inp.offset(8 as libc::c_int as isize);
            *A_flat.offset(i as isize) ^= BitInterleave(Ai);
            i = i.wrapping_add(1);
            i;
        }
        KeccakF1600(A);
        len = len.wrapping_sub(r);
    }
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn Keccak1600_Squeeze(
    mut A: *mut [uint64_t; 5],
    mut out: *mut uint8_t,
    mut len: size_t,
    mut r: size_t,
    mut padded: libc::c_int,
) {
    let mut A_flat: *mut uint64_t = A as *mut uint64_t;
    let mut i: size_t = 0;
    let mut w: size_t = r / 8 as libc::c_int as size_t;
    if r
        < (25 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<uint64_t>() as libc::c_ulong)
        && r % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t
    {} else {
        __assert_fail(
            b"r < (25 * sizeof(A[0][0])) && (r % 8) == 0\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/keccak1600.c\0"
                as *const u8 as *const libc::c_char,
            368 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 73],
                &[libc::c_char; 73],
            >(
                b"void Keccak1600_Squeeze(uint64_t (*)[5], uint8_t *, size_t, size_t, int)\0",
            ))
                .as_ptr(),
        );
    }
    'c_10240: {
        if r
            < (25 as libc::c_int as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<uint64_t>() as libc::c_ulong)
            && r % 8 as libc::c_int as size_t == 0 as libc::c_int as size_t
        {} else {
            __assert_fail(
                b"r < (25 * sizeof(A[0][0])) && (r % 8) == 0\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/sha/keccak1600.c\0"
                    as *const u8 as *const libc::c_char,
                368 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 73],
                    &[libc::c_char; 73],
                >(
                    b"void Keccak1600_Squeeze(uint64_t (*)[5], uint8_t *, size_t, size_t, int)\0",
                ))
                    .as_ptr(),
            );
        }
    };
    while len != 0 as libc::c_int as size_t {
        if padded != 0 {
            KeccakF1600(A);
        }
        padded = 1 as libc::c_int;
        i = 0 as libc::c_int as size_t;
        while i < w && len != 0 as libc::c_int as size_t {
            let mut Ai: uint64_t = BitDeinterleave(*A_flat.offset(i as isize));
            if len < 8 as libc::c_int as size_t {
                i = 0 as libc::c_int as size_t;
                while i < len {
                    let fresh0 = out;
                    out = out.offset(1);
                    *fresh0 = Ai as uint8_t;
                    Ai >>= 8 as libc::c_int;
                    i = i.wrapping_add(1);
                    i;
                }
                return;
            }
            *out.offset(0 as libc::c_int as isize) = Ai as uint8_t;
            *out.offset(1 as libc::c_int as isize) = (Ai >> 8 as libc::c_int) as uint8_t;
            *out
                .offset(
                    2 as libc::c_int as isize,
                ) = (Ai >> 16 as libc::c_int) as uint8_t;
            *out
                .offset(
                    3 as libc::c_int as isize,
                ) = (Ai >> 24 as libc::c_int) as uint8_t;
            *out
                .offset(
                    4 as libc::c_int as isize,
                ) = (Ai >> 32 as libc::c_int) as uint8_t;
            *out
                .offset(
                    5 as libc::c_int as isize,
                ) = (Ai >> 40 as libc::c_int) as uint8_t;
            *out
                .offset(
                    6 as libc::c_int as isize,
                ) = (Ai >> 48 as libc::c_int) as uint8_t;
            *out
                .offset(
                    7 as libc::c_int as isize,
                ) = (Ai >> 56 as libc::c_int) as uint8_t;
            out = out.offset(8 as libc::c_int as isize);
            len = len.wrapping_sub(8 as libc::c_int as size_t);
            i = i.wrapping_add(1);
            i;
        }
    }
}
unsafe extern "C" fn run_static_initializers() {
    iotas = [
        (if 0 as libc::c_int != 0 {
            0x1 as libc::c_ulonglong
        } else {
            0x1 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8900000000 as libc::c_ulonglong
        } else {
            0x8082 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000008b00000000 as libc::c_ulonglong
        } else {
            0x800000000000808a as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000808000000000 as libc::c_ulonglong
        } else {
            0x8000000080008000 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8b00000001 as libc::c_ulonglong
        } else {
            0x808b as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x800000000001 as libc::c_ulonglong
        } else {
            0x80000001 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000808800000001 as libc::c_ulonglong
        } else {
            0x8000000080008081 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000008200000001 as libc::c_ulonglong
        } else {
            0x8000000000008009 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0xb00000000 as libc::c_ulonglong
        } else {
            0x8a as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0xa00000000 as libc::c_ulonglong
        } else {
            0x88 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x808200000001 as libc::c_ulonglong
        } else {
            0x80008009 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x800300000000 as libc::c_ulonglong
        } else {
            0x8000000a as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x808b00000001 as libc::c_ulonglong
        } else {
            0x8000808b as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000000b00000001 as libc::c_ulonglong
        } else {
            0x800000000000008b as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000008a00000001 as libc::c_ulonglong
        } else {
            0x8000000000008089 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000008100000001 as libc::c_ulonglong
        } else {
            0x8000000000008003 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000008100000000 as libc::c_ulonglong
        } else {
            0x8000000000008002 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000000800000000 as libc::c_ulonglong
        } else {
            0x8000000000000080 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8300000000 as libc::c_ulonglong
        } else {
            0x800a as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000800300000000 as libc::c_ulonglong
        } else {
            0x800000008000000a as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000808800000001 as libc::c_ulonglong
        } else {
            0x8000000080008081 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000008800000000 as libc::c_ulonglong
        } else {
            0x8000000000008080 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x800000000001 as libc::c_ulonglong
        } else {
            0x80000001 as libc::c_ulonglong
        }) as uint64_t,
        (if 0 as libc::c_int != 0 {
            0x8000808200000000 as libc::c_ulonglong
        } else {
            0x8000000080008008 as libc::c_ulonglong
        }) as uint64_t,
    ];
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
