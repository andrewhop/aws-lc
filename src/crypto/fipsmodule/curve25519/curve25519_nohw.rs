#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(asm, label_break_value)]
use core::arch::asm;
extern "C" {
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn CRYPTO_memcmp(
        a: *const libc::c_void,
        b: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn ed25519_sha512(
        out: *mut uint8_t,
        input1: *const libc::c_void,
        len1: size_t,
        input2: *const libc::c_void,
        len2: size_t,
        input3: *const libc::c_void,
        len3: size_t,
        input4: *const libc::c_void,
        len4: size_t,
    );
}
pub type __uint128_t = u128;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t {
    #[bitfield(
        name = "static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_552_error_is_int_is_not_the_same_size_as_uint32_t: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fe {
    pub v: [uint64_t; 5],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fe_loose {
    pub v: [uint64_t; 5],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_p2 {
    pub X: fe,
    pub Y: fe,
    pub Z: fe,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_p3 {
    pub X: fe,
    pub Y: fe,
    pub Z: fe,
    pub T: fe,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_p1p1 {
    pub X: fe_loose,
    pub Y: fe_loose,
    pub Z: fe_loose,
    pub T: fe_loose,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_precomp {
    pub yplusx: fe_loose,
    pub yminusx: fe_loose,
    pub xy2d: fe_loose,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_cached {
    pub YplusX: fe_loose,
    pub YminusX: fe_loose,
    pub Z: fe_loose,
    pub T2d: fe_loose,
}
pub type fiat_25519_uint1 = libc::c_uchar;
pub type fiat_25519_int1 = libc::c_schar;
pub type fe_limb_t = uint64_t;
pub type fiat_25519_uint128 = __uint128_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct static_assertion_at_line_309_error_is_fe_and_fe_loose_mismatch {
    #[bitfield(
        name = "static_assertion_at_line_309_error_is_fe_and_fe_loose_mismatch",
        ty = "libc::c_uint",
        bits = "0..=0"
    )]
    pub static_assertion_at_line_309_error_is_fe_and_fe_loose_mismatch: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[inline]
unsafe extern "C" fn value_barrier_u32(mut a: uint32_t) -> uint32_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_declassify_int(mut v: libc::c_int) -> libc::c_int {
    return value_barrier_u32(v as uint32_t) as libc::c_int;
}
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memcpy(dst, src, n);
}
#[inline]
unsafe extern "C" fn OPENSSL_memmove(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memmove(dst, src, n);
}
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return dst;
    }
    return memset(dst, c, n);
}
static mut k25519d: fe = {
    let mut init = fe {
        v: [
            929955233495203 as libc::c_long as uint64_t,
            466365720129213 as libc::c_long as uint64_t,
            1662059464998953 as libc::c_long as uint64_t,
            2033849074728123 as libc::c_long as uint64_t,
            1442794654840575 as libc::c_long as uint64_t,
        ],
    };
    init
};
static mut k25519sqrtm1: fe = {
    let mut init = fe {
        v: [
            1718705420411056 as libc::c_long as uint64_t,
            234908883556509 as libc::c_long as uint64_t,
            2233514472574048 as libc::c_long as uint64_t,
            2117202627021982 as libc::c_long as uint64_t,
            765476049583133 as libc::c_long as uint64_t,
        ],
    };
    init
};
static mut k25519d2: fe = {
    let mut init = fe {
        v: [
            1859910466990425 as libc::c_long as uint64_t,
            932731440258426 as libc::c_long as uint64_t,
            1072319116312658 as libc::c_long as uint64_t,
            1815898335770999 as libc::c_long as uint64_t,
            633789495995903 as libc::c_long as uint64_t,
        ],
    };
    init
};
static mut k25519Precomp: [[ge_precomp; 8]; 32] = [
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1288382639258501 as libc::c_long as uint64_t,
                            245678601348599 as libc::c_long as uint64_t,
                            269427782077623 as libc::c_long as uint64_t,
                            1462984067271730 as libc::c_long as uint64_t,
                            137412439391563 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            62697248952638 as libc::c_long as uint64_t,
                            204681361388450 as libc::c_long as uint64_t,
                            631292143396476 as libc::c_long as uint64_t,
                            338455783676468 as libc::c_long as uint64_t,
                            1213667448819585 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            301289933810280 as libc::c_long as uint64_t,
                            1259582250014073 as libc::c_long as uint64_t,
                            1422107436869536 as libc::c_long as uint64_t,
                            796239922652654 as libc::c_long as uint64_t,
                            1953934009299142 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1380971894829527 as libc::c_long as uint64_t,
                            790832306631236 as libc::c_long as uint64_t,
                            2067202295274102 as libc::c_long as uint64_t,
                            1995808275510000 as libc::c_long as uint64_t,
                            1566530869037010 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            463307831301544 as libc::c_long as uint64_t,
                            432984605774163 as libc::c_long as uint64_t,
                            1610641361907204 as libc::c_long as uint64_t,
                            750899048855000 as libc::c_long as uint64_t,
                            1894842303421586 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            748439484463711 as libc::c_long as uint64_t,
                            1033211726465151 as libc::c_long as uint64_t,
                            1396005112841647 as libc::c_long as uint64_t,
                            1611506220286469 as libc::c_long as uint64_t,
                            1972177495910992 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1601611775252272 as libc::c_long as uint64_t,
                            1720807796594148 as libc::c_long as uint64_t,
                            1132070835939856 as libc::c_long as uint64_t,
                            1260455018889551 as libc::c_long as uint64_t,
                            2147779492816911 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            316559037616741 as libc::c_long as uint64_t,
                            2177824224946892 as libc::c_long as uint64_t,
                            1459442586438991 as libc::c_long as uint64_t,
                            1461528397712656 as libc::c_long as uint64_t,
                            751590696113597 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1850748884277385 as libc::c_long as uint64_t,
                            1200145853858453 as libc::c_long as uint64_t,
                            1068094770532492 as libc::c_long as uint64_t,
                            672251375690438 as libc::c_long as uint64_t,
                            1586055907191707 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            934282339813791 as libc::c_long as uint64_t,
                            1846903124198670 as libc::c_long as uint64_t,
                            1172395437954843 as libc::c_long as uint64_t,
                            1007037127761661 as libc::c_long as uint64_t,
                            1830588347719256 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1694390458783935 as libc::c_long as uint64_t,
                            1735906047636159 as libc::c_long as uint64_t,
                            705069562067493 as libc::c_long as uint64_t,
                            648033061693059 as libc::c_long as uint64_t,
                            696214010414170 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1121406372216585 as libc::c_long as uint64_t,
                            192876649532226 as libc::c_long as uint64_t,
                            190294192191717 as libc::c_long as uint64_t,
                            1994165897297032 as libc::c_long as uint64_t,
                            2245000007398739 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            769950342298419 as libc::c_long as uint64_t,
                            132954430919746 as libc::c_long as uint64_t,
                            844085933195555 as libc::c_long as uint64_t,
                            974092374476333 as libc::c_long as uint64_t,
                            726076285546016 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            425251763115706 as libc::c_long as uint64_t,
                            608463272472562 as libc::c_long as uint64_t,
                            442562545713235 as libc::c_long as uint64_t,
                            837766094556764 as libc::c_long as uint64_t,
                            374555092627893 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1086255230780037 as libc::c_long as uint64_t,
                            274979815921559 as libc::c_long as uint64_t,
                            1960002765731872 as libc::c_long as uint64_t,
                            929474102396301 as libc::c_long as uint64_t,
                            1190409889297339 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1388594989461809 as libc::c_long as uint64_t,
                            316767091099457 as libc::c_long as uint64_t,
                            394298842192982 as libc::c_long as uint64_t,
                            1230079486801005 as libc::c_long as uint64_t,
                            1440737038838979 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            7380825640100 as libc::c_long as uint64_t,
                            146210432690483 as libc::c_long as uint64_t,
                            304903576448906 as libc::c_long as uint64_t,
                            1198869323871120 as libc::c_long as uint64_t,
                            997689833219095 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1181317918772081 as libc::c_long as uint64_t,
                            114573476638901 as libc::c_long as uint64_t,
                            262805072233344 as libc::c_long as uint64_t,
                            265712217171332 as libc::c_long as uint64_t,
                            294181933805782 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            665000864555967 as libc::c_long as uint64_t,
                            2065379846933859 as libc::c_long as uint64_t,
                            370231110385876 as libc::c_long as uint64_t,
                            350988370788628 as libc::c_long as uint64_t,
                            1233371373142985 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2019367628972465 as libc::c_long as uint64_t,
                            676711900706637 as libc::c_long as uint64_t,
                            110710997811333 as libc::c_long as uint64_t,
                            1108646842542025 as libc::c_long as uint64_t,
                            517791959672113 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            965130719900578 as libc::c_long as uint64_t,
                            247011430587952 as libc::c_long as uint64_t,
                            526356006571389 as libc::c_long as uint64_t,
                            91986625355052 as libc::c_long as uint64_t,
                            2157223321444601 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2068619540119183 as libc::c_long as uint64_t,
                            1966274918058806 as libc::c_long as uint64_t,
                            957728544705549 as libc::c_long as uint64_t,
                            729906502578991 as libc::c_long as uint64_t,
                            159834893065166 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2073601412052185 as libc::c_long as uint64_t,
                            31021124762708 as libc::c_long as uint64_t,
                            264500969797082 as libc::c_long as uint64_t,
                            248034690651703 as libc::c_long as uint64_t,
                            1030252227928288 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            551790716293402 as libc::c_long as uint64_t,
                            1989538725166328 as libc::c_long as uint64_t,
                            801169423371717 as libc::c_long as uint64_t,
                            2052451893578887 as libc::c_long as uint64_t,
                            678432056995012 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1368953770187805 as libc::c_long as uint64_t,
                            790347636712921 as libc::c_long as uint64_t,
                            437508475667162 as libc::c_long as uint64_t,
                            2142576377050580 as libc::c_long as uint64_t,
                            1932081720066286 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            953638594433374 as libc::c_long as uint64_t,
                            1092333936795051 as libc::c_long as uint64_t,
                            1419774766716690 as libc::c_long as uint64_t,
                            805677984380077 as libc::c_long as uint64_t,
                            859228993502513 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1200766035879111 as libc::c_long as uint64_t,
                            20142053207432 as libc::c_long as uint64_t,
                            1465634435977050 as libc::c_long as uint64_t,
                            1645256912097844 as libc::c_long as uint64_t,
                            295121984874596 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1735718747031557 as libc::c_long as uint64_t,
                            1248237894295956 as libc::c_long as uint64_t,
                            1204753118328107 as libc::c_long as uint64_t,
                            976066523550493 as libc::c_long as uint64_t,
                            65943769534592 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1060098822528990 as libc::c_long as uint64_t,
                            1586825862073490 as libc::c_long as uint64_t,
                            212301317240126 as libc::c_long as uint64_t,
                            1975302711403555 as libc::c_long as uint64_t,
                            666724059764335 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1091990273418756 as libc::c_long as uint64_t,
                            1572899409348578 as libc::c_long as uint64_t,
                            80968014455247 as libc::c_long as uint64_t,
                            306009358661350 as libc::c_long as uint64_t,
                            1520450739132526 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1480517209436112 as libc::c_long as uint64_t,
                            1511153322193952 as libc::c_long as uint64_t,
                            1244343858991172 as libc::c_long as uint64_t,
                            304788150493241 as libc::c_long as uint64_t,
                            369136856496443 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2151330273626164 as libc::c_long as uint64_t,
                            762045184746182 as libc::c_long as uint64_t,
                            1688074332551515 as libc::c_long as uint64_t,
                            823046109005759 as libc::c_long as uint64_t,
                            907602769079491 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2047386910586836 as libc::c_long as uint64_t,
                            168470092900250 as libc::c_long as uint64_t,
                            1552838872594810 as libc::c_long as uint64_t,
                            340951180073789 as libc::c_long as uint64_t,
                            360819374702533 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1982622644432056 as libc::c_long as uint64_t,
                            2014393600336956 as libc::c_long as uint64_t,
                            128909208804214 as libc::c_long as uint64_t,
                            1617792623929191 as libc::c_long as uint64_t,
                            105294281913815 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            980234343912898 as libc::c_long as uint64_t,
                            1712256739246056 as libc::c_long as uint64_t,
                            588935272190264 as libc::c_long as uint64_t,
                            204298813091998 as libc::c_long as uint64_t,
                            841798321043288 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            197561292938973 as libc::c_long as uint64_t,
                            454817274782871 as libc::c_long as uint64_t,
                            1963754960082318 as libc::c_long as uint64_t,
                            2113372252160468 as libc::c_long as uint64_t,
                            971377527342673 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            164699448829328 as libc::c_long as uint64_t,
                            3127451757672 as libc::c_long as uint64_t,
                            1199504971548753 as libc::c_long as uint64_t,
                            1766155447043652 as libc::c_long as uint64_t,
                            1899238924683527 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            732262946680281 as libc::c_long as uint64_t,
                            1674412764227063 as libc::c_long as uint64_t,
                            2182456405662809 as libc::c_long as uint64_t,
                            1350894754474250 as libc::c_long as uint64_t,
                            558458873295247 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2103305098582922 as libc::c_long as uint64_t,
                            1960809151316468 as libc::c_long as uint64_t,
                            715134605001343 as libc::c_long as uint64_t,
                            1454892949167181 as libc::c_long as uint64_t,
                            40827143824949 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1239289043050212 as libc::c_long as uint64_t,
                            1744654158124578 as libc::c_long as uint64_t,
                            758702410031698 as libc::c_long as uint64_t,
                            1796762995074688 as libc::c_long as uint64_t,
                            1603056663766 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2232056027107988 as libc::c_long as uint64_t,
                            987343914584615 as libc::c_long as uint64_t,
                            2115594492994461 as libc::c_long as uint64_t,
                            1819598072792159 as libc::c_long as uint64_t,
                            1119305654014850 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            320153677847348 as libc::c_long as uint64_t,
                            939613871605645 as libc::c_long as uint64_t,
                            641883205761567 as libc::c_long as uint64_t,
                            1930009789398224 as libc::c_long as uint64_t,
                            329165806634126 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            980930490474130 as libc::c_long as uint64_t,
                            1242488692177893 as libc::c_long as uint64_t,
                            1251446316964684 as libc::c_long as uint64_t,
                            1086618677993530 as libc::c_long as uint64_t,
                            1961430968465772 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            276821765317453 as libc::c_long as uint64_t,
                            1536835591188030 as libc::c_long as uint64_t,
                            1305212741412361 as libc::c_long as uint64_t,
                            61473904210175 as libc::c_long as uint64_t,
                            2051377036983058 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            833449923882501 as libc::c_long as uint64_t,
                            1750270368490475 as libc::c_long as uint64_t,
                            1123347002068295 as libc::c_long as uint64_t,
                            185477424765687 as libc::c_long as uint64_t,
                            278090826653186 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            794524995833413 as libc::c_long as uint64_t,
                            1849907304548286 as libc::c_long as uint64_t,
                            53348672473145 as libc::c_long as uint64_t,
                            1272368559505217 as libc::c_long as uint64_t,
                            1147304168324779 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1504846112759364 as libc::c_long as uint64_t,
                            1203096289004681 as libc::c_long as uint64_t,
                            562139421471418 as libc::c_long as uint64_t,
                            274333017451844 as libc::c_long as uint64_t,
                            1284344053775441 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            483048732424432 as libc::c_long as uint64_t,
                            2116063063343382 as libc::c_long as uint64_t,
                            30120189902313 as libc::c_long as uint64_t,
                            292451576741007 as libc::c_long as uint64_t,
                            1156379271702225 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            928372153029038 as libc::c_long as uint64_t,
                            2147692869914564 as libc::c_long as uint64_t,
                            1455665844462196 as libc::c_long as uint64_t,
                            1986737809425946 as libc::c_long as uint64_t,
                            185207050258089 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            137732961814206 as libc::c_long as uint64_t,
                            706670923917341 as libc::c_long as uint64_t,
                            1387038086865771 as libc::c_long as uint64_t,
                            1965643813686352 as libc::c_long as uint64_t,
                            1384777115696347 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            481144981981577 as libc::c_long as uint64_t,
                            2053319313589856 as libc::c_long as uint64_t,
                            2065402289827512 as libc::c_long as uint64_t,
                            617954271490316 as libc::c_long as uint64_t,
                            1106602634668125 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            696298019648792 as libc::c_long as uint64_t,
                            893299659040895 as libc::c_long as uint64_t,
                            1148636718636009 as libc::c_long as uint64_t,
                            26734077349617 as libc::c_long as uint64_t,
                            2203955659340681 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            657390353372855 as libc::c_long as uint64_t,
                            998499966885562 as libc::c_long as uint64_t,
                            991893336905797 as libc::c_long as uint64_t,
                            810470207106761 as libc::c_long as uint64_t,
                            343139804608786 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            791736669492960 as libc::c_long as uint64_t,
                            934767652997115 as libc::c_long as uint64_t,
                            824656780392914 as libc::c_long as uint64_t,
                            1759463253018643 as libc::c_long as uint64_t,
                            361530362383518 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2022541353055597 as libc::c_long as uint64_t,
                            2094700262587466 as libc::c_long as uint64_t,
                            1551008075025686 as libc::c_long as uint64_t,
                            242785517418164 as libc::c_long as uint64_t,
                            695985404963562 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1287487199965223 as libc::c_long as uint64_t,
                            2215311941380308 as libc::c_long as uint64_t,
                            1552928390931986 as libc::c_long as uint64_t,
                            1664859529680196 as libc::c_long as uint64_t,
                            1125004975265243 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            677434665154918 as libc::c_long as uint64_t,
                            989582503122485 as libc::c_long as uint64_t,
                            1817429540898386 as libc::c_long as uint64_t,
                            1052904935475344 as libc::c_long as uint64_t,
                            1143826298169798 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            367266328308408 as libc::c_long as uint64_t,
                            318431188922404 as libc::c_long as uint64_t,
                            695629353755355 as libc::c_long as uint64_t,
                            634085657580832 as libc::c_long as uint64_t,
                            24581612564426 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            773360688841258 as libc::c_long as uint64_t,
                            1815381330538070 as libc::c_long as uint64_t,
                            363773437667376 as libc::c_long as uint64_t,
                            539629987070205 as libc::c_long as uint64_t,
                            783280434248437 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            180820816194166 as libc::c_long as uint64_t,
                            168937968377394 as libc::c_long as uint64_t,
                            748416242794470 as libc::c_long as uint64_t,
                            1227281252254508 as libc::c_long as uint64_t,
                            1567587861004268 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            478775558583645 as libc::c_long as uint64_t,
                            2062896624554807 as libc::c_long as uint64_t,
                            699391259285399 as libc::c_long as uint64_t,
                            358099408427873 as libc::c_long as uint64_t,
                            1277310261461761 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1984740906540026 as libc::c_long as uint64_t,
                            1079164179400229 as libc::c_long as uint64_t,
                            1056021349262661 as libc::c_long as uint64_t,
                            1659958556483663 as libc::c_long as uint64_t,
                            1088529069025527 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            580736401511151 as libc::c_long as uint64_t,
                            1842931091388998 as libc::c_long as uint64_t,
                            1177201471228238 as libc::c_long as uint64_t,
                            2075460256527244 as libc::c_long as uint64_t,
                            1301133425678027 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1515728832059182 as libc::c_long as uint64_t,
                            1575261009617579 as libc::c_long as uint64_t,
                            1510246567196186 as libc::c_long as uint64_t,
                            191078022609704 as libc::c_long as uint64_t,
                            116661716289141 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1295295738269652 as libc::c_long as uint64_t,
                            1714742313707026 as libc::c_long as uint64_t,
                            545583042462581 as libc::c_long as uint64_t,
                            2034411676262552 as libc::c_long as uint64_t,
                            1513248090013606 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            230710545179830 as libc::c_long as uint64_t,
                            30821514358353 as libc::c_long as uint64_t,
                            760704303452229 as libc::c_long as uint64_t,
                            390668103790604 as libc::c_long as uint64_t,
                            573437871383156 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1169380107545646 as libc::c_long as uint64_t,
                            263167233745614 as libc::c_long as uint64_t,
                            2022901299054448 as libc::c_long as uint64_t,
                            819900753251120 as libc::c_long as uint64_t,
                            2023898464874585 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2102254323485823 as libc::c_long as uint64_t,
                            1570832666216754 as libc::c_long as uint64_t,
                            34696906544624 as libc::c_long as uint64_t,
                            1993213739807337 as libc::c_long as uint64_t,
                            70638552271463 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            894132856735058 as libc::c_long as uint64_t,
                            548675863558441 as libc::c_long as uint64_t,
                            845349339503395 as libc::c_long as uint64_t,
                            1942269668326667 as libc::c_long as uint64_t,
                            1615682209874691 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1287670217537834 as libc::c_long as uint64_t,
                            1222355136884920 as libc::c_long as uint64_t,
                            1846481788678694 as libc::c_long as uint64_t,
                            1150426571265110 as libc::c_long as uint64_t,
                            1613523400722047 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            793388516527298 as libc::c_long as uint64_t,
                            1315457083650035 as libc::c_long as uint64_t,
                            1972286999342417 as libc::c_long as uint64_t,
                            1901825953052455 as libc::c_long as uint64_t,
                            338269477222410 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            550201530671806 as libc::c_long as uint64_t,
                            778605267108140 as libc::c_long as uint64_t,
                            2063911101902983 as libc::c_long as uint64_t,
                            115500557286349 as libc::c_long as uint64_t,
                            2041641272971022 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            717255318455100 as libc::c_long as uint64_t,
                            519313764361315 as libc::c_long as uint64_t,
                            2080406977303708 as libc::c_long as uint64_t,
                            541981206705521 as libc::c_long as uint64_t,
                            774328150311600 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            261715221532238 as libc::c_long as uint64_t,
                            1795354330069993 as libc::c_long as uint64_t,
                            1496878026850283 as libc::c_long as uint64_t,
                            499739720521052 as libc::c_long as uint64_t,
                            389031152673770 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1997217696294013 as libc::c_long as uint64_t,
                            1717306351628065 as libc::c_long as uint64_t,
                            1684313917746180 as libc::c_long as uint64_t,
                            1644426076011410 as libc::c_long as uint64_t,
                            1857378133465451 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1475434724792648 as libc::c_long as uint64_t,
                            76931896285979 as libc::c_long as uint64_t,
                            1116729029771667 as libc::c_long as uint64_t,
                            2002544139318042 as libc::c_long as uint64_t,
                            725547833803938 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2022306639183567 as libc::c_long as uint64_t,
                            726296063571875 as libc::c_long as uint64_t,
                            315345054448644 as libc::c_long as uint64_t,
                            1058733329149221 as libc::c_long as uint64_t,
                            1448201136060677 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1710065158525665 as libc::c_long as uint64_t,
                            1895094923036397 as libc::c_long as uint64_t,
                            123988286168546 as libc::c_long as uint64_t,
                            1145519900776355 as libc::c_long as uint64_t,
                            1607510767693874 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            561605375422540 as libc::c_long as uint64_t,
                            1071733543815037 as libc::c_long as uint64_t,
                            131496498800990 as libc::c_long as uint64_t,
                            1946868434569999 as libc::c_long as uint64_t,
                            828138133964203 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1548495173745801 as libc::c_long as uint64_t,
                            442310529226540 as libc::c_long as uint64_t,
                            998072547000384 as libc::c_long as uint64_t,
                            553054358385281 as libc::c_long as uint64_t,
                            644824326376171 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1445526537029440 as libc::c_long as uint64_t,
                            2225519789662536 as libc::c_long as uint64_t,
                            914628859347385 as libc::c_long as uint64_t,
                            1064754194555068 as libc::c_long as uint64_t,
                            1660295614401091 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1199690223111956 as libc::c_long as uint64_t,
                            24028135822341 as libc::c_long as uint64_t,
                            66638289244341 as libc::c_long as uint64_t,
                            57626156285975 as libc::c_long as uint64_t,
                            565093967979607 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            876926774220824 as libc::c_long as uint64_t,
                            554618976488214 as libc::c_long as uint64_t,
                            1012056309841565 as libc::c_long as uint64_t,
                            839961821554611 as libc::c_long as uint64_t,
                            1414499340307677 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            703047626104145 as libc::c_long as uint64_t,
                            1266841406201770 as libc::c_long as uint64_t,
                            165556500219173 as libc::c_long as uint64_t,
                            486991595001879 as libc::c_long as uint64_t,
                            1011325891650656 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1622861044480487 as libc::c_long as uint64_t,
                            1156394801573634 as libc::c_long as uint64_t,
                            1869132565415504 as libc::c_long as uint64_t,
                            327103985777730 as libc::c_long as uint64_t,
                            2095342781472284 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            334886927423922 as libc::c_long as uint64_t,
                            489511099221528 as libc::c_long as uint64_t,
                            129160865966726 as libc::c_long as uint64_t,
                            1720809113143481 as libc::c_long as uint64_t,
                            619700195649254 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1646545795166119 as libc::c_long as uint64_t,
                            1758370782583567 as libc::c_long as uint64_t,
                            714746174550637 as libc::c_long as uint64_t,
                            1472693650165135 as libc::c_long as uint64_t,
                            898994790308209 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            333403773039279 as libc::c_long as uint64_t,
                            295772542452938 as libc::c_long as uint64_t,
                            1693106465353610 as libc::c_long as uint64_t,
                            912330357530760 as libc::c_long as uint64_t,
                            471235657950362 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1811196219982022 as libc::c_long as uint64_t,
                            1068969825533602 as libc::c_long as uint64_t,
                            289602974833439 as libc::c_long as uint64_t,
                            1988956043611592 as libc::c_long as uint64_t,
                            863562343398367 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            906282429780072 as libc::c_long as uint64_t,
                            2108672665779781 as libc::c_long as uint64_t,
                            432396390473936 as libc::c_long as uint64_t,
                            150625823801893 as libc::c_long as uint64_t,
                            1708930497638539 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            925664675702328 as libc::c_long as uint64_t,
                            21416848568684 as libc::c_long as uint64_t,
                            1831436641861340 as libc::c_long as uint64_t,
                            601157008940113 as libc::c_long as uint64_t,
                            371818055044496 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1479786007267725 as libc::c_long as uint64_t,
                            1738881859066675 as libc::c_long as uint64_t,
                            68646196476567 as libc::c_long as uint64_t,
                            2146507056100328 as libc::c_long as uint64_t,
                            1247662817535471 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            52035296774456 as libc::c_long as uint64_t,
                            939969390708103 as libc::c_long as uint64_t,
                            312023458773250 as libc::c_long as uint64_t,
                            59873523517659 as libc::c_long as uint64_t,
                            1231345905848899 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            643355106415761 as libc::c_long as uint64_t,
                            290186807495774 as libc::c_long as uint64_t,
                            2013561737429023 as libc::c_long as uint64_t,
                            319648069511546 as libc::c_long as uint64_t,
                            393736678496162 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            129358342392716 as libc::c_long as uint64_t,
                            1932811617704777 as libc::c_long as uint64_t,
                            1176749390799681 as libc::c_long as uint64_t,
                            398040349861790 as libc::c_long as uint64_t,
                            1170779668090425 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2051980782668029 as libc::c_long as uint64_t,
                            121859921510665 as libc::c_long as uint64_t,
                            2048329875753063 as libc::c_long as uint64_t,
                            1235229850149665 as libc::c_long as uint64_t,
                            519062146124755 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1608170971973096 as libc::c_long as uint64_t,
                            415809060360428 as libc::c_long as uint64_t,
                            1350468408164766 as libc::c_long as uint64_t,
                            2038620059057678 as libc::c_long as uint64_t,
                            1026904485989112 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1837656083115103 as libc::c_long as uint64_t,
                            1510134048812070 as libc::c_long as uint64_t,
                            906263674192061 as libc::c_long as uint64_t,
                            1821064197805734 as libc::c_long as uint64_t,
                            565375124676301 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            578027192365650 as libc::c_long as uint64_t,
                            2034800251375322 as libc::c_long as uint64_t,
                            2128954087207123 as libc::c_long as uint64_t,
                            478816193810521 as libc::c_long as uint64_t,
                            2196171989962750 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1633188840273139 as libc::c_long as uint64_t,
                            852787172373708 as libc::c_long as uint64_t,
                            1548762607215796 as libc::c_long as uint64_t,
                            1266275218902681 as libc::c_long as uint64_t,
                            1107218203325133 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            462189358480054 as libc::c_long as uint64_t,
                            1784816734159228 as libc::c_long as uint64_t,
                            1611334301651368 as libc::c_long as uint64_t,
                            1303938263943540 as libc::c_long as uint64_t,
                            707589560319424 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1038829280972848 as libc::c_long as uint64_t,
                            38176604650029 as libc::c_long as uint64_t,
                            753193246598573 as libc::c_long as uint64_t,
                            1136076426528122 as libc::c_long as uint64_t,
                            595709990562434 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1408451820859834 as libc::c_long as uint64_t,
                            2194984964010833 as libc::c_long as uint64_t,
                            2198361797561729 as libc::c_long as uint64_t,
                            1061962440055713 as libc::c_long as uint64_t,
                            1645147963442934 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            4701053362120 as libc::c_long as uint64_t,
                            1647641066302348 as libc::c_long as uint64_t,
                            1047553002242085 as libc::c_long as uint64_t,
                            1923635013395977 as libc::c_long as uint64_t,
                            206970314902065 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1750479161778571 as libc::c_long as uint64_t,
                            1362553355169293 as libc::c_long as uint64_t,
                            1891721260220598 as libc::c_long as uint64_t,
                            966109370862782 as libc::c_long as uint64_t,
                            1024913988299801 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            212699049131723 as libc::c_long as uint64_t,
                            1117950018299775 as libc::c_long as uint64_t,
                            1873945661751056 as libc::c_long as uint64_t,
                            1403802921984058 as libc::c_long as uint64_t,
                            130896082652698 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            636808533673210 as libc::c_long as uint64_t,
                            1262201711667560 as libc::c_long as uint64_t,
                            390951380330599 as libc::c_long as uint64_t,
                            1663420692697294 as libc::c_long as uint64_t,
                            561951321757406 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            520731594438141 as libc::c_long as uint64_t,
                            1446301499955692 as libc::c_long as uint64_t,
                            273753264629267 as libc::c_long as uint64_t,
                            1565101517999256 as libc::c_long as uint64_t,
                            1019411827004672 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            926527492029409 as libc::c_long as uint64_t,
                            1191853477411379 as libc::c_long as uint64_t,
                            734233225181171 as libc::c_long as uint64_t,
                            184038887541270 as libc::c_long as uint64_t,
                            1790426146325343 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1464651961852572 as libc::c_long as uint64_t,
                            1483737295721717 as libc::c_long as uint64_t,
                            1519450561335517 as libc::c_long as uint64_t,
                            1161429831763785 as libc::c_long as uint64_t,
                            405914998179977 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            996126634382301 as libc::c_long as uint64_t,
                            796204125879525 as libc::c_long as uint64_t,
                            127517800546509 as libc::c_long as uint64_t,
                            344155944689303 as libc::c_long as uint64_t,
                            615279846169038 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            738724080975276 as libc::c_long as uint64_t,
                            2188666632415296 as libc::c_long as uint64_t,
                            1961313708559162 as libc::c_long as uint64_t,
                            1506545807547587 as libc::c_long as uint64_t,
                            1151301638969740 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            622917337413835 as libc::c_long as uint64_t,
                            1218989177089035 as libc::c_long as uint64_t,
                            1284857712846592 as libc::c_long as uint64_t,
                            970502061709359 as libc::c_long as uint64_t,
                            351025208117090 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2067814584765580 as libc::c_long as uint64_t,
                            1677855129927492 as libc::c_long as uint64_t,
                            2086109782475197 as libc::c_long as uint64_t,
                            235286517313238 as libc::c_long as uint64_t,
                            1416314046739645 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            586844262630358 as libc::c_long as uint64_t,
                            307444381952195 as libc::c_long as uint64_t,
                            458399356043426 as libc::c_long as uint64_t,
                            602068024507062 as libc::c_long as uint64_t,
                            1028548203415243 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            678489922928203 as libc::c_long as uint64_t,
                            2016657584724032 as libc::c_long as uint64_t,
                            90977383049628 as libc::c_long as uint64_t,
                            1026831907234582 as libc::c_long as uint64_t,
                            615271492942522 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            301225714012278 as libc::c_long as uint64_t,
                            1094837270268560 as libc::c_long as uint64_t,
                            1202288391010439 as libc::c_long as uint64_t,
                            644352775178361 as libc::c_long as uint64_t,
                            1647055902137983 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1210746697896478 as libc::c_long as uint64_t,
                            1416608304244708 as libc::c_long as uint64_t,
                            686487477217856 as libc::c_long as uint64_t,
                            1245131191434135 as libc::c_long as uint64_t,
                            1051238336855737 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1135604073198207 as libc::c_long as uint64_t,
                            1683322080485474 as libc::c_long as uint64_t,
                            769147804376683 as libc::c_long as uint64_t,
                            2086688130589414 as libc::c_long as uint64_t,
                            900445683120379 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1971518477615628 as libc::c_long as uint64_t,
                            401909519527336 as libc::c_long as uint64_t,
                            448627091057375 as libc::c_long as uint64_t,
                            1409486868273821 as libc::c_long as uint64_t,
                            1214789035034363 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1364039144731711 as libc::c_long as uint64_t,
                            1897497433586190 as libc::c_long as uint64_t,
                            2203097701135459 as libc::c_long as uint64_t,
                            145461396811251 as libc::c_long as uint64_t,
                            1349844460790699 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1045230323257973 as libc::c_long as uint64_t,
                            818206601145807 as libc::c_long as uint64_t,
                            630513189076103 as libc::c_long as uint64_t,
                            1672046528998132 as libc::c_long as uint64_t,
                            807204017562437 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            439961968385997 as libc::c_long as uint64_t,
                            386362664488986 as libc::c_long as uint64_t,
                            1382706320807688 as libc::c_long as uint64_t,
                            309894000125359 as libc::c_long as uint64_t,
                            2207801346498567 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1229004686397588 as libc::c_long as uint64_t,
                            920643968530863 as libc::c_long as uint64_t,
                            123975893911178 as libc::c_long as uint64_t,
                            681423993215777 as libc::c_long as uint64_t,
                            1400559197080973 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2003766096898049 as libc::c_long as uint64_t,
                            170074059235165 as libc::c_long as uint64_t,
                            1141124258967971 as libc::c_long as uint64_t,
                            1485419893480973 as libc::c_long as uint64_t,
                            1573762821028725 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            729905708611432 as libc::c_long as uint64_t,
                            1270323270673202 as libc::c_long as uint64_t,
                            123353058984288 as libc::c_long as uint64_t,
                            426460209632942 as libc::c_long as uint64_t,
                            2195574535456672 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1271140255321235 as libc::c_long as uint64_t,
                            2044363183174497 as libc::c_long as uint64_t,
                            52125387634689 as libc::c_long as uint64_t,
                            1445120246694705 as libc::c_long as uint64_t,
                            942541986339084 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1761608437466135 as libc::c_long as uint64_t,
                            583360847526804 as libc::c_long as uint64_t,
                            1586706389685493 as libc::c_long as uint64_t,
                            2157056599579261 as libc::c_long as uint64_t,
                            1170692369685772 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            871476219910823 as libc::c_long as uint64_t,
                            1878769545097794 as libc::c_long as uint64_t,
                            2241832391238412 as libc::c_long as uint64_t,
                            548957640601001 as libc::c_long as uint64_t,
                            690047440233174 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            297194732135507 as libc::c_long as uint64_t,
                            1366347803776820 as libc::c_long as uint64_t,
                            1301185512245601 as libc::c_long as uint64_t,
                            561849853336294 as libc::c_long as uint64_t,
                            1533554921345731 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            999628998628371 as libc::c_long as uint64_t,
                            1132836708493400 as libc::c_long as uint64_t,
                            2084741674517453 as libc::c_long as uint64_t,
                            469343353015612 as libc::c_long as uint64_t,
                            678782988708035 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2189427607417022 as libc::c_long as uint64_t,
                            699801937082607 as libc::c_long as uint64_t,
                            412764402319267 as libc::c_long as uint64_t,
                            1478091893643349 as libc::c_long as uint64_t,
                            2244675696854460 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1712292055966563 as libc::c_long as uint64_t,
                            204413590624874 as libc::c_long as uint64_t,
                            1405738637332841 as libc::c_long as uint64_t,
                            408981300829763 as libc::c_long as uint64_t,
                            861082219276721 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            508561155940631 as libc::c_long as uint64_t,
                            966928475686665 as libc::c_long as uint64_t,
                            2236717801150132 as libc::c_long as uint64_t,
                            424543858577297 as libc::c_long as uint64_t,
                            2089272956986143 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            221245220129925 as libc::c_long as uint64_t,
                            1156020201681217 as libc::c_long as uint64_t,
                            491145634799213 as libc::c_long as uint64_t,
                            542422431960839 as libc::c_long as uint64_t,
                            828100817819207 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            153756971240384 as libc::c_long as uint64_t,
                            1299874139923977 as libc::c_long as uint64_t,
                            393099165260502 as libc::c_long as uint64_t,
                            1058234455773022 as libc::c_long as uint64_t,
                            996989038681183 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            559086812798481 as libc::c_long as uint64_t,
                            573177704212711 as libc::c_long as uint64_t,
                            1629737083816402 as libc::c_long as uint64_t,
                            1399819713462595 as libc::c_long as uint64_t,
                            1646954378266038 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1887963056288059 as libc::c_long as uint64_t,
                            228507035730124 as libc::c_long as uint64_t,
                            1468368348640282 as libc::c_long as uint64_t,
                            930557653420194 as libc::c_long as uint64_t,
                            613513962454686 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1224529808187553 as libc::c_long as uint64_t,
                            1577022856702685 as libc::c_long as uint64_t,
                            2206946542980843 as libc::c_long as uint64_t,
                            625883007765001 as libc::c_long as uint64_t,
                            279930793512158 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1076287717051609 as libc::c_long as uint64_t,
                            1114455570543035 as libc::c_long as uint64_t,
                            187297059715481 as libc::c_long as uint64_t,
                            250446884292121 as libc::c_long as uint64_t,
                            1885187512550540 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            902497362940219 as libc::c_long as uint64_t,
                            76749815795675 as libc::c_long as uint64_t,
                            1657927525633846 as libc::c_long as uint64_t,
                            1420238379745202 as libc::c_long as uint64_t,
                            1340321636548352 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1129576631190784 as libc::c_long as uint64_t,
                            1281994010027327 as libc::c_long as uint64_t,
                            996844254743018 as libc::c_long as uint64_t,
                            257876363489249 as libc::c_long as uint64_t,
                            1150850742055018 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            628740660038789 as libc::c_long as uint64_t,
                            1943038498527841 as libc::c_long as uint64_t,
                            467786347793886 as libc::c_long as uint64_t,
                            1093341428303375 as libc::c_long as uint64_t,
                            235413859513003 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            237425418909360 as libc::c_long as uint64_t,
                            469614029179605 as libc::c_long as uint64_t,
                            1512389769174935 as libc::c_long as uint64_t,
                            1241726368345357 as libc::c_long as uint64_t,
                            441602891065214 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1736417953058555 as libc::c_long as uint64_t,
                            726531315520508 as libc::c_long as uint64_t,
                            1833335034432527 as libc::c_long as uint64_t,
                            1629442561574747 as libc::c_long as uint64_t,
                            624418919286085 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1960754663920689 as libc::c_long as uint64_t,
                            497040957888962 as libc::c_long as uint64_t,
                            1909832851283095 as libc::c_long as uint64_t,
                            1271432136996826 as libc::c_long as uint64_t,
                            2219780368020940 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1537037379417136 as libc::c_long as uint64_t,
                            1358865369268262 as libc::c_long as uint64_t,
                            2130838645654099 as libc::c_long as uint64_t,
                            828733687040705 as libc::c_long as uint64_t,
                            1999987652890901 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            629042105241814 as libc::c_long as uint64_t,
                            1098854999137608 as libc::c_long as uint64_t,
                            887281544569320 as libc::c_long as uint64_t,
                            1423102019874777 as libc::c_long as uint64_t,
                            7911258951561 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1811562332665373 as libc::c_long as uint64_t,
                            1501882019007673 as libc::c_long as uint64_t,
                            2213763501088999 as libc::c_long as uint64_t,
                            359573079719636 as libc::c_long as uint64_t,
                            36370565049116 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            218907117361280 as libc::c_long as uint64_t,
                            1209298913016966 as libc::c_long as uint64_t,
                            1944312619096112 as libc::c_long as uint64_t,
                            1130690631451061 as libc::c_long as uint64_t,
                            1342327389191701 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1369976867854704 as libc::c_long as uint64_t,
                            1396479602419169 as libc::c_long as uint64_t,
                            1765656654398856 as libc::c_long as uint64_t,
                            2203659200586299 as libc::c_long as uint64_t,
                            998327836117241 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2230701885562825 as libc::c_long as uint64_t,
                            1348173180338974 as libc::c_long as uint64_t,
                            2172856128624598 as libc::c_long as uint64_t,
                            1426538746123771 as libc::c_long as uint64_t,
                            444193481326151 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            784210426627951 as libc::c_long as uint64_t,
                            918204562375674 as libc::c_long as uint64_t,
                            1284546780452985 as libc::c_long as uint64_t,
                            1324534636134684 as libc::c_long as uint64_t,
                            1872449409642708 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            319638829540294 as libc::c_long as uint64_t,
                            596282656808406 as libc::c_long as uint64_t,
                            2037902696412608 as libc::c_long as uint64_t,
                            1557219121643918 as libc::c_long as uint64_t,
                            341938082688094 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1901860206695915 as libc::c_long as uint64_t,
                            2004489122065736 as libc::c_long as uint64_t,
                            1625847061568236 as libc::c_long as uint64_t,
                            973529743399879 as libc::c_long as uint64_t,
                            2075287685312905 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1371853944110545 as libc::c_long as uint64_t,
                            1042332820512553 as libc::c_long as uint64_t,
                            1949855697918254 as libc::c_long as uint64_t,
                            1791195775521505 as libc::c_long as uint64_t,
                            37487364849293 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            687200189577855 as libc::c_long as uint64_t,
                            1082536651125675 as libc::c_long as uint64_t,
                            644224940871546 as libc::c_long as uint64_t,
                            340923196057951 as libc::c_long as uint64_t,
                            343581346747396 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2082717129583892 as libc::c_long as uint64_t,
                            27829425539422 as libc::c_long as uint64_t,
                            145655066671970 as libc::c_long as uint64_t,
                            1690527209845512 as libc::c_long as uint64_t,
                            1865260509673478 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1059729620568824 as libc::c_long as uint64_t,
                            2163709103470266 as libc::c_long as uint64_t,
                            1440302280256872 as libc::c_long as uint64_t,
                            1769143160546397 as libc::c_long as uint64_t,
                            869830310425069 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1609516219779025 as libc::c_long as uint64_t,
                            777277757338817 as libc::c_long as uint64_t,
                            2101121130363987 as libc::c_long as uint64_t,
                            550762194946473 as libc::c_long as uint64_t,
                            1905542338659364 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2024821921041576 as libc::c_long as uint64_t,
                            426948675450149 as libc::c_long as uint64_t,
                            595133284085473 as libc::c_long as uint64_t,
                            471860860885970 as libc::c_long as uint64_t,
                            600321679413000 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            598474602406721 as libc::c_long as uint64_t,
                            1468128276358244 as libc::c_long as uint64_t,
                            1191923149557635 as libc::c_long as uint64_t,
                            1501376424093216 as libc::c_long as uint64_t,
                            1281662691293476 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1721138489890707 as libc::c_long as uint64_t,
                            1264336102277790 as libc::c_long as uint64_t,
                            433064545421287 as libc::c_long as uint64_t,
                            1359988423149466 as libc::c_long as uint64_t,
                            1561871293409447 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            719520245587143 as libc::c_long as uint64_t,
                            393380711632345 as libc::c_long as uint64_t,
                            132350400863381 as libc::c_long as uint64_t,
                            1543271270810729 as libc::c_long as uint64_t,
                            1819543295798660 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            396397949784152 as libc::c_long as uint64_t,
                            1811354474471839 as libc::c_long as uint64_t,
                            1362679985304303 as libc::c_long as uint64_t,
                            2117033964846756 as libc::c_long as uint64_t,
                            498041172552279 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1812471844975748 as libc::c_long as uint64_t,
                            1856491995543149 as libc::c_long as uint64_t,
                            126579494584102 as libc::c_long as uint64_t,
                            1036244859282620 as libc::c_long as uint64_t,
                            1975108050082550 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            650623932407995 as libc::c_long as uint64_t,
                            1137551288410575 as libc::c_long as uint64_t,
                            2125223403615539 as libc::c_long as uint64_t,
                            1725658013221271 as libc::c_long as uint64_t,
                            2134892965117796 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            522584000310195 as libc::c_long as uint64_t,
                            1241762481390450 as libc::c_long as uint64_t,
                            1743702789495384 as libc::c_long as uint64_t,
                            2227404127826575 as libc::c_long as uint64_t,
                            1686746002148897 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            427904865186312 as libc::c_long as uint64_t,
                            1703211129693455 as libc::c_long as uint64_t,
                            1585368107547509 as libc::c_long as uint64_t,
                            1436984488744336 as libc::c_long as uint64_t,
                            761188534613978 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            318101947455002 as libc::c_long as uint64_t,
                            248138407995851 as libc::c_long as uint64_t,
                            1481904195303927 as libc::c_long as uint64_t,
                            309278454311197 as libc::c_long as uint64_t,
                            1258516760217879 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1275068538599310 as libc::c_long as uint64_t,
                            513726919533379 as libc::c_long as uint64_t,
                            349926553492294 as libc::c_long as uint64_t,
                            688428871968420 as libc::c_long as uint64_t,
                            1702400196000666 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1061864036265233 as libc::c_long as uint64_t,
                            961611260325381 as libc::c_long as uint64_t,
                            321859632700838 as libc::c_long as uint64_t,
                            1045600629959517 as libc::c_long as uint64_t,
                            1985130202504038 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1558816436882417 as libc::c_long as uint64_t,
                            1962896332636523 as libc::c_long as uint64_t,
                            1337709822062152 as libc::c_long as uint64_t,
                            1501413830776938 as libc::c_long as uint64_t,
                            294436165831932 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            818359826554971 as libc::c_long as uint64_t,
                            1862173000996177 as libc::c_long as uint64_t,
                            626821592884859 as libc::c_long as uint64_t,
                            573655738872376 as libc::c_long as uint64_t,
                            1749691246745455 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1988022651432119 as libc::c_long as uint64_t,
                            1082111498586040 as libc::c_long as uint64_t,
                            1834020786104821 as libc::c_long as uint64_t,
                            1454826876423687 as libc::c_long as uint64_t,
                            692929915223122 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2146513703733331 as libc::c_long as uint64_t,
                            584788900394667 as libc::c_long as uint64_t,
                            464965657279958 as libc::c_long as uint64_t,
                            2183973639356127 as libc::c_long as uint64_t,
                            238371159456790 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1129007025494441 as libc::c_long as uint64_t,
                            2197883144413266 as libc::c_long as uint64_t,
                            265142755578169 as libc::c_long as uint64_t,
                            971864464758890 as libc::c_long as uint64_t,
                            1983715884903702 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1291366624493075 as libc::c_long as uint64_t,
                            381456718189114 as libc::c_long as uint64_t,
                            1711482489312444 as libc::c_long as uint64_t,
                            1815233647702022 as libc::c_long as uint64_t,
                            892279782992467 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            444548969917454 as libc::c_long as uint64_t,
                            1452286453853356 as libc::c_long as uint64_t,
                            2113731441506810 as libc::c_long as uint64_t,
                            645188273895859 as libc::c_long as uint64_t,
                            810317625309512 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2242724082797924 as libc::c_long as uint64_t,
                            1373354730327868 as libc::c_long as uint64_t,
                            1006520110883049 as libc::c_long as uint64_t,
                            2147330369940688 as libc::c_long as uint64_t,
                            1151816104883620 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1745720200383796 as libc::c_long as uint64_t,
                            1911723143175317 as libc::c_long as uint64_t,
                            2056329390702074 as libc::c_long as uint64_t,
                            355227174309849 as libc::c_long as uint64_t,
                            879232794371100 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            163723479936298 as libc::c_long as uint64_t,
                            115424889803150 as libc::c_long as uint64_t,
                            1156016391581227 as libc::c_long as uint64_t,
                            1894942220753364 as libc::c_long as uint64_t,
                            1970549419986329 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            681981452362484 as libc::c_long as uint64_t,
                            267208874112496 as libc::c_long as uint64_t,
                            1374683991933094 as libc::c_long as uint64_t,
                            638600984916117 as libc::c_long as uint64_t,
                            646178654558546 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            13378654854251 as libc::c_long as uint64_t,
                            106237307029567 as libc::c_long as uint64_t,
                            1944412051589651 as libc::c_long as uint64_t,
                            1841976767925457 as libc::c_long as uint64_t,
                            230702819835573 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            260683893467075 as libc::c_long as uint64_t,
                            854060306077237 as libc::c_long as uint64_t,
                            913639551980112 as libc::c_long as uint64_t,
                            4704576840123 as libc::c_long as uint64_t,
                            280254810808712 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            715374893080287 as libc::c_long as uint64_t,
                            1173334812210491 as libc::c_long as uint64_t,
                            1806524662079626 as libc::c_long as uint64_t,
                            1894596008000979 as libc::c_long as uint64_t,
                            398905715033393 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            500026409727661 as libc::c_long as uint64_t,
                            1596431288195371 as libc::c_long as uint64_t,
                            1420380351989370 as libc::c_long as uint64_t,
                            985211561521489 as libc::c_long as uint64_t,
                            392444930785633 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2096421546958141 as libc::c_long as uint64_t,
                            1922523000950363 as libc::c_long as uint64_t,
                            789831022876840 as libc::c_long as uint64_t,
                            427295144688779 as libc::c_long as uint64_t,
                            320923973161730 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1927770723575450 as libc::c_long as uint64_t,
                            1485792977512719 as libc::c_long as uint64_t,
                            1850996108474547 as libc::c_long as uint64_t,
                            551696031508956 as libc::c_long as uint64_t,
                            2126047405475647 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2112099158080148 as libc::c_long as uint64_t,
                            742570803909715 as libc::c_long as uint64_t,
                            6484558077432 as libc::c_long as uint64_t,
                            1951119898618916 as libc::c_long as uint64_t,
                            93090382703416 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            383905201636970 as libc::c_long as uint64_t,
                            859946997631870 as libc::c_long as uint64_t,
                            855623867637644 as libc::c_long as uint64_t,
                            1017125780577795 as libc::c_long as uint64_t,
                            794250831877809 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            77571826285752 as libc::c_long as uint64_t,
                            999304298101753 as libc::c_long as uint64_t,
                            487841111777762 as libc::c_long as uint64_t,
                            1038031143212339 as libc::c_long as uint64_t,
                            339066367948762 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            674994775520533 as libc::c_long as uint64_t,
                            266035846330789 as libc::c_long as uint64_t,
                            826951213393478 as libc::c_long as uint64_t,
                            1405007746162285 as libc::c_long as uint64_t,
                            1781791018620876 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1001412661522686 as libc::c_long as uint64_t,
                            348196197067298 as libc::c_long as uint64_t,
                            1666614366723946 as libc::c_long as uint64_t,
                            888424995032760 as libc::c_long as uint64_t,
                            580747687801357 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1939560076207777 as libc::c_long as uint64_t,
                            1409892634407635 as libc::c_long as uint64_t,
                            552574736069277 as libc::c_long as uint64_t,
                            383854338280405 as libc::c_long as uint64_t,
                            190706709864139 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2177087163428741 as libc::c_long as uint64_t,
                            1439255351721944 as libc::c_long as uint64_t,
                            1208070840382793 as libc::c_long as uint64_t,
                            2230616362004769 as libc::c_long as uint64_t,
                            1396886392021913 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            676962063230039 as libc::c_long as uint64_t,
                            1880275537148808 as libc::c_long as uint64_t,
                            2046721011602706 as libc::c_long as uint64_t,
                            888463247083003 as libc::c_long as uint64_t,
                            1318301552024067 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1466980508178206 as libc::c_long as uint64_t,
                            617045217998949 as libc::c_long as uint64_t,
                            652303580573628 as libc::c_long as uint64_t,
                            757303753529064 as libc::c_long as uint64_t,
                            207583137376902 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1511056752906902 as libc::c_long as uint64_t,
                            105403126891277 as libc::c_long as uint64_t,
                            493434892772846 as libc::c_long as uint64_t,
                            1091943425335976 as libc::c_long as uint64_t,
                            1802717338077427 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1853982405405128 as libc::c_long as uint64_t,
                            1878664056251147 as libc::c_long as uint64_t,
                            1528011020803992 as libc::c_long as uint64_t,
                            1019626468153565 as libc::c_long as uint64_t,
                            1128438412189035 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1963939888391106 as libc::c_long as uint64_t,
                            293456433791664 as libc::c_long as uint64_t,
                            697897559513649 as libc::c_long as uint64_t,
                            985882796904380 as libc::c_long as uint64_t,
                            796244541237972 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            416770998629779 as libc::c_long as uint64_t,
                            389655552427054 as libc::c_long as uint64_t,
                            1314476859406756 as libc::c_long as uint64_t,
                            1749382513022778 as libc::c_long as uint64_t,
                            1161905598739491 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1428358296490651 as libc::c_long as uint64_t,
                            1027115282420478 as libc::c_long as uint64_t,
                            304840698058337 as libc::c_long as uint64_t,
                            441410174026628 as libc::c_long as uint64_t,
                            1819358356278573 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            204943430200135 as libc::c_long as uint64_t,
                            1554861433819175 as libc::c_long as uint64_t,
                            216426658514651 as libc::c_long as uint64_t,
                            264149070665950 as libc::c_long as uint64_t,
                            2047097371738319 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1934415182909034 as libc::c_long as uint64_t,
                            1393285083565062 as libc::c_long as uint64_t,
                            516409331772960 as libc::c_long as uint64_t,
                            1157690734993892 as libc::c_long as uint64_t,
                            121039666594268 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            662035583584445 as libc::c_long as uint64_t,
                            286736105093098 as libc::c_long as uint64_t,
                            1131773000510616 as libc::c_long as uint64_t,
                            818494214211439 as libc::c_long as uint64_t,
                            472943792054479 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            665784778135882 as libc::c_long as uint64_t,
                            1893179629898606 as libc::c_long as uint64_t,
                            808313193813106 as libc::c_long as uint64_t,
                            276797254706413 as libc::c_long as uint64_t,
                            1563426179676396 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            945205108984232 as libc::c_long as uint64_t,
                            526277562959295 as libc::c_long as uint64_t,
                            1324180513733566 as libc::c_long as uint64_t,
                            1666970227868664 as libc::c_long as uint64_t,
                            153547609289173 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2031433403516252 as libc::c_long as uint64_t,
                            203996615228162 as libc::c_long as uint64_t,
                            170487168837083 as libc::c_long as uint64_t,
                            981513604791390 as libc::c_long as uint64_t,
                            843573964916831 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1476570093962618 as libc::c_long as uint64_t,
                            838514669399805 as libc::c_long as uint64_t,
                            1857930577281364 as libc::c_long as uint64_t,
                            2017007352225784 as libc::c_long as uint64_t,
                            317085545220047 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1461557121912842 as libc::c_long as uint64_t,
                            1600674043318359 as libc::c_long as uint64_t,
                            2157134900399597 as libc::c_long as uint64_t,
                            1670641601940616 as libc::c_long as uint64_t,
                            127765583803283 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1293543509393474 as libc::c_long as uint64_t,
                            2143624609202546 as libc::c_long as uint64_t,
                            1058361566797508 as libc::c_long as uint64_t,
                            214097127393994 as libc::c_long as uint64_t,
                            946888515472729 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            357067959932916 as libc::c_long as uint64_t,
                            1290876214345711 as libc::c_long as uint64_t,
                            521245575443703 as libc::c_long as uint64_t,
                            1494975468601005 as libc::c_long as uint64_t,
                            800942377643885 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            566116659100033 as libc::c_long as uint64_t,
                            820247422481740 as libc::c_long as uint64_t,
                            994464017954148 as libc::c_long as uint64_t,
                            327157611686365 as libc::c_long as uint64_t,
                            92591318111744 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            617256647603209 as libc::c_long as uint64_t,
                            1652107761099439 as libc::c_long as uint64_t,
                            1857213046645471 as libc::c_long as uint64_t,
                            1085597175214970 as libc::c_long as uint64_t,
                            817432759830522 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            771808161440705 as libc::c_long as uint64_t,
                            1323510426395069 as libc::c_long as uint64_t,
                            680497615846440 as libc::c_long as uint64_t,
                            851580615547985 as libc::c_long as uint64_t,
                            1320806384849017 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1219260086131915 as libc::c_long as uint64_t,
                            647169006596815 as libc::c_long as uint64_t,
                            79601124759706 as libc::c_long as uint64_t,
                            2161724213426748 as libc::c_long as uint64_t,
                            404861897060198 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1327968293887866 as libc::c_long as uint64_t,
                            1335500852943256 as libc::c_long as uint64_t,
                            1401587164534264 as libc::c_long as uint64_t,
                            558137311952440 as libc::c_long as uint64_t,
                            1551360549268902 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            417621685193956 as libc::c_long as uint64_t,
                            1429953819744454 as libc::c_long as uint64_t,
                            396157358457099 as libc::c_long as uint64_t,
                            1940470778873255 as libc::c_long as uint64_t,
                            214000046234152 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1268047918491973 as libc::c_long as uint64_t,
                            2172375426948536 as libc::c_long as uint64_t,
                            1533916099229249 as libc::c_long as uint64_t,
                            1761293575457130 as libc::c_long as uint64_t,
                            1590622667026765 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1627072914981959 as libc::c_long as uint64_t,
                            2211603081280073 as libc::c_long as uint64_t,
                            1912369601616504 as libc::c_long as uint64_t,
                            1191770436221309 as libc::c_long as uint64_t,
                            2187309757525860 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1149147819689533 as libc::c_long as uint64_t,
                            378692712667677 as libc::c_long as uint64_t,
                            828475842424202 as libc::c_long as uint64_t,
                            2218619146419342 as libc::c_long as uint64_t,
                            70688125792186 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1299739417079761 as libc::c_long as uint64_t,
                            1438616663452759 as libc::c_long as uint64_t,
                            1536729078504412 as libc::c_long as uint64_t,
                            2053896748919838 as libc::c_long as uint64_t,
                            1008421032591246 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2040723824657366 as libc::c_long as uint64_t,
                            399555637875075 as libc::c_long as uint64_t,
                            632543375452995 as libc::c_long as uint64_t,
                            872649937008051 as libc::c_long as uint64_t,
                            1235394727030233 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2211311599327900 as libc::c_long as uint64_t,
                            2139787259888175 as libc::c_long as uint64_t,
                            938706616835350 as libc::c_long as uint64_t,
                            12609661139114 as libc::c_long as uint64_t,
                            2081897930719789 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1324994503390450 as libc::c_long as uint64_t,
                            336982330582631 as libc::c_long as uint64_t,
                            1183998925654177 as libc::c_long as uint64_t,
                            1091654665913274 as libc::c_long as uint64_t,
                            48727673971319 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1845522914617879 as libc::c_long as uint64_t,
                            1222198248335542 as libc::c_long as uint64_t,
                            150841072760134 as libc::c_long as uint64_t,
                            1927029069940982 as libc::c_long as uint64_t,
                            1189913404498011 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1079559557592645 as libc::c_long as uint64_t,
                            2215338383666441 as libc::c_long as uint64_t,
                            1903569501302605 as libc::c_long as uint64_t,
                            49033973033940 as libc::c_long as uint64_t,
                            305703433934152 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            94653405416909 as libc::c_long as uint64_t,
                            1386121349852999 as libc::c_long as uint64_t,
                            1062130477891762 as libc::c_long as uint64_t,
                            36553947479274 as libc::c_long as uint64_t,
                            833669648948846 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1432015813136298 as libc::c_long as uint64_t,
                            440364795295369 as libc::c_long as uint64_t,
                            1395647062821501 as libc::c_long as uint64_t,
                            1976874522764578 as libc::c_long as uint64_t,
                            934452372723352 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1296625309219774 as libc::c_long as uint64_t,
                            2068273464883862 as libc::c_long as uint64_t,
                            1858621048097805 as libc::c_long as uint64_t,
                            1492281814208508 as libc::c_long as uint64_t,
                            2235868981918946 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1490330266465570 as libc::c_long as uint64_t,
                            1858795661361448 as libc::c_long as uint64_t,
                            1436241134969763 as libc::c_long as uint64_t,
                            294573218899647 as libc::c_long as uint64_t,
                            1208140011028933 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1282462923712748 as libc::c_long as uint64_t,
                            741885683986255 as libc::c_long as uint64_t,
                            2027754642827561 as libc::c_long as uint64_t,
                            518989529541027 as libc::c_long as uint64_t,
                            1826610009555945 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1525827120027511 as libc::c_long as uint64_t,
                            723686461809551 as libc::c_long as uint64_t,
                            1597702369236987 as libc::c_long as uint64_t,
                            244802101764964 as libc::c_long as uint64_t,
                            1502833890372311 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            113622036244513 as libc::c_long as uint64_t,
                            1233740067745854 as libc::c_long as uint64_t,
                            674109952278496 as libc::c_long as uint64_t,
                            2114345180342965 as libc::c_long as uint64_t,
                            166764512856263 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2041668749310338 as libc::c_long as uint64_t,
                            2184405322203901 as libc::c_long as uint64_t,
                            1633400637611036 as libc::c_long as uint64_t,
                            2110682505536899 as libc::c_long as uint64_t,
                            2048144390084644 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            503058759232932 as libc::c_long as uint64_t,
                            760293024620937 as libc::c_long as uint64_t,
                            2027152777219493 as libc::c_long as uint64_t,
                            666858468148475 as libc::c_long as uint64_t,
                            1539184379870952 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1916168475367211 as libc::c_long as uint64_t,
                            915626432541343 as libc::c_long as uint64_t,
                            883217071712575 as libc::c_long as uint64_t,
                            363427871374304 as libc::c_long as uint64_t,
                            1976029821251593 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            678039535434506 as libc::c_long as uint64_t,
                            570587290189340 as libc::c_long as uint64_t,
                            1605302676614120 as libc::c_long as uint64_t,
                            2147762562875701 as libc::c_long as uint64_t,
                            1706063797091704 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1439489648586438 as libc::c_long as uint64_t,
                            2194580753290951 as libc::c_long as uint64_t,
                            832380563557396 as libc::c_long as uint64_t,
                            561521973970522 as libc::c_long as uint64_t,
                            584497280718389 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            187989455492609 as libc::c_long as uint64_t,
                            681223515948275 as libc::c_long as uint64_t,
                            1933493571072456 as libc::c_long as uint64_t,
                            1872921007304880 as libc::c_long as uint64_t,
                            488162364135671 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1413466089534451 as libc::c_long as uint64_t,
                            410844090765630 as libc::c_long as uint64_t,
                            1397263346404072 as libc::c_long as uint64_t,
                            408227143123410 as libc::c_long as uint64_t,
                            1594561803147811 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2102170800973153 as libc::c_long as uint64_t,
                            719462588665004 as libc::c_long as uint64_t,
                            1479649438510153 as libc::c_long as uint64_t,
                            1097529543970028 as libc::c_long as uint64_t,
                            1302363283777685 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            942065717847195 as libc::c_long as uint64_t,
                            1069313679352961 as libc::c_long as uint64_t,
                            2007341951411051 as libc::c_long as uint64_t,
                            70973416446291 as libc::c_long as uint64_t,
                            1419433790163706 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1146565545556377 as libc::c_long as uint64_t,
                            1661971299445212 as libc::c_long as uint64_t,
                            406681704748893 as libc::c_long as uint64_t,
                            564452436406089 as libc::c_long as uint64_t,
                            1109109865829139 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2214421081775077 as libc::c_long as uint64_t,
                            1165671861210569 as libc::c_long as uint64_t,
                            1890453018796184 as libc::c_long as uint64_t,
                            3556249878661 as libc::c_long as uint64_t,
                            442116172656317 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            753830546620811 as libc::c_long as uint64_t,
                            1666955059895019 as libc::c_long as uint64_t,
                            1530775289309243 as libc::c_long as uint64_t,
                            1119987029104146 as libc::c_long as uint64_t,
                            2164156153857580 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            615171919212796 as libc::c_long as uint64_t,
                            1523849404854568 as libc::c_long as uint64_t,
                            854560460547503 as libc::c_long as uint64_t,
                            2067097370290715 as libc::c_long as uint64_t,
                            1765325848586042 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1094538949313667 as libc::c_long as uint64_t,
                            1796592198908825 as libc::c_long as uint64_t,
                            870221004284388 as libc::c_long as uint64_t,
                            2025558921863561 as libc::c_long as uint64_t,
                            1699010892802384 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1951351290725195 as libc::c_long as uint64_t,
                            1916457206844795 as libc::c_long as uint64_t,
                            198025184438026 as libc::c_long as uint64_t,
                            1909076887557595 as libc::c_long as uint64_t,
                            1938542290318919 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1014323197538413 as libc::c_long as uint64_t,
                            869150639940606 as libc::c_long as uint64_t,
                            1756009942696599 as libc::c_long as uint64_t,
                            1334952557375672 as libc::c_long as uint64_t,
                            1544945379082874 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            764055910920305 as libc::c_long as uint64_t,
                            1603590757375439 as libc::c_long as uint64_t,
                            146805246592357 as libc::c_long as uint64_t,
                            1843313433854297 as libc::c_long as uint64_t,
                            954279890114939 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            80113526615750 as libc::c_long as uint64_t,
                            764536758732259 as libc::c_long as uint64_t,
                            1055139345100233 as libc::c_long as uint64_t,
                            469252651759390 as libc::c_long as uint64_t,
                            617897512431515 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            74497112547268 as libc::c_long as uint64_t,
                            740094153192149 as libc::c_long as uint64_t,
                            1745254631717581 as libc::c_long as uint64_t,
                            727713886503130 as libc::c_long as uint64_t,
                            1283034364416928 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            525892105991110 as libc::c_long as uint64_t,
                            1723776830270342 as libc::c_long as uint64_t,
                            1476444848991936 as libc::c_long as uint64_t,
                            573789489857760 as libc::c_long as uint64_t,
                            133864092632978 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            542611720192581 as libc::c_long as uint64_t,
                            1986812262899321 as libc::c_long as uint64_t,
                            1162535242465837 as libc::c_long as uint64_t,
                            481498966143464 as libc::c_long as uint64_t,
                            544600533583622 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            64123227344372 as libc::c_long as uint64_t,
                            1239927720647794 as libc::c_long as uint64_t,
                            1360722983445904 as libc::c_long as uint64_t,
                            222610813654661 as libc::c_long as uint64_t,
                            62429487187991 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1793193323953132 as libc::c_long as uint64_t,
                            91096687857833 as libc::c_long as uint64_t,
                            70945970938921 as libc::c_long as uint64_t,
                            2158587638946380 as libc::c_long as uint64_t,
                            1537042406482111 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1895854577604609 as libc::c_long as uint64_t,
                            1394895708949416 as libc::c_long as uint64_t,
                            1728548428495944 as libc::c_long as uint64_t,
                            1140864900240149 as libc::c_long as uint64_t,
                            563645333603061 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            141358280486863 as libc::c_long as uint64_t,
                            91435889572504 as libc::c_long as uint64_t,
                            1087208572552643 as libc::c_long as uint64_t,
                            1829599652522921 as libc::c_long as uint64_t,
                            1193307020643647 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1611230858525381 as libc::c_long as uint64_t,
                            950720175540785 as libc::c_long as uint64_t,
                            499589887488610 as libc::c_long as uint64_t,
                            2001656988495019 as libc::c_long as uint64_t,
                            88977313255908 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1189080501479658 as libc::c_long as uint64_t,
                            2184348804772597 as libc::c_long as uint64_t,
                            1040818725742319 as libc::c_long as uint64_t,
                            2018318290311834 as libc::c_long as uint64_t,
                            1712060030915354 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            873966876953756 as libc::c_long as uint64_t,
                            1090638350350440 as libc::c_long as uint64_t,
                            1708559325189137 as libc::c_long as uint64_t,
                            672344594801910 as libc::c_long as uint64_t,
                            1320437969700239 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1508590048271766 as libc::c_long as uint64_t,
                            1131769479776094 as libc::c_long as uint64_t,
                            101550868699323 as libc::c_long as uint64_t,
                            428297785557897 as libc::c_long as uint64_t,
                            561791648661744 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            756417570499462 as libc::c_long as uint64_t,
                            237882279232602 as libc::c_long as uint64_t,
                            2136263418594016 as libc::c_long as uint64_t,
                            1701968045454886 as libc::c_long as uint64_t,
                            703713185137472 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1781187809325462 as libc::c_long as uint64_t,
                            1697624151492346 as libc::c_long as uint64_t,
                            1381393690939988 as libc::c_long as uint64_t,
                            175194132284669 as libc::c_long as uint64_t,
                            1483054666415238 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2175517777364616 as libc::c_long as uint64_t,
                            708781536456029 as libc::c_long as uint64_t,
                            955668231122942 as libc::c_long as uint64_t,
                            1967557500069555 as libc::c_long as uint64_t,
                            2021208005604118 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1115135966606887 as libc::c_long as uint64_t,
                            224217372950782 as libc::c_long as uint64_t,
                            915967306279222 as libc::c_long as uint64_t,
                            593866251291540 as libc::c_long as uint64_t,
                            561747094208006 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1443163092879439 as libc::c_long as uint64_t,
                            391875531646162 as libc::c_long as uint64_t,
                            2180847134654632 as libc::c_long as uint64_t,
                            464538543018753 as libc::c_long as uint64_t,
                            1594098196837178 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            850858855888869 as libc::c_long as uint64_t,
                            319436476624586 as libc::c_long as uint64_t,
                            327807784938441 as libc::c_long as uint64_t,
                            740785849558761 as libc::c_long as uint64_t,
                            17128415486016 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2132756334090067 as libc::c_long as uint64_t,
                            536247820155645 as libc::c_long as uint64_t,
                            48907151276867 as libc::c_long as uint64_t,
                            608473197600695 as libc::c_long as uint64_t,
                            1261689545022784 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1525176236978354 as libc::c_long as uint64_t,
                            974205476721062 as libc::c_long as uint64_t,
                            293436255662638 as libc::c_long as uint64_t,
                            148269621098039 as libc::c_long as uint64_t,
                            137961998433963 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1121075518299410 as libc::c_long as uint64_t,
                            2071745529082111 as libc::c_long as uint64_t,
                            1265567917414828 as libc::c_long as uint64_t,
                            1648196578317805 as libc::c_long as uint64_t,
                            496232102750820 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            122321229299801 as libc::c_long as uint64_t,
                            1022922077493685 as libc::c_long as uint64_t,
                            2001275453369484 as libc::c_long as uint64_t,
                            2017441881607947 as libc::c_long as uint64_t,
                            993205880778002 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            654925550560074 as libc::c_long as uint64_t,
                            1168810995576858 as libc::c_long as uint64_t,
                            575655959430926 as libc::c_long as uint64_t,
                            905758704861388 as libc::c_long as uint64_t,
                            496774564663534 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1954109525779738 as libc::c_long as uint64_t,
                            2117022646152485 as libc::c_long as uint64_t,
                            338102630417180 as libc::c_long as uint64_t,
                            1194140505732026 as libc::c_long as uint64_t,
                            107881734943492 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1714785840001267 as libc::c_long as uint64_t,
                            2036500018681589 as libc::c_long as uint64_t,
                            1876380234251966 as libc::c_long as uint64_t,
                            2056717182974196 as libc::c_long as uint64_t,
                            1645855254384642 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            106431476499341 as libc::c_long as uint64_t,
                            62482972120563 as libc::c_long as uint64_t,
                            1513446655109411 as libc::c_long as uint64_t,
                            807258751769522 as libc::c_long as uint64_t,
                            538491469114 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2002850762893643 as libc::c_long as uint64_t,
                            1243624520538135 as libc::c_long as uint64_t,
                            1486040410574605 as libc::c_long as uint64_t,
                            2184752338181213 as libc::c_long as uint64_t,
                            378495998083531 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            922510868424903 as libc::c_long as uint64_t,
                            1089502620807680 as libc::c_long as uint64_t,
                            402544072617374 as libc::c_long as uint64_t,
                            1131446598479839 as libc::c_long as uint64_t,
                            1290278588136533 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1867998812076769 as libc::c_long as uint64_t,
                            715425053580701 as libc::c_long as uint64_t,
                            39968586461416 as libc::c_long as uint64_t,
                            2173068014586163 as libc::c_long as uint64_t,
                            653822651801304 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            162892278589453 as libc::c_long as uint64_t,
                            182585796682149 as libc::c_long as uint64_t,
                            75093073137630 as libc::c_long as uint64_t,
                            497037941226502 as libc::c_long as uint64_t,
                            133871727117371 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1914596576579670 as libc::c_long as uint64_t,
                            1608999621851578 as libc::c_long as uint64_t,
                            1987629837704609 as libc::c_long as uint64_t,
                            1519655314857977 as libc::c_long as uint64_t,
                            1819193753409464 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1949315551096831 as libc::c_long as uint64_t,
                            1069003344994464 as libc::c_long as uint64_t,
                            1939165033499916 as libc::c_long as uint64_t,
                            1548227205730856 as libc::c_long as uint64_t,
                            1933767655861407 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1730519386931635 as libc::c_long as uint64_t,
                            1393284965610134 as libc::c_long as uint64_t,
                            1597143735726030 as libc::c_long as uint64_t,
                            416032382447158 as libc::c_long as uint64_t,
                            1429665248828629 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            360275475604565 as libc::c_long as uint64_t,
                            547835731063078 as libc::c_long as uint64_t,
                            215360904187529 as libc::c_long as uint64_t,
                            596646739879007 as libc::c_long as uint64_t,
                            332709650425085 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            47602113726801 as libc::c_long as uint64_t,
                            1522314509708010 as libc::c_long as uint64_t,
                            437706261372925 as libc::c_long as uint64_t,
                            814035330438027 as libc::c_long as uint64_t,
                            335930650933545 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1291597595523886 as libc::c_long as uint64_t,
                            1058020588994081 as libc::c_long as uint64_t,
                            402837842324045 as libc::c_long as uint64_t,
                            1363323695882781 as libc::c_long as uint64_t,
                            2105763393033193 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            109521982566564 as libc::c_long as uint64_t,
                            1715257748585139 as libc::c_long as uint64_t,
                            1112231216891516 as libc::c_long as uint64_t,
                            2046641005101484 as libc::c_long as uint64_t,
                            134249157157013 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2156991030936798 as libc::c_long as uint64_t,
                            2227544497153325 as libc::c_long as uint64_t,
                            1869050094431622 as libc::c_long as uint64_t,
                            754875860479115 as libc::c_long as uint64_t,
                            1754242344267058 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1846089562873800 as libc::c_long as uint64_t,
                            98894784984326 as libc::c_long as uint64_t,
                            1412430299204844 as libc::c_long as uint64_t,
                            171351226625762 as libc::c_long as uint64_t,
                            1100604760929008 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            84172382130492 as libc::c_long as uint64_t,
                            499710970700046 as libc::c_long as uint64_t,
                            425749630620778 as libc::c_long as uint64_t,
                            1762872794206857 as libc::c_long as uint64_t,
                            612842602127960 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            868309334532756 as libc::c_long as uint64_t,
                            1703010512741873 as libc::c_long as uint64_t,
                            1952690008738057 as libc::c_long as uint64_t,
                            4325269926064 as libc::c_long as uint64_t,
                            2071083554962116 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            523094549451158 as libc::c_long as uint64_t,
                            401938899487815 as libc::c_long as uint64_t,
                            1407690589076010 as libc::c_long as uint64_t,
                            2022387426254453 as libc::c_long as uint64_t,
                            158660516411257 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            612867287630009 as libc::c_long as uint64_t,
                            448212612103814 as libc::c_long as uint64_t,
                            571629077419196 as libc::c_long as uint64_t,
                            1466796750919376 as libc::c_long as uint64_t,
                            1728478129663858 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1723848973783452 as libc::c_long as uint64_t,
                            2208822520534681 as libc::c_long as uint64_t,
                            1718748322776940 as libc::c_long as uint64_t,
                            1974268454121942 as libc::c_long as uint64_t,
                            1194212502258141 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1254114807944608 as libc::c_long as uint64_t,
                            977770684047110 as libc::c_long as uint64_t,
                            2010756238954993 as libc::c_long as uint64_t,
                            1783628927194099 as libc::c_long as uint64_t,
                            1525962994408256 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            232464058235826 as libc::c_long as uint64_t,
                            1948628555342434 as libc::c_long as uint64_t,
                            1835348780427694 as libc::c_long as uint64_t,
                            1031609499437291 as libc::c_long as uint64_t,
                            64472106918373 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            767338676040683 as libc::c_long as uint64_t,
                            754089548318405 as libc::c_long as uint64_t,
                            1523192045639075 as libc::c_long as uint64_t,
                            435746025122062 as libc::c_long as uint64_t,
                            512692508440385 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1255955808701983 as libc::c_long as uint64_t,
                            1700487367990941 as libc::c_long as uint64_t,
                            1166401238800299 as libc::c_long as uint64_t,
                            1175121994891534 as libc::c_long as uint64_t,
                            1190934801395380 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            349144008168292 as libc::c_long as uint64_t,
                            1337012557669162 as libc::c_long as uint64_t,
                            1475912332999108 as libc::c_long as uint64_t,
                            1321618454900458 as libc::c_long as uint64_t,
                            47611291904320 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            877519947135419 as libc::c_long as uint64_t,
                            2172838026132651 as libc::c_long as uint64_t,
                            272304391224129 as libc::c_long as uint64_t,
                            1655143327559984 as libc::c_long as uint64_t,
                            886229406429814 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            375806028254706 as libc::c_long as uint64_t,
                            214463229793940 as libc::c_long as uint64_t,
                            572906353144089 as libc::c_long as uint64_t,
                            572168269875638 as libc::c_long as uint64_t,
                            697556386112979 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1168827102357844 as libc::c_long as uint64_t,
                            823864273033637 as libc::c_long as uint64_t,
                            2071538752104697 as libc::c_long as uint64_t,
                            788062026895924 as libc::c_long as uint64_t,
                            599578340743362 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1948116082078088 as libc::c_long as uint64_t,
                            2054898304487796 as libc::c_long as uint64_t,
                            2204939184983900 as libc::c_long as uint64_t,
                            210526805152138 as libc::c_long as uint64_t,
                            786593586607626 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1915320147894736 as libc::c_long as uint64_t,
                            156481169009469 as libc::c_long as uint64_t,
                            655050471180417 as libc::c_long as uint64_t,
                            592917090415421 as libc::c_long as uint64_t,
                            2165897438660879 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1726336468579724 as libc::c_long as uint64_t,
                            1119932070398949 as libc::c_long as uint64_t,
                            1929199510967666 as libc::c_long as uint64_t,
                            33918788322959 as libc::c_long as uint64_t,
                            1836837863503150 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            829996854845988 as libc::c_long as uint64_t,
                            217061778005138 as libc::c_long as uint64_t,
                            1686565909803640 as libc::c_long as uint64_t,
                            1346948817219846 as libc::c_long as uint64_t,
                            1723823550730181 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            384301494966394 as libc::c_long as uint64_t,
                            687038900403062 as libc::c_long as uint64_t,
                            2211195391021739 as libc::c_long as uint64_t,
                            254684538421383 as libc::c_long as uint64_t,
                            1245698430589680 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1247567493562688 as libc::c_long as uint64_t,
                            1978182094455847 as libc::c_long as uint64_t,
                            183871474792955 as libc::c_long as uint64_t,
                            806570235643435 as libc::c_long as uint64_t,
                            288461518067916 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1449077384734201 as libc::c_long as uint64_t,
                            38285445457996 as libc::c_long as uint64_t,
                            2136537659177832 as libc::c_long as uint64_t,
                            2146493000841573 as libc::c_long as uint64_t,
                            725161151123125 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1201928866368855 as libc::c_long as uint64_t,
                            800415690605445 as libc::c_long as uint64_t,
                            1703146756828343 as libc::c_long as uint64_t,
                            997278587541744 as libc::c_long as uint64_t,
                            1858284414104014 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            356468809648877 as libc::c_long as uint64_t,
                            782373916933152 as libc::c_long as uint64_t,
                            1718002439402870 as libc::c_long as uint64_t,
                            1392222252219254 as libc::c_long as uint64_t,
                            663171266061951 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            759628738230460 as libc::c_long as uint64_t,
                            1012693474275852 as libc::c_long as uint64_t,
                            353780233086498 as libc::c_long as uint64_t,
                            246080061387552 as libc::c_long as uint64_t,
                            2030378857679162 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2040672435071076 as libc::c_long as uint64_t,
                            888593182036908 as libc::c_long as uint64_t,
                            1298443657189359 as libc::c_long as uint64_t,
                            1804780278521327 as libc::c_long as uint64_t,
                            354070726137060 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1894938527423184 as libc::c_long as uint64_t,
                            1463213041477277 as libc::c_long as uint64_t,
                            474410505497651 as libc::c_long as uint64_t,
                            247294963033299 as libc::c_long as uint64_t,
                            877975941029128 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            207937160991127 as libc::c_long as uint64_t,
                            12966911039119 as libc::c_long as uint64_t,
                            820997788283092 as libc::c_long as uint64_t,
                            1010440472205286 as libc::c_long as uint64_t,
                            1701372890140810 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            218882774543183 as libc::c_long as uint64_t,
                            533427444716285 as libc::c_long as uint64_t,
                            1233243976733245 as libc::c_long as uint64_t,
                            435054256891319 as libc::c_long as uint64_t,
                            1509568989549904 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1888838535711826 as libc::c_long as uint64_t,
                            1052177758340622 as libc::c_long as uint64_t,
                            1213553803324135 as libc::c_long as uint64_t,
                            169182009127332 as libc::c_long as uint64_t,
                            463374268115872 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            299137589460312 as libc::c_long as uint64_t,
                            1594371588983567 as libc::c_long as uint64_t,
                            868058494039073 as libc::c_long as uint64_t,
                            257771590636681 as libc::c_long as uint64_t,
                            1805012993142921 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1806842755664364 as libc::c_long as uint64_t,
                            2098896946025095 as libc::c_long as uint64_t,
                            1356630998422878 as libc::c_long as uint64_t,
                            1458279806348064 as libc::c_long as uint64_t,
                            347755825962072 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1402334161391744 as libc::c_long as uint64_t,
                            1560083671046299 as libc::c_long as uint64_t,
                            1008585416617747 as libc::c_long as uint64_t,
                            1147797150908892 as libc::c_long as uint64_t,
                            1420416683642459 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            665506704253369 as libc::c_long as uint64_t,
                            273770475169863 as libc::c_long as uint64_t,
                            799236974202630 as libc::c_long as uint64_t,
                            848328990077558 as libc::c_long as uint64_t,
                            1811448782807931 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1468412523962641 as libc::c_long as uint64_t,
                            771866649897997 as libc::c_long as uint64_t,
                            1931766110147832 as libc::c_long as uint64_t,
                            799561180078482 as libc::c_long as uint64_t,
                            524837559150077 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2223212657821850 as libc::c_long as uint64_t,
                            630416247363666 as libc::c_long as uint64_t,
                            2144451165500328 as libc::c_long as uint64_t,
                            816911130947791 as libc::c_long as uint64_t,
                            1024351058410032 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1266603897524861 as libc::c_long as uint64_t,
                            156378408858100 as libc::c_long as uint64_t,
                            1275649024228779 as libc::c_long as uint64_t,
                            447738405888420 as libc::c_long as uint64_t,
                            253186462063095 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2022215964509735 as libc::c_long as uint64_t,
                            136144366993649 as libc::c_long as uint64_t,
                            1800716593296582 as libc::c_long as uint64_t,
                            1193970603800203 as libc::c_long as uint64_t,
                            871675847064218 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1862751661970328 as libc::c_long as uint64_t,
                            851596246739884 as libc::c_long as uint64_t,
                            1519315554814041 as libc::c_long as uint64_t,
                            1542798466547449 as libc::c_long as uint64_t,
                            1417975335901520 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1228168094547481 as libc::c_long as uint64_t,
                            334133883362894 as libc::c_long as uint64_t,
                            587567568420081 as libc::c_long as uint64_t,
                            433612590281181 as libc::c_long as uint64_t,
                            603390400373205 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            121893973206505 as libc::c_long as uint64_t,
                            1843345804916664 as libc::c_long as uint64_t,
                            1703118377384911 as libc::c_long as uint64_t,
                            497810164760654 as libc::c_long as uint64_t,
                            101150811654673 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            458346255946468 as libc::c_long as uint64_t,
                            290909935619344 as libc::c_long as uint64_t,
                            1452768413850679 as libc::c_long as uint64_t,
                            550922875254215 as libc::c_long as uint64_t,
                            1537286854336538 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            584322311184395 as libc::c_long as uint64_t,
                            380661238802118 as libc::c_long as uint64_t,
                            114839394528060 as libc::c_long as uint64_t,
                            655082270500073 as libc::c_long as uint64_t,
                            2111856026034852 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            996965581008991 as libc::c_long as uint64_t,
                            2148998626477022 as libc::c_long as uint64_t,
                            1012273164934654 as libc::c_long as uint64_t,
                            1073876063914522 as libc::c_long as uint64_t,
                            1688031788934939 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            923487018849600 as libc::c_long as uint64_t,
                            2085106799623355 as libc::c_long as uint64_t,
                            528082801620136 as libc::c_long as uint64_t,
                            1606206360876188 as libc::c_long as uint64_t,
                            735907091712524 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1697697887804317 as libc::c_long as uint64_t,
                            1335343703828273 as libc::c_long as uint64_t,
                            831288615207040 as libc::c_long as uint64_t,
                            949416685250051 as libc::c_long as uint64_t,
                            288760277392022 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1419122478109648 as libc::c_long as uint64_t,
                            1325574567803701 as libc::c_long as uint64_t,
                            602393874111094 as libc::c_long as uint64_t,
                            2107893372601700 as libc::c_long as uint64_t,
                            1314159682671307 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2201150872731804 as libc::c_long as uint64_t,
                            2180241023425241 as libc::c_long as uint64_t,
                            97663456423163 as libc::c_long as uint64_t,
                            1633405770247824 as libc::c_long as uint64_t,
                            848945042443986 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1173339555550611 as libc::c_long as uint64_t,
                            818605084277583 as libc::c_long as uint64_t,
                            47521504364289 as libc::c_long as uint64_t,
                            924108720564965 as libc::c_long as uint64_t,
                            735423405754506 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            830104860549448 as libc::c_long as uint64_t,
                            1886653193241086 as libc::c_long as uint64_t,
                            1600929509383773 as libc::c_long as uint64_t,
                            1475051275443631 as libc::c_long as uint64_t,
                            286679780900937 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1577111294832995 as libc::c_long as uint64_t,
                            1030899169768747 as libc::c_long as uint64_t,
                            144900916293530 as libc::c_long as uint64_t,
                            1964672592979567 as libc::c_long as uint64_t,
                            568390100955250 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            278388655910247 as libc::c_long as uint64_t,
                            487143369099838 as libc::c_long as uint64_t,
                            927762205508727 as libc::c_long as uint64_t,
                            181017540174210 as libc::c_long as uint64_t,
                            1616886700741287 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1191033906638969 as libc::c_long as uint64_t,
                            940823957346562 as libc::c_long as uint64_t,
                            1606870843663445 as libc::c_long as uint64_t,
                            861684761499847 as libc::c_long as uint64_t,
                            658674867251089 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1875032594195546 as libc::c_long as uint64_t,
                            1427106132796197 as libc::c_long as uint64_t,
                            724736390962158 as libc::c_long as uint64_t,
                            901860512044740 as libc::c_long as uint64_t,
                            635268497268760 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            622869792298357 as libc::c_long as uint64_t,
                            1903919278950367 as libc::c_long as uint64_t,
                            1922588621661629 as libc::c_long as uint64_t,
                            1520574711600434 as libc::c_long as uint64_t,
                            1087100760174640 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            25465949416618 as libc::c_long as uint64_t,
                            1693639527318811 as libc::c_long as uint64_t,
                            1526153382657203 as libc::c_long as uint64_t,
                            125943137857169 as libc::c_long as uint64_t,
                            145276964043999 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            214739857969358 as libc::c_long as uint64_t,
                            920212862967915 as libc::c_long as uint64_t,
                            1939901550972269 as libc::c_long as uint64_t,
                            1211862791775221 as libc::c_long as uint64_t,
                            85097515720120 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2006245852772938 as libc::c_long as uint64_t,
                            734762734836159 as libc::c_long as uint64_t,
                            254642929763427 as libc::c_long as uint64_t,
                            1406213292755966 as libc::c_long as uint64_t,
                            239303749517686 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1619678837192149 as libc::c_long as uint64_t,
                            1919424032779215 as libc::c_long as uint64_t,
                            1357391272956794 as libc::c_long as uint64_t,
                            1525634040073113 as libc::c_long as uint64_t,
                            1310226789796241 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1040763709762123 as libc::c_long as uint64_t,
                            1704449869235352 as libc::c_long as uint64_t,
                            605263070456329 as libc::c_long as uint64_t,
                            1998838089036355 as libc::c_long as uint64_t,
                            1312142911487502 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1996723311435669 as libc::c_long as uint64_t,
                            1844342766567060 as libc::c_long as uint64_t,
                            985455700466044 as libc::c_long as uint64_t,
                            1165924681400960 as libc::c_long as uint64_t,
                            311508689870129 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            43173156290518 as libc::c_long as uint64_t,
                            2202883069785309 as libc::c_long as uint64_t,
                            1137787467085917 as libc::c_long as uint64_t,
                            1733636061944606 as libc::c_long as uint64_t,
                            1394992037553852 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            670078326344559 as libc::c_long as uint64_t,
                            555655025059356 as libc::c_long as uint64_t,
                            471959386282438 as libc::c_long as uint64_t,
                            2141455487356409 as libc::c_long as uint64_t,
                            849015953823125 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2197214573372804 as libc::c_long as uint64_t,
                            794254097241315 as libc::c_long as uint64_t,
                            1030190060513737 as libc::c_long as uint64_t,
                            267632515541902 as libc::c_long as uint64_t,
                            2040478049202624 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1812516004670529 as libc::c_long as uint64_t,
                            1609256702920783 as libc::c_long as uint64_t,
                            1706897079364493 as libc::c_long as uint64_t,
                            258549904773295 as libc::c_long as uint64_t,
                            996051247540686 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1540374301420584 as libc::c_long as uint64_t,
                            1764656898914615 as libc::c_long as uint64_t,
                            1810104162020396 as libc::c_long as uint64_t,
                            923808779163088 as libc::c_long as uint64_t,
                            664390074196579 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1323460699404750 as libc::c_long as uint64_t,
                            1262690757880991 as libc::c_long as uint64_t,
                            871777133477900 as libc::c_long as uint64_t,
                            1060078894988977 as libc::c_long as uint64_t,
                            1712236889662886 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1696163952057966 as libc::c_long as uint64_t,
                            1391710137550823 as libc::c_long as uint64_t,
                            608793846867416 as libc::c_long as uint64_t,
                            1034391509472039 as libc::c_long as uint64_t,
                            1780770894075012 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1367603834210841 as libc::c_long as uint64_t,
                            2131988646583224 as libc::c_long as uint64_t,
                            890353773628144 as libc::c_long as uint64_t,
                            1908908219165595 as libc::c_long as uint64_t,
                            270836895252891 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            597536315471731 as libc::c_long as uint64_t,
                            40375058742586 as libc::c_long as uint64_t,
                            1942256403956049 as libc::c_long as uint64_t,
                            1185484645495932 as libc::c_long as uint64_t,
                            312666282024145 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1919411405316294 as libc::c_long as uint64_t,
                            1234508526402192 as libc::c_long as uint64_t,
                            1066863051997083 as libc::c_long as uint64_t,
                            1008444703737597 as libc::c_long as uint64_t,
                            1348810787701552 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2102881477513865 as libc::c_long as uint64_t,
                            1570274565945361 as libc::c_long as uint64_t,
                            1573617900503708 as libc::c_long as uint64_t,
                            18662635732583 as libc::c_long as uint64_t,
                            2232324307922098 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1853931367696942 as libc::c_long as uint64_t,
                            8107973870707 as libc::c_long as uint64_t,
                            350214504129299 as libc::c_long as uint64_t,
                            775206934582587 as libc::c_long as uint64_t,
                            1752317649166792 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1417148368003523 as libc::c_long as uint64_t,
                            721357181628282 as libc::c_long as uint64_t,
                            505725498207811 as libc::c_long as uint64_t,
                            373232277872983 as libc::c_long as uint64_t,
                            261634707184480 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2186733281493267 as libc::c_long as uint64_t,
                            2250694917008620 as libc::c_long as uint64_t,
                            1014829812957440 as libc::c_long as uint64_t,
                            479998161452389 as libc::c_long as uint64_t,
                            83566193876474 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1268116367301224 as libc::c_long as uint64_t,
                            560157088142809 as libc::c_long as uint64_t,
                            802626839600444 as libc::c_long as uint64_t,
                            2210189936605713 as libc::c_long as uint64_t,
                            1129993785579988 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            615183387352312 as libc::c_long as uint64_t,
                            917611676109240 as libc::c_long as uint64_t,
                            878893615973325 as libc::c_long as uint64_t,
                            978940963313282 as libc::c_long as uint64_t,
                            938686890583575 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            522024729211672 as libc::c_long as uint64_t,
                            1045059315315808 as libc::c_long as uint64_t,
                            1892245413707790 as libc::c_long as uint64_t,
                            1907891107684253 as libc::c_long as uint64_t,
                            2059998109500714 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1799679152208884 as libc::c_long as uint64_t,
                            912132775900387 as libc::c_long as uint64_t,
                            25967768040979 as libc::c_long as uint64_t,
                            432130448590461 as libc::c_long as uint64_t,
                            274568990261996 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            98698809797682 as libc::c_long as uint64_t,
                            2144627600856209 as libc::c_long as uint64_t,
                            1907959298569602 as libc::c_long as uint64_t,
                            811491302610148 as libc::c_long as uint64_t,
                            1262481774981493 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1791451399743152 as libc::c_long as uint64_t,
                            1713538728337276 as libc::c_long as uint64_t,
                            118349997257490 as libc::c_long as uint64_t,
                            1882306388849954 as libc::c_long as uint64_t,
                            158235232210248 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1217809823321928 as libc::c_long as uint64_t,
                            2173947284933160 as libc::c_long as uint64_t,
                            1986927836272325 as libc::c_long as uint64_t,
                            1388114931125539 as libc::c_long as uint64_t,
                            12686131160169 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1650875518872272 as libc::c_long as uint64_t,
                            1136263858253897 as libc::c_long as uint64_t,
                            1732115601395988 as libc::c_long as uint64_t,
                            734312880662190 as libc::c_long as uint64_t,
                            1252904681142109 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            372986456113865 as libc::c_long as uint64_t,
                            525430915458171 as libc::c_long as uint64_t,
                            2116279931702135 as libc::c_long as uint64_t,
                            501422713587815 as libc::c_long as uint64_t,
                            1907002872974925 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            803147181835288 as libc::c_long as uint64_t,
                            868941437997146 as libc::c_long as uint64_t,
                            316299302989663 as libc::c_long as uint64_t,
                            943495589630550 as libc::c_long as uint64_t,
                            571224287904572 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            227742695588364 as libc::c_long as uint64_t,
                            1776969298667369 as libc::c_long as uint64_t,
                            628602552821802 as libc::c_long as uint64_t,
                            457210915378118 as libc::c_long as uint64_t,
                            2041906378111140 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            815000523470260 as libc::c_long as uint64_t,
                            913085688728307 as libc::c_long as uint64_t,
                            1052060118271173 as libc::c_long as uint64_t,
                            1345536665214223 as libc::c_long as uint64_t,
                            541623413135555 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1580216071604333 as libc::c_long as uint64_t,
                            1877997504342444 as libc::c_long as uint64_t,
                            857147161260913 as libc::c_long as uint64_t,
                            703522726778478 as libc::c_long as uint64_t,
                            2182763974211603 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1870080310923419 as libc::c_long as uint64_t,
                            71988220958492 as libc::c_long as uint64_t,
                            1783225432016732 as libc::c_long as uint64_t,
                            615915287105016 as libc::c_long as uint64_t,
                            1035570475990230 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            730987750830150 as libc::c_long as uint64_t,
                            857613889540280 as libc::c_long as uint64_t,
                            1083813157271766 as libc::c_long as uint64_t,
                            1002817255970169 as libc::c_long as uint64_t,
                            1719228484436074 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            377616581647602 as libc::c_long as uint64_t,
                            1581980403078513 as libc::c_long as uint64_t,
                            804044118130621 as libc::c_long as uint64_t,
                            2034382823044191 as libc::c_long as uint64_t,
                            643844048472185 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            176957326463017 as libc::c_long as uint64_t,
                            1573744060478586 as libc::c_long as uint64_t,
                            528642225008045 as libc::c_long as uint64_t,
                            1816109618372371 as libc::c_long as uint64_t,
                            1515140189765006 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1888911448245718 as libc::c_long as uint64_t,
                            1387110895611080 as libc::c_long as uint64_t,
                            1924503794066429 as libc::c_long as uint64_t,
                            1731539523700949 as libc::c_long as uint64_t,
                            2230378382645454 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            443392177002051 as libc::c_long as uint64_t,
                            233793396845137 as libc::c_long as uint64_t,
                            2199506622312416 as libc::c_long as uint64_t,
                            1011858706515937 as libc::c_long as uint64_t,
                            974676837063129 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1846351103143623 as libc::c_long as uint64_t,
                            1949984838808427 as libc::c_long as uint64_t,
                            671247021915253 as libc::c_long as uint64_t,
                            1946756846184401 as libc::c_long as uint64_t,
                            1929296930380217 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            849646212452002 as libc::c_long as uint64_t,
                            1410198775302919 as libc::c_long as uint64_t,
                            73767886183695 as libc::c_long as uint64_t,
                            1641663456615812 as libc::c_long as uint64_t,
                            762256272452411 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            692017667358279 as libc::c_long as uint64_t,
                            723305578826727 as libc::c_long as uint64_t,
                            1638042139863265 as libc::c_long as uint64_t,
                            748219305990306 as libc::c_long as uint64_t,
                            334589200523901 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            22893968530686 as libc::c_long as uint64_t,
                            2235758574399251 as libc::c_long as uint64_t,
                            1661465835630252 as libc::c_long as uint64_t,
                            925707319443452 as libc::c_long as uint64_t,
                            1203475116966621 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            801299035785166 as libc::c_long as uint64_t,
                            1733292596726131 as libc::c_long as uint64_t,
                            1664508947088596 as libc::c_long as uint64_t,
                            467749120991922 as libc::c_long as uint64_t,
                            1647498584535623 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            903105258014366 as libc::c_long as uint64_t,
                            427141894933047 as libc::c_long as uint64_t,
                            561187017169777 as libc::c_long as uint64_t,
                            1884330244401954 as libc::c_long as uint64_t,
                            1914145708422219 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1344191060517578 as libc::c_long as uint64_t,
                            1960935031767890 as libc::c_long as uint64_t,
                            1518838929955259 as libc::c_long as uint64_t,
                            1781502350597190 as libc::c_long as uint64_t,
                            1564784025565682 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            673723351748086 as libc::c_long as uint64_t,
                            1979969272514923 as libc::c_long as uint64_t,
                            1175287312495508 as libc::c_long as uint64_t,
                            1187589090978666 as libc::c_long as uint64_t,
                            1881897672213940 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1917185587363432 as libc::c_long as uint64_t,
                            1098342571752737 as libc::c_long as uint64_t,
                            5935801044414 as libc::c_long as uint64_t,
                            2000527662351839 as libc::c_long as uint64_t,
                            1538640296181569 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2495540013192 as libc::c_long as uint64_t,
                            678856913479236 as libc::c_long as uint64_t,
                            224998292422872 as libc::c_long as uint64_t,
                            219635787698590 as libc::c_long as uint64_t,
                            1972465269000940 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            271413961212179 as libc::c_long as uint64_t,
                            1353052061471651 as libc::c_long as uint64_t,
                            344711291283483 as libc::c_long as uint64_t,
                            2014925838520662 as libc::c_long as uint64_t,
                            2006221033113941 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            194583029968109 as libc::c_long as uint64_t,
                            514316781467765 as libc::c_long as uint64_t,
                            829677956235672 as libc::c_long as uint64_t,
                            1676415686873082 as libc::c_long as uint64_t,
                            810104584395840 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1980510813313589 as libc::c_long as uint64_t,
                            1948645276483975 as libc::c_long as uint64_t,
                            152063780665900 as libc::c_long as uint64_t,
                            129968026417582 as libc::c_long as uint64_t,
                            256984195613935 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1860190562533102 as libc::c_long as uint64_t,
                            1936576191345085 as libc::c_long as uint64_t,
                            461100292705964 as libc::c_long as uint64_t,
                            1811043097042830 as libc::c_long as uint64_t,
                            957486749306835 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            796664815624365 as libc::c_long as uint64_t,
                            1543160838872951 as libc::c_long as uint64_t,
                            1500897791837765 as libc::c_long as uint64_t,
                            1667315977988401 as libc::c_long as uint64_t,
                            599303877030711 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1151480509533204 as libc::c_long as uint64_t,
                            2136010406720455 as libc::c_long as uint64_t,
                            738796060240027 as libc::c_long as uint64_t,
                            319298003765044 as libc::c_long as uint64_t,
                            1150614464349587 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1731069268103150 as libc::c_long as uint64_t,
                            735642447616087 as libc::c_long as uint64_t,
                            1364750481334268 as libc::c_long as uint64_t,
                            417232839982871 as libc::c_long as uint64_t,
                            927108269127661 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1017222050227968 as libc::c_long as uint64_t,
                            1987716148359 as libc::c_long as uint64_t,
                            2234319589635701 as libc::c_long as uint64_t,
                            621282683093392 as libc::c_long as uint64_t,
                            2132553131763026 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1567828528453324 as libc::c_long as uint64_t,
                            1017807205202360 as libc::c_long as uint64_t,
                            565295260895298 as libc::c_long as uint64_t,
                            829541698429100 as libc::c_long as uint64_t,
                            307243822276582 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            249079270936248 as libc::c_long as uint64_t,
                            1501514259790706 as libc::c_long as uint64_t,
                            947909724204848 as libc::c_long as uint64_t,
                            944551802437487 as libc::c_long as uint64_t,
                            552658763982480 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2089966982947227 as libc::c_long as uint64_t,
                            1854140343916181 as libc::c_long as uint64_t,
                            2151980759220007 as libc::c_long as uint64_t,
                            2139781292261749 as libc::c_long as uint64_t,
                            158070445864917 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1338766321464554 as libc::c_long as uint64_t,
                            1906702607371284 as libc::c_long as uint64_t,
                            1519569445519894 as libc::c_long as uint64_t,
                            115384726262267 as libc::c_long as uint64_t,
                            1393058953390992 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1364621558265400 as libc::c_long as uint64_t,
                            1512388234908357 as libc::c_long as uint64_t,
                            1926731583198686 as libc::c_long as uint64_t,
                            2041482526432505 as libc::c_long as uint64_t,
                            920401122333774 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1884844597333588 as libc::c_long as uint64_t,
                            601480070269079 as libc::c_long as uint64_t,
                            620203503079537 as libc::c_long as uint64_t,
                            1079527400117915 as libc::c_long as uint64_t,
                            1202076693132015 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            840922919763324 as libc::c_long as uint64_t,
                            727955812569642 as libc::c_long as uint64_t,
                            1303406629750194 as libc::c_long as uint64_t,
                            522898432152867 as libc::c_long as uint64_t,
                            294161410441865 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            353760790835310 as libc::c_long as uint64_t,
                            1598361541848743 as libc::c_long as uint64_t,
                            1122905698202299 as libc::c_long as uint64_t,
                            1922533590158905 as libc::c_long as uint64_t,
                            419107700666580 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            359856369838236 as libc::c_long as uint64_t,
                            180914355488683 as libc::c_long as uint64_t,
                            861726472646627 as libc::c_long as uint64_t,
                            218807937262986 as libc::c_long as uint64_t,
                            575626773232501 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            755467689082474 as libc::c_long as uint64_t,
                            909202735047934 as libc::c_long as uint64_t,
                            730078068932500 as libc::c_long as uint64_t,
                            936309075711518 as libc::c_long as uint64_t,
                            2007798262842972 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1609384177904073 as libc::c_long as uint64_t,
                            362745185608627 as libc::c_long as uint64_t,
                            1335318541768201 as libc::c_long as uint64_t,
                            800965770436248 as libc::c_long as uint64_t,
                            547877979267412 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            984339177776787 as libc::c_long as uint64_t,
                            815727786505884 as libc::c_long as uint64_t,
                            1645154585713747 as libc::c_long as uint64_t,
                            1659074964378553 as libc::c_long as uint64_t,
                            1686601651984156 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1697863093781930 as libc::c_long as uint64_t,
                            599794399429786 as libc::c_long as uint64_t,
                            1104556219769607 as libc::c_long as uint64_t,
                            830560774794755 as libc::c_long as uint64_t,
                            12812858601017 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1168737550514982 as libc::c_long as uint64_t,
                            897832437380552 as libc::c_long as uint64_t,
                            463140296333799 as libc::c_long as uint64_t,
                            302564600022547 as libc::c_long as uint64_t,
                            2008360505135501 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1856930662813910 as libc::c_long as uint64_t,
                            678090852002597 as libc::c_long as uint64_t,
                            1920179140755167 as libc::c_long as uint64_t,
                            1259527833759868 as libc::c_long as uint64_t,
                            55540971895511 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1158643631044921 as libc::c_long as uint64_t,
                            476554103621892 as libc::c_long as uint64_t,
                            178447851439725 as libc::c_long as uint64_t,
                            1305025542653569 as libc::c_long as uint64_t,
                            103433927680625 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2176793111709008 as libc::c_long as uint64_t,
                            1576725716350391 as libc::c_long as uint64_t,
                            2009350167273523 as libc::c_long as uint64_t,
                            2012390194631546 as libc::c_long as uint64_t,
                            2125297410909580 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            825403285195098 as libc::c_long as uint64_t,
                            2144208587560784 as libc::c_long as uint64_t,
                            1925552004644643 as libc::c_long as uint64_t,
                            1915177840006985 as libc::c_long as uint64_t,
                            1015952128947864 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1807108316634472 as libc::c_long as uint64_t,
                            1534392066433717 as libc::c_long as uint64_t,
                            347342975407218 as libc::c_long as uint64_t,
                            1153820745616376 as libc::c_long as uint64_t,
                            7375003497471 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            983061001799725 as libc::c_long as uint64_t,
                            431211889901241 as libc::c_long as uint64_t,
                            2201903782961093 as libc::c_long as uint64_t,
                            817393911064341 as libc::c_long as uint64_t,
                            2214616493042167 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            228567918409756 as libc::c_long as uint64_t,
                            865093958780220 as libc::c_long as uint64_t,
                            358083886450556 as libc::c_long as uint64_t,
                            159617889659320 as libc::c_long as uint64_t,
                            1360637926292598 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            234147501399755 as libc::c_long as uint64_t,
                            2229469128637390 as libc::c_long as uint64_t,
                            2175289352258889 as libc::c_long as uint64_t,
                            1397401514549353 as libc::c_long as uint64_t,
                            1885288963089922 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1111762412951562 as libc::c_long as uint64_t,
                            252849572507389 as libc::c_long as uint64_t,
                            1048714233823341 as libc::c_long as uint64_t,
                            146111095601446 as libc::c_long as uint64_t,
                            1237505378776770 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1113790697840279 as libc::c_long as uint64_t,
                            1051167139966244 as libc::c_long as uint64_t,
                            1045930658550944 as libc::c_long as uint64_t,
                            2011366241542643 as libc::c_long as uint64_t,
                            1686166824620755 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1054097349305049 as libc::c_long as uint64_t,
                            1872495070333352 as libc::c_long as uint64_t,
                            182121071220717 as libc::c_long as uint64_t,
                            1064378906787311 as libc::c_long as uint64_t,
                            100273572924182 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1306410853171605 as libc::c_long as uint64_t,
                            1627717417672447 as libc::c_long as uint64_t,
                            50983221088417 as libc::c_long as uint64_t,
                            1109249951172250 as libc::c_long as uint64_t,
                            870201789081392 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            104233794644221 as libc::c_long as uint64_t,
                            1548919791188248 as libc::c_long as uint64_t,
                            2224541913267306 as libc::c_long as uint64_t,
                            2054909377116478 as libc::c_long as uint64_t,
                            1043803389015153 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            216762189468802 as libc::c_long as uint64_t,
                            707284285441622 as libc::c_long as uint64_t,
                            190678557969733 as libc::c_long as uint64_t,
                            973969342604308 as libc::c_long as uint64_t,
                            1403009538434867 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1279024291038477 as libc::c_long as uint64_t,
                            344776835218310 as libc::c_long as uint64_t,
                            273722096017199 as libc::c_long as uint64_t,
                            1834200436811442 as libc::c_long as uint64_t,
                            634517197663804 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            343805853118335 as libc::c_long as uint64_t,
                            1302216857414201 as libc::c_long as uint64_t,
                            566872543223541 as libc::c_long as uint64_t,
                            2051138939539004 as libc::c_long as uint64_t,
                            321428858384280 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            470067171324852 as libc::c_long as uint64_t,
                            1618629234173951 as libc::c_long as uint64_t,
                            2000092177515639 as libc::c_long as uint64_t,
                            7307679772789 as libc::c_long as uint64_t,
                            1117521120249968 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            278151578291475 as libc::c_long as uint64_t,
                            1810282338562947 as libc::c_long as uint64_t,
                            1771599529530998 as libc::c_long as uint64_t,
                            1383659409671631 as libc::c_long as uint64_t,
                            685373414471841 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            577009397403102 as libc::c_long as uint64_t,
                            1791440261786291 as libc::c_long as uint64_t,
                            2177643735971638 as libc::c_long as uint64_t,
                            174546149911960 as libc::c_long as uint64_t,
                            1412505077782326 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            893719721537457 as libc::c_long as uint64_t,
                            1201282458018197 as libc::c_long as uint64_t,
                            1522349501711173 as libc::c_long as uint64_t,
                            58011597740583 as libc::c_long as uint64_t,
                            1130406465887139 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            412607348255453 as libc::c_long as uint64_t,
                            1280455764199780 as libc::c_long as uint64_t,
                            2233277987330768 as libc::c_long as uint64_t,
                            14180080401665 as libc::c_long as uint64_t,
                            331584698417165 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            262483770854550 as libc::c_long as uint64_t,
                            990511055108216 as libc::c_long as uint64_t,
                            526885552771698 as libc::c_long as uint64_t,
                            571664396646158 as libc::c_long as uint64_t,
                            354086190278723 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1820352417585487 as libc::c_long as uint64_t,
                            24495617171480 as libc::c_long as uint64_t,
                            1547899057533253 as libc::c_long as uint64_t,
                            10041836186225 as libc::c_long as uint64_t,
                            480457105094042 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2023310314989233 as libc::c_long as uint64_t,
                            637905337525881 as libc::c_long as uint64_t,
                            2106474638900687 as libc::c_long as uint64_t,
                            557820711084072 as libc::c_long as uint64_t,
                            1687858215057826 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1144168702609745 as libc::c_long as uint64_t,
                            604444390410187 as libc::c_long as uint64_t,
                            1544541121756138 as libc::c_long as uint64_t,
                            1925315550126027 as libc::c_long as uint64_t,
                            626401428894002 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1922168257351784 as libc::c_long as uint64_t,
                            2018674099908659 as libc::c_long as uint64_t,
                            1776454117494445 as libc::c_long as uint64_t,
                            956539191509034 as libc::c_long as uint64_t,
                            36031129147635 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            544644538748041 as libc::c_long as uint64_t,
                            1039872944430374 as libc::c_long as uint64_t,
                            876750409130610 as libc::c_long as uint64_t,
                            710657711326551 as libc::c_long as uint64_t,
                            1216952687484972 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            58242421545916 as libc::c_long as uint64_t,
                            2035812695641843 as libc::c_long as uint64_t,
                            2118491866122923 as libc::c_long as uint64_t,
                            1191684463816273 as libc::c_long as uint64_t,
                            46921517454099 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            272268252444639 as libc::c_long as uint64_t,
                            1374166457774292 as libc::c_long as uint64_t,
                            2230115177009552 as libc::c_long as uint64_t,
                            1053149803909880 as libc::c_long as uint64_t,
                            1354288411641016 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1857910905368338 as libc::c_long as uint64_t,
                            1754729879288912 as libc::c_long as uint64_t,
                            885945464109877 as libc::c_long as uint64_t,
                            1516096106802166 as libc::c_long as uint64_t,
                            1602902393369811 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1193437069800958 as libc::c_long as uint64_t,
                            901107149704790 as libc::c_long as uint64_t,
                            999672920611411 as libc::c_long as uint64_t,
                            477584824802207 as libc::c_long as uint64_t,
                            364239578697845 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            886299989548838 as libc::c_long as uint64_t,
                            1538292895758047 as libc::c_long as uint64_t,
                            1590564179491896 as libc::c_long as uint64_t,
                            1944527126709657 as libc::c_long as uint64_t,
                            837344427345298 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            754558365378305 as libc::c_long as uint64_t,
                            1712186480903618 as libc::c_long as uint64_t,
                            1703656826337531 as libc::c_long as uint64_t,
                            750310918489786 as libc::c_long as uint64_t,
                            518996040250900 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1309847803895382 as libc::c_long as uint64_t,
                            1462151862813074 as libc::c_long as uint64_t,
                            211370866671570 as libc::c_long as uint64_t,
                            1544595152703681 as libc::c_long as uint64_t,
                            1027691798954090 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            803217563745370 as libc::c_long as uint64_t,
                            1884799722343599 as libc::c_long as uint64_t,
                            1357706345069218 as libc::c_long as uint64_t,
                            2244955901722095 as libc::c_long as uint64_t,
                            730869460037413 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            689299471295966 as libc::c_long as uint64_t,
                            1831210565161071 as libc::c_long as uint64_t,
                            1375187341585438 as libc::c_long as uint64_t,
                            1106284977546171 as libc::c_long as uint64_t,
                            1893781834054269 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            696351368613042 as libc::c_long as uint64_t,
                            1494385251239250 as libc::c_long as uint64_t,
                            738037133616932 as libc::c_long as uint64_t,
                            636385507851544 as libc::c_long as uint64_t,
                            927483222611406 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1949114198209333 as libc::c_long as uint64_t,
                            1104419699537997 as libc::c_long as uint64_t,
                            783495707664463 as libc::c_long as uint64_t,
                            1747473107602770 as libc::c_long as uint64_t,
                            2002634765788641 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1607325776830197 as libc::c_long as uint64_t,
                            530883941415333 as libc::c_long as uint64_t,
                            1451089452727895 as libc::c_long as uint64_t,
                            1581691157083423 as libc::c_long as uint64_t,
                            496100432831154 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1068900648804224 as libc::c_long as uint64_t,
                            2006891997072550 as libc::c_long as uint64_t,
                            1134049269345549 as libc::c_long as uint64_t,
                            1638760646180091 as libc::c_long as uint64_t,
                            2055396084625778 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2222475519314561 as libc::c_long as uint64_t,
                            1870703901472013 as libc::c_long as uint64_t,
                            1884051508440561 as libc::c_long as uint64_t,
                            1344072275216753 as libc::c_long as uint64_t,
                            1318025677799069 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            155711679280656 as libc::c_long as uint64_t,
                            681100400509288 as libc::c_long as uint64_t,
                            389811735211209 as libc::c_long as uint64_t,
                            2135723811340709 as libc::c_long as uint64_t,
                            408733211204125 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            7813206966729 as libc::c_long as uint64_t,
                            194444201427550 as libc::c_long as uint64_t,
                            2071405409526507 as libc::c_long as uint64_t,
                            1065605076176312 as libc::c_long as uint64_t,
                            1645486789731291 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            16625790644959 as libc::c_long as uint64_t,
                            1647648827778410 as libc::c_long as uint64_t,
                            1579910185572704 as libc::c_long as uint64_t,
                            436452271048548 as libc::c_long as uint64_t,
                            121070048451050 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1037263028552531 as libc::c_long as uint64_t,
                            568385780377829 as libc::c_long as uint64_t,
                            297953104144430 as libc::c_long as uint64_t,
                            1558584511931211 as libc::c_long as uint64_t,
                            2238221839292471 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            190565267697443 as libc::c_long as uint64_t,
                            672855706028058 as libc::c_long as uint64_t,
                            338796554369226 as libc::c_long as uint64_t,
                            337687268493904 as libc::c_long as uint64_t,
                            853246848691734 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1763863028400139 as libc::c_long as uint64_t,
                            766498079432444 as libc::c_long as uint64_t,
                            1321118624818005 as libc::c_long as uint64_t,
                            69494294452268 as libc::c_long as uint64_t,
                            858786744165651 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1292056768563024 as libc::c_long as uint64_t,
                            1456632109855638 as libc::c_long as uint64_t,
                            1100631247050184 as libc::c_long as uint64_t,
                            1386133165675321 as libc::c_long as uint64_t,
                            1232898350193752 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            366253102478259 as libc::c_long as uint64_t,
                            525676242508811 as libc::c_long as uint64_t,
                            1449610995265438 as libc::c_long as uint64_t,
                            1183300845322183 as libc::c_long as uint64_t,
                            185960306491545 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            28315355815982 as libc::c_long as uint64_t,
                            460422265558930 as libc::c_long as uint64_t,
                            1799675876678724 as libc::c_long as uint64_t,
                            1969256312504498 as libc::c_long as uint64_t,
                            1051823843138725 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            156914999361983 as libc::c_long as uint64_t,
                            1606148405719949 as libc::c_long as uint64_t,
                            1665208410108430 as libc::c_long as uint64_t,
                            317643278692271 as libc::c_long as uint64_t,
                            1383783705665320 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            54684536365732 as libc::c_long as uint64_t,
                            2210010038536222 as libc::c_long as uint64_t,
                            1194984798155308 as libc::c_long as uint64_t,
                            535239027773705 as libc::c_long as uint64_t,
                            1516355079301361 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1484387703771650 as libc::c_long as uint64_t,
                            198537510937949 as libc::c_long as uint64_t,
                            2186282186359116 as libc::c_long as uint64_t,
                            617687444857508 as libc::c_long as uint64_t,
                            647477376402122 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2147715541830533 as libc::c_long as uint64_t,
                            500032538445817 as libc::c_long as uint64_t,
                            646380016884826 as libc::c_long as uint64_t,
                            352227855331122 as libc::c_long as uint64_t,
                            1488268620408052 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            159386186465542 as libc::c_long as uint64_t,
                            1877626593362941 as libc::c_long as uint64_t,
                            618737197060512 as libc::c_long as uint64_t,
                            1026674284330807 as libc::c_long as uint64_t,
                            1158121760792685 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1744544377739822 as libc::c_long as uint64_t,
                            1964054180355661 as libc::c_long as uint64_t,
                            1685781755873170 as libc::c_long as uint64_t,
                            2169740670377448 as libc::c_long as uint64_t,
                            1286112621104591 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            81977249784993 as libc::c_long as uint64_t,
                            1667943117713086 as libc::c_long as uint64_t,
                            1668983819634866 as libc::c_long as uint64_t,
                            1605016835177615 as libc::c_long as uint64_t,
                            1353960708075544 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1602253788689063 as libc::c_long as uint64_t,
                            439542044889886 as libc::c_long as uint64_t,
                            2220348297664483 as libc::c_long as uint64_t,
                            657877410752869 as libc::c_long as uint64_t,
                            157451572512238 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1029287186166717 as libc::c_long as uint64_t,
                            65860128430192 as libc::c_long as uint64_t,
                            525298368814832 as libc::c_long as uint64_t,
                            1491902500801986 as libc::c_long as uint64_t,
                            1461064796385400 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            408216988729246 as libc::c_long as uint64_t,
                            2121095722306989 as libc::c_long as uint64_t,
                            913562102267595 as libc::c_long as uint64_t,
                            1879708920318308 as libc::c_long as uint64_t,
                            241061448436731 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1185483484383269 as libc::c_long as uint64_t,
                            1356339572588553 as libc::c_long as uint64_t,
                            584932367316448 as libc::c_long as uint64_t,
                            102132779946470 as libc::c_long as uint64_t,
                            1792922621116791 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1966196870701923 as libc::c_long as uint64_t,
                            2230044620318636 as libc::c_long as uint64_t,
                            1425982460745905 as libc::c_long as uint64_t,
                            261167817826569 as libc::c_long as uint64_t,
                            46517743394330 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            107077591595359 as libc::c_long as uint64_t,
                            884959942172345 as libc::c_long as uint64_t,
                            27306869797400 as libc::c_long as uint64_t,
                            2224911448949390 as libc::c_long as uint64_t,
                            964352058245223 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1730194207717538 as libc::c_long as uint64_t,
                            431790042319772 as libc::c_long as uint64_t,
                            1831515233279467 as libc::c_long as uint64_t,
                            1372080552768581 as libc::c_long as uint64_t,
                            1074513929381760 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1450880638731607 as libc::c_long as uint64_t,
                            1019861580989005 as libc::c_long as uint64_t,
                            1229729455116861 as libc::c_long as uint64_t,
                            1174945729836143 as libc::c_long as uint64_t,
                            826083146840706 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1899935429242705 as libc::c_long as uint64_t,
                            1602068751520477 as libc::c_long as uint64_t,
                            940583196550370 as libc::c_long as uint64_t,
                            82431069053859 as libc::c_long as uint64_t,
                            1540863155745696 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2136688454840028 as libc::c_long as uint64_t,
                            2099509000964294 as libc::c_long as uint64_t,
                            1690800495246475 as libc::c_long as uint64_t,
                            1217643678575476 as libc::c_long as uint64_t,
                            828720645084218 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            765548025667841 as libc::c_long as uint64_t,
                            462473984016099 as libc::c_long as uint64_t,
                            998061409979798 as libc::c_long as uint64_t,
                            546353034089527 as libc::c_long as uint64_t,
                            2212508972466858 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            46575283771160 as libc::c_long as uint64_t,
                            892570971573071 as libc::c_long as uint64_t,
                            1281983193144090 as libc::c_long as uint64_t,
                            1491520128287375 as libc::c_long as uint64_t,
                            75847005908304 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1801436127943107 as libc::c_long as uint64_t,
                            1734436817907890 as libc::c_long as uint64_t,
                            1268728090345068 as libc::c_long as uint64_t,
                            167003097070711 as libc::c_long as uint64_t,
                            2233597765834956 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1997562060465113 as libc::c_long as uint64_t,
                            1048700225534011 as libc::c_long as uint64_t,
                            7615603985628 as libc::c_long as uint64_t,
                            1855310849546841 as libc::c_long as uint64_t,
                            2242557647635213 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1161017320376250 as libc::c_long as uint64_t,
                            492624580169043 as libc::c_long as uint64_t,
                            2169815802355237 as libc::c_long as uint64_t,
                            976496781732542 as libc::c_long as uint64_t,
                            1770879511019629 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1357044908364776 as libc::c_long as uint64_t,
                            729130645262438 as libc::c_long as uint64_t,
                            1762469072918979 as libc::c_long as uint64_t,
                            1365633616878458 as libc::c_long as uint64_t,
                            181282906404941 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1080413443139865 as libc::c_long as uint64_t,
                            1155205815510486 as libc::c_long as uint64_t,
                            1848782073549786 as libc::c_long as uint64_t,
                            622566975152580 as libc::c_long as uint64_t,
                            124965574467971 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1184526762066993 as libc::c_long as uint64_t,
                            247622751762817 as libc::c_long as uint64_t,
                            692129017206356 as libc::c_long as uint64_t,
                            820018689412496 as libc::c_long as uint64_t,
                            2188697339828085 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2020536369003019 as libc::c_long as uint64_t,
                            202261491735136 as libc::c_long as uint64_t,
                            1053169669150884 as libc::c_long as uint64_t,
                            2056531979272544 as libc::c_long as uint64_t,
                            778165514694311 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            237404399610207 as libc::c_long as uint64_t,
                            1308324858405118 as libc::c_long as uint64_t,
                            1229680749538400 as libc::c_long as uint64_t,
                            720131409105291 as libc::c_long as uint64_t,
                            1958958863624906 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            515583508038846 as libc::c_long as uint64_t,
                            17656978857189 as libc::c_long as uint64_t,
                            1717918437373989 as libc::c_long as uint64_t,
                            1568052070792483 as libc::c_long as uint64_t,
                            46975803123923 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            281527309158085 as libc::c_long as uint64_t,
                            36970532401524 as libc::c_long as uint64_t,
                            866906920877543 as libc::c_long as uint64_t,
                            2222282602952734 as libc::c_long as uint64_t,
                            1289598729589882 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1278207464902042 as libc::c_long as uint64_t,
                            494742455008756 as libc::c_long as uint64_t,
                            1262082121427081 as libc::c_long as uint64_t,
                            1577236621659884 as libc::c_long as uint64_t,
                            1888786707293291 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            353042527954210 as libc::c_long as uint64_t,
                            1830056151907359 as libc::c_long as uint64_t,
                            1111731275799225 as libc::c_long as uint64_t,
                            174960955838824 as libc::c_long as uint64_t,
                            404312815582675 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2064251142068628 as libc::c_long as uint64_t,
                            1666421603389706 as libc::c_long as uint64_t,
                            1419271365315441 as libc::c_long as uint64_t,
                            468767774902855 as libc::c_long as uint64_t,
                            191535130366583 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1716987058588002 as libc::c_long as uint64_t,
                            1859366439773457 as libc::c_long as uint64_t,
                            1767194234188234 as libc::c_long as uint64_t,
                            64476199777924 as libc::c_long as uint64_t,
                            1117233614485261 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            984292135520292 as libc::c_long as uint64_t,
                            135138246951259 as libc::c_long as uint64_t,
                            2220652137473167 as libc::c_long as uint64_t,
                            1722843421165029 as libc::c_long as uint64_t,
                            190482558012909 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            298845952651262 as libc::c_long as uint64_t,
                            1166086588952562 as libc::c_long as uint64_t,
                            1179896526238434 as libc::c_long as uint64_t,
                            1347812759398693 as libc::c_long as uint64_t,
                            1412945390096208 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1143239552672925 as libc::c_long as uint64_t,
                            906436640714209 as libc::c_long as uint64_t,
                            2177000572812152 as libc::c_long as uint64_t,
                            2075299936108548 as libc::c_long as uint64_t,
                            325186347798433 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            721024854374772 as libc::c_long as uint64_t,
                            684487861263316 as libc::c_long as uint64_t,
                            1373438744094159 as libc::c_long as uint64_t,
                            2193186935276995 as libc::c_long as uint64_t,
                            1387043709851261 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            418098668140962 as libc::c_long as uint64_t,
                            715065997721283 as libc::c_long as uint64_t,
                            1471916138376055 as libc::c_long as uint64_t,
                            2168570337288357 as libc::c_long as uint64_t,
                            937812682637044 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1043584187226485 as libc::c_long as uint64_t,
                            2143395746619356 as libc::c_long as uint64_t,
                            2209558562919611 as libc::c_long as uint64_t,
                            482427979307092 as libc::c_long as uint64_t,
                            847556718384018 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1248731221520759 as libc::c_long as uint64_t,
                            1465200936117687 as libc::c_long as uint64_t,
                            540803492710140 as libc::c_long as uint64_t,
                            52978634680892 as libc::c_long as uint64_t,
                            261434490176109 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1057329623869501 as libc::c_long as uint64_t,
                            620334067429122 as libc::c_long as uint64_t,
                            461700859268034 as libc::c_long as uint64_t,
                            2012481616501857 as libc::c_long as uint64_t,
                            297268569108938 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1055352180870759 as libc::c_long as uint64_t,
                            1553151421852298 as libc::c_long as uint64_t,
                            1510903185371259 as libc::c_long as uint64_t,
                            1470458349428097 as libc::c_long as uint64_t,
                            1226259419062731 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1492988790301668 as libc::c_long as uint64_t,
                            790326625573331 as libc::c_long as uint64_t,
                            1190107028409745 as libc::c_long as uint64_t,
                            1389394752159193 as libc::c_long as uint64_t,
                            1620408196604194 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            47000654413729 as libc::c_long as uint64_t,
                            1004754424173864 as libc::c_long as uint64_t,
                            1868044813557703 as libc::c_long as uint64_t,
                            173236934059409 as libc::c_long as uint64_t,
                            588771199737015 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            30498470091663 as libc::c_long as uint64_t,
                            1082245510489825 as libc::c_long as uint64_t,
                            576771653181956 as libc::c_long as uint64_t,
                            806509986132686 as libc::c_long as uint64_t,
                            1317634017056939 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            420308055751555 as libc::c_long as uint64_t,
                            1493354863316002 as libc::c_long as uint64_t,
                            165206721528088 as libc::c_long as uint64_t,
                            1884845694919786 as libc::c_long as uint64_t,
                            2065456951573059 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1115636332012334 as libc::c_long as uint64_t,
                            1854340990964155 as libc::c_long as uint64_t,
                            83792697369514 as libc::c_long as uint64_t,
                            1972177451994021 as libc::c_long as uint64_t,
                            457455116057587 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1698968457310898 as libc::c_long as uint64_t,
                            1435137169051090 as libc::c_long as uint64_t,
                            1083661677032510 as libc::c_long as uint64_t,
                            938363267483709 as libc::c_long as uint64_t,
                            340103887207182 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1995325341336574 as libc::c_long as uint64_t,
                            911500251774648 as libc::c_long as uint64_t,
                            164010755403692 as libc::c_long as uint64_t,
                            855378419194762 as libc::c_long as uint64_t,
                            1573601397528842 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            241719380661528 as libc::c_long as uint64_t,
                            310028521317150 as libc::c_long as uint64_t,
                            1215881323380194 as libc::c_long as uint64_t,
                            1408214976493624 as libc::c_long as uint64_t,
                            2141142156467363 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1315157046163473 as libc::c_long as uint64_t,
                            727368447885818 as libc::c_long as uint64_t,
                            1363466668108618 as libc::c_long as uint64_t,
                            1668921439990361 as libc::c_long as uint64_t,
                            1398483384337907 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            75029678299646 as libc::c_long as uint64_t,
                            1015388206460473 as libc::c_long as uint64_t,
                            1849729037055212 as libc::c_long as uint64_t,
                            1939814616452984 as libc::c_long as uint64_t,
                            444404230394954 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2053597130993710 as libc::c_long as uint64_t,
                            2024431685856332 as libc::c_long as uint64_t,
                            2233550957004860 as libc::c_long as uint64_t,
                            2012407275509545 as libc::c_long as uint64_t,
                            872546993104440 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1217269667678610 as libc::c_long as uint64_t,
                            599909351968693 as libc::c_long as uint64_t,
                            1390077048548598 as libc::c_long as uint64_t,
                            1471879360694802 as libc::c_long as uint64_t,
                            739586172317596 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1718318639380794 as libc::c_long as uint64_t,
                            1560510726633958 as libc::c_long as uint64_t,
                            904462881159922 as libc::c_long as uint64_t,
                            1418028351780052 as libc::c_long as uint64_t,
                            94404349451937 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2132502667405250 as libc::c_long as uint64_t,
                            214379346175414 as libc::c_long as uint64_t,
                            1502748313768060 as libc::c_long as uint64_t,
                            1960071701057800 as libc::c_long as uint64_t,
                            1353971822643138 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            319394212043702 as libc::c_long as uint64_t,
                            2127459436033571 as libc::c_long as uint64_t,
                            717646691535162 as libc::c_long as uint64_t,
                            663366796076914 as libc::c_long as uint64_t,
                            318459064945314 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            405989424923593 as libc::c_long as uint64_t,
                            1960452633787083 as libc::c_long as uint64_t,
                            667349034401665 as libc::c_long as uint64_t,
                            1492674260767112 as libc::c_long as uint64_t,
                            1451061489880787 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            947085906234007 as libc::c_long as uint64_t,
                            323284730494107 as libc::c_long as uint64_t,
                            1485778563977200 as libc::c_long as uint64_t,
                            728576821512394 as libc::c_long as uint64_t,
                            901584347702286 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1575783124125742 as libc::c_long as uint64_t,
                            2126210792434375 as libc::c_long as uint64_t,
                            1569430791264065 as libc::c_long as uint64_t,
                            1402582372904727 as libc::c_long as uint64_t,
                            1891780248341114 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            838432205560695 as libc::c_long as uint64_t,
                            1997703511451664 as libc::c_long as uint64_t,
                            1018791879907867 as libc::c_long as uint64_t,
                            1662001808174331 as libc::c_long as uint64_t,
                            78328132957753 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            739152638255629 as libc::c_long as uint64_t,
                            2074935399403557 as libc::c_long as uint64_t,
                            505483666745895 as libc::c_long as uint64_t,
                            1611883356514088 as libc::c_long as uint64_t,
                            628654635394878 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1822054032121349 as libc::c_long as uint64_t,
                            643057948186973 as libc::c_long as uint64_t,
                            7306757352712 as libc::c_long as uint64_t,
                            577249257962099 as libc::c_long as uint64_t,
                            284735863382083 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1366558556363930 as libc::c_long as uint64_t,
                            1448606567552086 as libc::c_long as uint64_t,
                            1478881020944768 as libc::c_long as uint64_t,
                            165803179355898 as libc::c_long as uint64_t,
                            1115718458123498 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            204146226972102 as libc::c_long as uint64_t,
                            1630511199034723 as libc::c_long as uint64_t,
                            2215235214174763 as libc::c_long as uint64_t,
                            174665910283542 as libc::c_long as uint64_t,
                            956127674017216 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1562934578796716 as libc::c_long as uint64_t,
                            1070893489712745 as libc::c_long as uint64_t,
                            11324610642270 as libc::c_long as uint64_t,
                            958989751581897 as libc::c_long as uint64_t,
                            2172552325473805 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1770564423056027 as libc::c_long as uint64_t,
                            735523631664565 as libc::c_long as uint64_t,
                            1326060113795289 as libc::c_long as uint64_t,
                            1509650369341127 as libc::c_long as uint64_t,
                            65892421582684 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            623682558650637 as libc::c_long as uint64_t,
                            1337866509471512 as libc::c_long as uint64_t,
                            990313350206649 as libc::c_long as uint64_t,
                            1314236615762469 as libc::c_long as uint64_t,
                            1164772974270275 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            223256821462517 as libc::c_long as uint64_t,
                            723690150104139 as libc::c_long as uint64_t,
                            1000261663630601 as libc::c_long as uint64_t,
                            933280913953265 as libc::c_long as uint64_t,
                            254872671543046 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1969087237026041 as libc::c_long as uint64_t,
                            624795725447124 as libc::c_long as uint64_t,
                            1335555107635969 as libc::c_long as uint64_t,
                            2069986355593023 as libc::c_long as uint64_t,
                            1712100149341902 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1236103475266979 as libc::c_long as uint64_t,
                            1837885883267218 as libc::c_long as uint64_t,
                            1026072585230455 as libc::c_long as uint64_t,
                            1025865513954973 as libc::c_long as uint64_t,
                            1801964901432134 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1115241013365517 as libc::c_long as uint64_t,
                            1712251818829143 as libc::c_long as uint64_t,
                            2148864332502771 as libc::c_long as uint64_t,
                            2096001471438138 as libc::c_long as uint64_t,
                            2235017246626125 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1299268198601632 as libc::c_long as uint64_t,
                            2047148477845621 as libc::c_long as uint64_t,
                            2165648650132450 as libc::c_long as uint64_t,
                            1612539282026145 as libc::c_long as uint64_t,
                            514197911628890 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            118352772338543 as libc::c_long as uint64_t,
                            1067608711804704 as libc::c_long as uint64_t,
                            1434796676193498 as libc::c_long as uint64_t,
                            1683240170548391 as libc::c_long as uint64_t,
                            230866769907437 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1850689576796636 as libc::c_long as uint64_t,
                            1601590730430274 as libc::c_long as uint64_t,
                            1139674615958142 as libc::c_long as uint64_t,
                            1954384401440257 as libc::c_long as uint64_t,
                            76039205311 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1723387471374172 as libc::c_long as uint64_t,
                            997301467038410 as libc::c_long as uint64_t,
                            533927635123657 as libc::c_long as uint64_t,
                            20928644693965 as libc::c_long as uint64_t,
                            1756575222802513 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2146711623855116 as libc::c_long as uint64_t,
                            503278928021499 as libc::c_long as uint64_t,
                            625853062251406 as libc::c_long as uint64_t,
                            1109121378393107 as libc::c_long as uint64_t,
                            1033853809911861 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            571005965509422 as libc::c_long as uint64_t,
                            2005213373292546 as libc::c_long as uint64_t,
                            1016697270349626 as libc::c_long as uint64_t,
                            56607856974274 as libc::c_long as uint64_t,
                            914438579435146 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1346698876211176 as libc::c_long as uint64_t,
                            2076651707527589 as libc::c_long as uint64_t,
                            1084761571110205 as libc::c_long as uint64_t,
                            265334478828406 as libc::c_long as uint64_t,
                            1068954492309671 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1769967932677654 as libc::c_long as uint64_t,
                            1695893319756416 as libc::c_long as uint64_t,
                            1151863389675920 as libc::c_long as uint64_t,
                            1781042784397689 as libc::c_long as uint64_t,
                            400287774418285 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1851867764003121 as libc::c_long as uint64_t,
                            403841933237558 as libc::c_long as uint64_t,
                            820549523771987 as libc::c_long as uint64_t,
                            761292590207581 as libc::c_long as uint64_t,
                            1743735048551143 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            410915148140008 as libc::c_long as uint64_t,
                            2107072311871739 as libc::c_long as uint64_t,
                            1004367461876503 as libc::c_long as uint64_t,
                            99684895396761 as libc::c_long as uint64_t,
                            1180818713503224 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            285945406881439 as libc::c_long as uint64_t,
                            648174397347453 as libc::c_long as uint64_t,
                            1098403762631981 as libc::c_long as uint64_t,
                            1366547441102991 as libc::c_long as uint64_t,
                            1505876883139217 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            672095903120153 as libc::c_long as uint64_t,
                            1675918957959872 as libc::c_long as uint64_t,
                            636236529315028 as libc::c_long as uint64_t,
                            1569297300327696 as libc::c_long as uint64_t,
                            2164144194785875 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1902708175321798 as libc::c_long as uint64_t,
                            1035343530915438 as libc::c_long as uint64_t,
                            1178560808893263 as libc::c_long as uint64_t,
                            301095684058146 as libc::c_long as uint64_t,
                            1280977479761118 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1615357281742403 as libc::c_long as uint64_t,
                            404257611616381 as libc::c_long as uint64_t,
                            2160201349780978 as libc::c_long as uint64_t,
                            1160947379188955 as libc::c_long as uint64_t,
                            1578038619549541 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2013087639791217 as libc::c_long as uint64_t,
                            822734930507457 as libc::c_long as uint64_t,
                            1785668418619014 as libc::c_long as uint64_t,
                            1668650702946164 as libc::c_long as uint64_t,
                            389450875221715 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            453918449698368 as libc::c_long as uint64_t,
                            106406819929001 as libc::c_long as uint64_t,
                            2072540975937135 as libc::c_long as uint64_t,
                            308588860670238 as libc::c_long as uint64_t,
                            1304394580755385 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1295082798350326 as libc::c_long as uint64_t,
                            2091844511495996 as libc::c_long as uint64_t,
                            1851348972587817 as libc::c_long as uint64_t,
                            3375039684596 as libc::c_long as uint64_t,
                            789440738712837 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2083069137186154 as libc::c_long as uint64_t,
                            848523102004566 as libc::c_long as uint64_t,
                            993982213589257 as libc::c_long as uint64_t,
                            1405313299916317 as libc::c_long as uint64_t,
                            1532824818698468 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1495961298852430 as libc::c_long as uint64_t,
                            1397203457344779 as libc::c_long as uint64_t,
                            1774950217066942 as libc::c_long as uint64_t,
                            139302743555696 as libc::c_long as uint64_t,
                            66603584342787 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1782411379088302 as libc::c_long as uint64_t,
                            1096724939964781 as libc::c_long as uint64_t,
                            27593390721418 as libc::c_long as uint64_t,
                            542241850291353 as libc::c_long as uint64_t,
                            1540337798439873 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            693543956581437 as libc::c_long as uint64_t,
                            171507720360750 as libc::c_long as uint64_t,
                            1557908942697227 as libc::c_long as uint64_t,
                            1074697073443438 as libc::c_long as uint64_t,
                            1104093109037196 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            345288228393419 as libc::c_long as uint64_t,
                            1099643569747172 as libc::c_long as uint64_t,
                            134881908403743 as libc::c_long as uint64_t,
                            1740551994106740 as libc::c_long as uint64_t,
                            248212179299770 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            231429562203065 as libc::c_long as uint64_t,
                            1526290236421172 as libc::c_long as uint64_t,
                            2021375064026423 as libc::c_long as uint64_t,
                            1520954495658041 as libc::c_long as uint64_t,
                            806337791525116 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1079623667189886 as libc::c_long as uint64_t,
                            872403650198613 as libc::c_long as uint64_t,
                            766894200588288 as libc::c_long as uint64_t,
                            2163700860774109 as libc::c_long as uint64_t,
                            2023464507911816 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            854645372543796 as libc::c_long as uint64_t,
                            1936406001954827 as libc::c_long as uint64_t,
                            151460662541253 as libc::c_long as uint64_t,
                            825325739271555 as libc::c_long as uint64_t,
                            1554306377287556 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1497138821904622 as libc::c_long as uint64_t,
                            1044820250515590 as libc::c_long as uint64_t,
                            1742593886423484 as libc::c_long as uint64_t,
                            1237204112746837 as libc::c_long as uint64_t,
                            849047450816987 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            667962773375330 as libc::c_long as uint64_t,
                            1897271816877105 as libc::c_long as uint64_t,
                            1399712621683474 as libc::c_long as uint64_t,
                            1143302161683099 as libc::c_long as uint64_t,
                            2081798441209593 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            127147851567005 as libc::c_long as uint64_t,
                            1936114012888110 as libc::c_long as uint64_t,
                            1704424366552046 as libc::c_long as uint64_t,
                            856674880716312 as libc::c_long as uint64_t,
                            716603621335359 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1072409664800960 as libc::c_long as uint64_t,
                            2146937497077528 as libc::c_long as uint64_t,
                            1508780108920651 as libc::c_long as uint64_t,
                            935767602384853 as libc::c_long as uint64_t,
                            1112800433544068 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            333549023751292 as libc::c_long as uint64_t,
                            280219272863308 as libc::c_long as uint64_t,
                            2104176666454852 as libc::c_long as uint64_t,
                            1036466864875785 as libc::c_long as uint64_t,
                            536135186520207 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            373666279883137 as libc::c_long as uint64_t,
                            146457241530109 as libc::c_long as uint64_t,
                            304116267127857 as libc::c_long as uint64_t,
                            416088749147715 as libc::c_long as uint64_t,
                            1258577131183391 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1186115062588401 as libc::c_long as uint64_t,
                            2251609796968486 as libc::c_long as uint64_t,
                            1098944457878953 as libc::c_long as uint64_t,
                            1153112761201374 as libc::c_long as uint64_t,
                            1791625503417267 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1870078460219737 as libc::c_long as uint64_t,
                            2129630962183380 as libc::c_long as uint64_t,
                            852283639691142 as libc::c_long as uint64_t,
                            292865602592851 as libc::c_long as uint64_t,
                            401904317342226 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1361070124828035 as libc::c_long as uint64_t,
                            815664541425524 as libc::c_long as uint64_t,
                            1026798897364671 as libc::c_long as uint64_t,
                            1951790935390647 as libc::c_long as uint64_t,
                            555874891834790 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1546301003424277 as libc::c_long as uint64_t,
                            459094500062839 as libc::c_long as uint64_t,
                            1097668518375311 as libc::c_long as uint64_t,
                            1780297770129643 as libc::c_long as uint64_t,
                            720763293687608 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1212405311403990 as libc::c_long as uint64_t,
                            1536693382542438 as libc::c_long as uint64_t,
                            61028431067459 as libc::c_long as uint64_t,
                            1863929423417129 as libc::c_long as uint64_t,
                            1223219538638038 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1294303766540260 as libc::c_long as uint64_t,
                            1183557465955093 as libc::c_long as uint64_t,
                            882271357233093 as libc::c_long as uint64_t,
                            63854569425375 as libc::c_long as uint64_t,
                            2213283684565087 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            339050984211414 as libc::c_long as uint64_t,
                            601386726509773 as libc::c_long as uint64_t,
                            413735232134068 as libc::c_long as uint64_t,
                            966191255137228 as libc::c_long as uint64_t,
                            1839475899458159 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            235605972169408 as libc::c_long as uint64_t,
                            2174055643032978 as libc::c_long as uint64_t,
                            1538335001838863 as libc::c_long as uint64_t,
                            1281866796917192 as libc::c_long as uint64_t,
                            1815940222628465 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1632352921721536 as libc::c_long as uint64_t,
                            1833328609514701 as libc::c_long as uint64_t,
                            2092779091951987 as libc::c_long as uint64_t,
                            1923956201873226 as libc::c_long as uint64_t,
                            2210068022482919 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            35271216625062 as libc::c_long as uint64_t,
                            1712350667021807 as libc::c_long as uint64_t,
                            983664255668860 as libc::c_long as uint64_t,
                            98571260373038 as libc::c_long as uint64_t,
                            1232645608559836 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1998172393429622 as libc::c_long as uint64_t,
                            1798947921427073 as libc::c_long as uint64_t,
                            784387737563581 as libc::c_long as uint64_t,
                            1589352214827263 as libc::c_long as uint64_t,
                            1589861734168180 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1733739258725305 as libc::c_long as uint64_t,
                            31715717059538 as libc::c_long as uint64_t,
                            201969945218860 as libc::c_long as uint64_t,
                            992093044556990 as libc::c_long as uint64_t,
                            1194308773174556 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            846415389605137 as libc::c_long as uint64_t,
                            746163495539180 as libc::c_long as uint64_t,
                            829658752826080 as libc::c_long as uint64_t,
                            592067705956946 as libc::c_long as uint64_t,
                            957242537821393 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1758148849754419 as libc::c_long as uint64_t,
                            619249044817679 as libc::c_long as uint64_t,
                            168089007997045 as libc::c_long as uint64_t,
                            1371497636330523 as libc::c_long as uint64_t,
                            1867101418880350 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            326633984209635 as libc::c_long as uint64_t,
                            261759506071016 as libc::c_long as uint64_t,
                            1700682323676193 as libc::c_long as uint64_t,
                            1577907266349064 as libc::c_long as uint64_t,
                            1217647663383016 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1714182387328607 as libc::c_long as uint64_t,
                            1477856482074168 as libc::c_long as uint64_t,
                            574895689942184 as libc::c_long as uint64_t,
                            2159118410227270 as libc::c_long as uint64_t,
                            1555532449716575 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            853828206885131 as libc::c_long as uint64_t,
                            998498946036955 as libc::c_long as uint64_t,
                            1835887550391235 as libc::c_long as uint64_t,
                            207627336608048 as libc::c_long as uint64_t,
                            258363815956050 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            141141474651677 as libc::c_long as uint64_t,
                            1236728744905256 as libc::c_long as uint64_t,
                            643101419899887 as libc::c_long as uint64_t,
                            1646615130509173 as libc::c_long as uint64_t,
                            1208239602291765 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1501663228068911 as libc::c_long as uint64_t,
                            1354879465566912 as libc::c_long as uint64_t,
                            1444432675498247 as libc::c_long as uint64_t,
                            897812463852601 as libc::c_long as uint64_t,
                            855062598754348 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            714380763546606 as libc::c_long as uint64_t,
                            1032824444965790 as libc::c_long as uint64_t,
                            1774073483745338 as libc::c_long as uint64_t,
                            1063840874947367 as libc::c_long as uint64_t,
                            1738680636537158 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1640635546696252 as libc::c_long as uint64_t,
                            633168953192112 as libc::c_long as uint64_t,
                            2212651044092396 as libc::c_long as uint64_t,
                            30590958583852 as libc::c_long as uint64_t,
                            368515260889378 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1171650314802029 as libc::c_long as uint64_t,
                            1567085444565577 as libc::c_long as uint64_t,
                            1453660792008405 as libc::c_long as uint64_t,
                            757914533009261 as libc::c_long as uint64_t,
                            1619511342778196 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            420958967093237 as libc::c_long as uint64_t,
                            971103481109486 as libc::c_long as uint64_t,
                            2169549185607107 as libc::c_long as uint64_t,
                            1301191633558497 as libc::c_long as uint64_t,
                            1661514101014240 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            907123651818302 as libc::c_long as uint64_t,
                            1332556122804146 as libc::c_long as uint64_t,
                            1824055253424487 as libc::c_long as uint64_t,
                            1367614217442959 as libc::c_long as uint64_t,
                            1982558335973172 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1121533090144639 as libc::c_long as uint64_t,
                            1021251337022187 as libc::c_long as uint64_t,
                            110469995947421 as libc::c_long as uint64_t,
                            1511059774758394 as libc::c_long as uint64_t,
                            2110035908131662 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            303213233384524 as libc::c_long as uint64_t,
                            2061932261128138 as libc::c_long as uint64_t,
                            352862124777736 as libc::c_long as uint64_t,
                            40828818670255 as libc::c_long as uint64_t,
                            249879468482660 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            856559257852200 as libc::c_long as uint64_t,
                            508517664949010 as libc::c_long as uint64_t,
                            1378193767894916 as libc::c_long as uint64_t,
                            1723459126947129 as libc::c_long as uint64_t,
                            1962275756614521 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1445691340537320 as libc::c_long as uint64_t,
                            40614383122127 as libc::c_long as uint64_t,
                            402104303144865 as libc::c_long as uint64_t,
                            485134269878232 as libc::c_long as uint64_t,
                            1659439323587426 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            20057458979482 as libc::c_long as uint64_t,
                            1183363722525800 as libc::c_long as uint64_t,
                            2140003847237215 as libc::c_long as uint64_t,
                            2053873950687614 as libc::c_long as uint64_t,
                            2112017736174909 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2228654250927986 as libc::c_long as uint64_t,
                            1483591363415267 as libc::c_long as uint64_t,
                            1368661293910956 as libc::c_long as uint64_t,
                            1076511285177291 as libc::c_long as uint64_t,
                            526650682059608 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            709481497028540 as libc::c_long as uint64_t,
                            531682216165724 as libc::c_long as uint64_t,
                            316963769431931 as libc::c_long as uint64_t,
                            1814315888453765 as libc::c_long as uint64_t,
                            258560242424104 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1053447823660455 as libc::c_long as uint64_t,
                            1955135194248683 as libc::c_long as uint64_t,
                            1010900954918985 as libc::c_long as uint64_t,
                            1182614026976701 as libc::c_long as uint64_t,
                            1240051576966610 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1957943897155497 as libc::c_long as uint64_t,
                            1788667368028035 as libc::c_long as uint64_t,
                            137692910029106 as libc::c_long as uint64_t,
                            1039519607062 as libc::c_long as uint64_t,
                            826404763313028 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1848942433095597 as libc::c_long as uint64_t,
                            1582009882530495 as libc::c_long as uint64_t,
                            1849292741020143 as libc::c_long as uint64_t,
                            1068498323302788 as libc::c_long as uint64_t,
                            2001402229799484 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1528282417624269 as libc::c_long as uint64_t,
                            2142492439828191 as libc::c_long as uint64_t,
                            2179662545816034 as libc::c_long as uint64_t,
                            362568973150328 as libc::c_long as uint64_t,
                            1591374675250271 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            160026679434388 as libc::c_long as uint64_t,
                            232341189218716 as libc::c_long as uint64_t,
                            2149181472355545 as libc::c_long as uint64_t,
                            598041771119831 as libc::c_long as uint64_t,
                            183859001910173 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2013278155187349 as libc::c_long as uint64_t,
                            662660471354454 as libc::c_long as uint64_t,
                            793981225706267 as libc::c_long as uint64_t,
                            411706605985744 as libc::c_long as uint64_t,
                            804490933124791 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2051892037280204 as libc::c_long as uint64_t,
                            488391251096321 as libc::c_long as uint64_t,
                            2230187337030708 as libc::c_long as uint64_t,
                            930221970662692 as libc::c_long as uint64_t,
                            679002758255210 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1530723630438670 as libc::c_long as uint64_t,
                            875873929577927 as libc::c_long as uint64_t,
                            341560134269988 as libc::c_long as uint64_t,
                            449903119530753 as libc::c_long as uint64_t,
                            1055551308214179 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1461835919309432 as libc::c_long as uint64_t,
                            1955256480136428 as libc::c_long as uint64_t,
                            180866187813063 as libc::c_long as uint64_t,
                            1551979252664528 as libc::c_long as uint64_t,
                            557743861963950 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            359179641731115 as libc::c_long as uint64_t,
                            1324915145732949 as libc::c_long as uint64_t,
                            902828372691474 as libc::c_long as uint64_t,
                            294254275669987 as libc::c_long as uint64_t,
                            1887036027752957 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2043271609454323 as libc::c_long as uint64_t,
                            2038225437857464 as libc::c_long as uint64_t,
                            1317528426475850 as libc::c_long as uint64_t,
                            1398989128982787 as libc::c_long as uint64_t,
                            2027639881006861 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2072902725256516 as libc::c_long as uint64_t,
                            312132452743412 as libc::c_long as uint64_t,
                            309930885642209 as libc::c_long as uint64_t,
                            996244312618453 as libc::c_long as uint64_t,
                            1590501300352303 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1397254305160710 as libc::c_long as uint64_t,
                            695734355138021 as libc::c_long as uint64_t,
                            2233992044438756 as libc::c_long as uint64_t,
                            1776180593969996 as libc::c_long as uint64_t,
                            1085588199351115 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            440567051331029 as libc::c_long as uint64_t,
                            254894786356681 as libc::c_long as uint64_t,
                            493869224930222 as libc::c_long as uint64_t,
                            1556322069683366 as libc::c_long as uint64_t,
                            1567456540319218 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1950722461391320 as libc::c_long as uint64_t,
                            1907845598854797 as libc::c_long as uint64_t,
                            1822757481635527 as libc::c_long as uint64_t,
                            2121567704750244 as libc::c_long as uint64_t,
                            73811931471221 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            387139307395758 as libc::c_long as uint64_t,
                            2058036430315676 as libc::c_long as uint64_t,
                            1220915649965325 as libc::c_long as uint64_t,
                            1794832055328951 as libc::c_long as uint64_t,
                            1230009312169328 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1765973779329517 as libc::c_long as uint64_t,
                            659344059446977 as libc::c_long as uint64_t,
                            19821901606666 as libc::c_long as uint64_t,
                            1301928341311214 as libc::c_long as uint64_t,
                            1116266004075885 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1127572801181483 as libc::c_long as uint64_t,
                            1224743760571696 as libc::c_long as uint64_t,
                            1276219889847274 as libc::c_long as uint64_t,
                            1529738721702581 as libc::c_long as uint64_t,
                            1589819666871853 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2181229378964934 as libc::c_long as uint64_t,
                            2190885205260020 as libc::c_long as uint64_t,
                            1511536077659137 as libc::c_long as uint64_t,
                            1246504208580490 as libc::c_long as uint64_t,
                            668883326494241 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            437866655573314 as libc::c_long as uint64_t,
                            669026411194768 as libc::c_long as uint64_t,
                            81896997980338 as libc::c_long as uint64_t,
                            523874406393178 as libc::c_long as uint64_t,
                            245052060935236 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1975438052228868 as libc::c_long as uint64_t,
                            1071801519999806 as libc::c_long as uint64_t,
                            594652299224319 as libc::c_long as uint64_t,
                            1877697652668809 as libc::c_long as uint64_t,
                            1489635366987285 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            958592545673770 as libc::c_long as uint64_t,
                            233048016518599 as libc::c_long as uint64_t,
                            851568750216589 as libc::c_long as uint64_t,
                            567703851596087 as libc::c_long as uint64_t,
                            1740300006094761 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2014540178270324 as libc::c_long as uint64_t,
                            192672779514432 as libc::c_long as uint64_t,
                            213877182641530 as libc::c_long as uint64_t,
                            2194819933853411 as libc::c_long as uint64_t,
                            1716422829364835 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1540769606609725 as libc::c_long as uint64_t,
                            2148289943846077 as libc::c_long as uint64_t,
                            1597804156127445 as libc::c_long as uint64_t,
                            1230603716683868 as libc::c_long as uint64_t,
                            815423458809453 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1738560251245018 as libc::c_long as uint64_t,
                            1779576754536888 as libc::c_long as uint64_t,
                            1783765347671392 as libc::c_long as uint64_t,
                            1880170990446751 as libc::c_long as uint64_t,
                            1088225159617541 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            659303913929492 as libc::c_long as uint64_t,
                            1956447718227573 as libc::c_long as uint64_t,
                            1830568515922666 as libc::c_long as uint64_t,
                            841069049744408 as libc::c_long as uint64_t,
                            1669607124206368 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1143465490433355 as libc::c_long as uint64_t,
                            1532194726196059 as libc::c_long as uint64_t,
                            1093276745494697 as libc::c_long as uint64_t,
                            481041706116088 as libc::c_long as uint64_t,
                            2121405433561163 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1686424298744462 as libc::c_long as uint64_t,
                            1451806974487153 as libc::c_long as uint64_t,
                            266296068846582 as libc::c_long as uint64_t,
                            1834686947542675 as libc::c_long as uint64_t,
                            1720762336132256 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            889217026388959 as libc::c_long as uint64_t,
                            1043290623284660 as libc::c_long as uint64_t,
                            856125087551909 as libc::c_long as uint64_t,
                            1669272323124636 as libc::c_long as uint64_t,
                            1603340330827879 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1206396181488998 as libc::c_long as uint64_t,
                            333158148435054 as libc::c_long as uint64_t,
                            1402633492821422 as libc::c_long as uint64_t,
                            1120091191722026 as libc::c_long as uint64_t,
                            1945474114550509 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            766720088232571 as libc::c_long as uint64_t,
                            1512222781191002 as libc::c_long as uint64_t,
                            1189719893490790 as libc::c_long as uint64_t,
                            2091302129467914 as libc::c_long as uint64_t,
                            2141418006894941 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            419663647306612 as libc::c_long as uint64_t,
                            1998875112167987 as libc::c_long as uint64_t,
                            1426599870253707 as libc::c_long as uint64_t,
                            1154928355379510 as libc::c_long as uint64_t,
                            486538532138187 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            938160078005954 as libc::c_long as uint64_t,
                            1421776319053174 as libc::c_long as uint64_t,
                            1941643234741774 as libc::c_long as uint64_t,
                            180002183320818 as libc::c_long as uint64_t,
                            1414380336750546 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            398001940109652 as libc::c_long as uint64_t,
                            1577721237663248 as libc::c_long as uint64_t,
                            1012748649830402 as libc::c_long as uint64_t,
                            1540516006905144 as libc::c_long as uint64_t,
                            1011684812884559 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1653276489969630 as libc::c_long as uint64_t,
                            6081825167624 as libc::c_long as uint64_t,
                            1921777941170836 as libc::c_long as uint64_t,
                            1604139841794531 as libc::c_long as uint64_t,
                            861211053640641 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            996661541407379 as libc::c_long as uint64_t,
                            1455877387952927 as libc::c_long as uint64_t,
                            744312806857277 as libc::c_long as uint64_t,
                            139213896196746 as libc::c_long as uint64_t,
                            1000282908547789 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1450817495603008 as libc::c_long as uint64_t,
                            1476865707053229 as libc::c_long as uint64_t,
                            1030490562252053 as libc::c_long as uint64_t,
                            620966950353376 as libc::c_long as uint64_t,
                            1744760161539058 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            559728410002599 as libc::c_long as uint64_t,
                            37056661641185 as libc::c_long as uint64_t,
                            2038622963352006 as libc::c_long as uint64_t,
                            1637244893271723 as libc::c_long as uint64_t,
                            1026565352238948 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            962165956135846 as libc::c_long as uint64_t,
                            1116599660248791 as libc::c_long as uint64_t,
                            182090178006815 as libc::c_long as uint64_t,
                            1455605467021751 as libc::c_long as uint64_t,
                            196053588803284 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            796863823080135 as libc::c_long as uint64_t,
                            1897365583584155 as libc::c_long as uint64_t,
                            420466939481601 as libc::c_long as uint64_t,
                            2165972651724672 as libc::c_long as uint64_t,
                            932177357788289 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            877047233620632 as libc::c_long as uint64_t,
                            1375632631944375 as libc::c_long as uint64_t,
                            643773611882121 as libc::c_long as uint64_t,
                            660022738847877 as libc::c_long as uint64_t,
                            19353932331831 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2216943882299338 as libc::c_long as uint64_t,
                            394841323190322 as libc::c_long as uint64_t,
                            2222656898319671 as libc::c_long as uint64_t,
                            558186553950529 as libc::c_long as uint64_t,
                            1077236877025190 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            801118384953213 as libc::c_long as uint64_t,
                            1914330175515892 as libc::c_long as uint64_t,
                            574541023311511 as libc::c_long as uint64_t,
                            1471123787903705 as libc::c_long as uint64_t,
                            1526158900256288 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            949617889087234 as libc::c_long as uint64_t,
                            2207116611267331 as libc::c_long as uint64_t,
                            912920039141287 as libc::c_long as uint64_t,
                            501158539198789 as libc::c_long as uint64_t,
                            62362560771472 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1474518386765335 as libc::c_long as uint64_t,
                            1760793622169197 as libc::c_long as uint64_t,
                            1157399790472736 as libc::c_long as uint64_t,
                            1622864308058898 as libc::c_long as uint64_t,
                            165428294422792 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1961673048027128 as libc::c_long as uint64_t,
                            102619413083113 as libc::c_long as uint64_t,
                            1051982726768458 as libc::c_long as uint64_t,
                            1603657989805485 as libc::c_long as uint64_t,
                            1941613251499678 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1401939116319266 as libc::c_long as uint64_t,
                            335306339903072 as libc::c_long as uint64_t,
                            72046196085786 as libc::c_long as uint64_t,
                            862423201496006 as libc::c_long as uint64_t,
                            850518754531384 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1234706593321979 as libc::c_long as uint64_t,
                            1083343891215917 as libc::c_long as uint64_t,
                            898273974314935 as libc::c_long as uint64_t,
                            1640859118399498 as libc::c_long as uint64_t,
                            157578398571149 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1143483057726416 as libc::c_long as uint64_t,
                            1992614991758919 as libc::c_long as uint64_t,
                            674268662140796 as libc::c_long as uint64_t,
                            1773370048077526 as libc::c_long as uint64_t,
                            674318359920189 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1835401379538542 as libc::c_long as uint64_t,
                            173900035308392 as libc::c_long as uint64_t,
                            818247630716732 as libc::c_long as uint64_t,
                            1762100412152786 as libc::c_long as uint64_t,
                            1021506399448291 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1506632088156630 as libc::c_long as uint64_t,
                            2127481795522179 as libc::c_long as uint64_t,
                            513812919490255 as libc::c_long as uint64_t,
                            140643715928370 as libc::c_long as uint64_t,
                            442476620300318 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2056683376856736 as libc::c_long as uint64_t,
                            219094741662735 as libc::c_long as uint64_t,
                            2193541883188309 as libc::c_long as uint64_t,
                            1841182310235800 as libc::c_long as uint64_t,
                            556477468664293 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1315019427910827 as libc::c_long as uint64_t,
                            1049075855992603 as libc::c_long as uint64_t,
                            2066573052986543 as libc::c_long as uint64_t,
                            266904467185534 as libc::c_long as uint64_t,
                            2040482348591520 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            94096246544434 as libc::c_long as uint64_t,
                            922482381166992 as libc::c_long as uint64_t,
                            24517828745563 as libc::c_long as uint64_t,
                            2139430508542503 as libc::c_long as uint64_t,
                            2097139044231004 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            537697207950515 as libc::c_long as uint64_t,
                            1399352016347350 as libc::c_long as uint64_t,
                            1563663552106345 as libc::c_long as uint64_t,
                            2148749520888918 as libc::c_long as uint64_t,
                            549922092988516 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1747985413252434 as libc::c_long as uint64_t,
                            680511052635695 as libc::c_long as uint64_t,
                            1809559829982725 as libc::c_long as uint64_t,
                            594274250930054 as libc::c_long as uint64_t,
                            201673170745982 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            323583936109569 as libc::c_long as uint64_t,
                            1973572998577657 as libc::c_long as uint64_t,
                            1192219029966558 as libc::c_long as uint64_t,
                            79354804385273 as libc::c_long as uint64_t,
                            1374043025560347 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            213277331329947 as libc::c_long as uint64_t,
                            416202017849623 as libc::c_long as uint64_t,
                            1950535221091783 as libc::c_long as uint64_t,
                            1313441578103244 as libc::c_long as uint64_t,
                            2171386783823658 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            189088804229831 as libc::c_long as uint64_t,
                            993969372859110 as libc::c_long as uint64_t,
                            895870121536987 as libc::c_long as uint64_t,
                            1547301535298256 as libc::c_long as uint64_t,
                            1477373024911350 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1620578418245010 as libc::c_long as uint64_t,
                            541035331188469 as libc::c_long as uint64_t,
                            2235785724453865 as libc::c_long as uint64_t,
                            2154865809088198 as libc::c_long as uint64_t,
                            1974627268751826 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1346805451740245 as libc::c_long as uint64_t,
                            1350981335690626 as libc::c_long as uint64_t,
                            942744349501813 as libc::c_long as uint64_t,
                            2155094562545502 as libc::c_long as uint64_t,
                            1012483751693409 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2107080134091762 as libc::c_long as uint64_t,
                            1132567062788208 as libc::c_long as uint64_t,
                            1824935377687210 as libc::c_long as uint64_t,
                            769194804343737 as libc::c_long as uint64_t,
                            1857941799971888 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1074666112436467 as libc::c_long as uint64_t,
                            249279386739593 as libc::c_long as uint64_t,
                            1174337926625354 as libc::c_long as uint64_t,
                            1559013532006480 as libc::c_long as uint64_t,
                            1472287775519121 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1872620123779532 as libc::c_long as uint64_t,
                            1892932666768992 as libc::c_long as uint64_t,
                            1921559078394978 as libc::c_long as uint64_t,
                            1270573311796160 as libc::c_long as uint64_t,
                            1438913646755037 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            837390187648199 as libc::c_long as uint64_t,
                            1012253300223599 as libc::c_long as uint64_t,
                            989780015893987 as libc::c_long as uint64_t,
                            1351393287739814 as libc::c_long as uint64_t,
                            328627746545550 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1028328827183114 as libc::c_long as uint64_t,
                            1711043289969857 as libc::c_long as uint64_t,
                            1350832470374933 as libc::c_long as uint64_t,
                            1923164689604327 as libc::c_long as uint64_t,
                            1495656368846911 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1900828492104143 as libc::c_long as uint64_t,
                            430212361082163 as libc::c_long as uint64_t,
                            687437570852799 as libc::c_long as uint64_t,
                            832514536673512 as libc::c_long as uint64_t,
                            1685641495940794 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            842632847936398 as libc::c_long as uint64_t,
                            605670026766216 as libc::c_long as uint64_t,
                            290836444839585 as libc::c_long as uint64_t,
                            163210774892356 as libc::c_long as uint64_t,
                            2213815011799645 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1176336383453996 as libc::c_long as uint64_t,
                            1725477294339771 as libc::c_long as uint64_t,
                            12700622672454 as libc::c_long as uint64_t,
                            678015708818208 as libc::c_long as uint64_t,
                            162724078519879 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1448049969043497 as libc::c_long as uint64_t,
                            1789411762943521 as libc::c_long as uint64_t,
                            385587766217753 as libc::c_long as uint64_t,
                            90201620913498 as libc::c_long as uint64_t,
                            832999441066823 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            516086333293313 as libc::c_long as uint64_t,
                            2240508292484616 as libc::c_long as uint64_t,
                            1351669528166508 as libc::c_long as uint64_t,
                            1223255565316488 as libc::c_long as uint64_t,
                            750235824427138 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1263624896582495 as libc::c_long as uint64_t,
                            1102602401673328 as libc::c_long as uint64_t,
                            526302183714372 as libc::c_long as uint64_t,
                            2152015839128799 as libc::c_long as uint64_t,
                            1483839308490010 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            442991718646863 as libc::c_long as uint64_t,
                            1599275157036458 as libc::c_long as uint64_t,
                            1925389027579192 as libc::c_long as uint64_t,
                            899514691371390 as libc::c_long as uint64_t,
                            350263251085160 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1689713572022143 as libc::c_long as uint64_t,
                            593854559254373 as libc::c_long as uint64_t,
                            978095044791970 as libc::c_long as uint64_t,
                            1985127338729499 as libc::c_long as uint64_t,
                            1676069120347625 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1557207018622683 as libc::c_long as uint64_t,
                            340631692799603 as libc::c_long as uint64_t,
                            1477725909476187 as libc::c_long as uint64_t,
                            614735951619419 as libc::c_long as uint64_t,
                            2033237123746766 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            968764929340557 as libc::c_long as uint64_t,
                            1225534776710944 as libc::c_long as uint64_t,
                            662967304013036 as libc::c_long as uint64_t,
                            1155521416178595 as libc::c_long as uint64_t,
                            791142883466590 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1487081286167458 as libc::c_long as uint64_t,
                            993039441814934 as libc::c_long as uint64_t,
                            1792378982844640 as libc::c_long as uint64_t,
                            698652444999874 as libc::c_long as uint64_t,
                            2153908693179754 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1123181311102823 as libc::c_long as uint64_t,
                            685575944875442 as libc::c_long as uint64_t,
                            507605465509927 as libc::c_long as uint64_t,
                            1412590462117473 as libc::c_long as uint64_t,
                            568017325228626 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            560258797465417 as libc::c_long as uint64_t,
                            2193971151466401 as libc::c_long as uint64_t,
                            1824086900849026 as libc::c_long as uint64_t,
                            579056363542056 as libc::c_long as uint64_t,
                            1690063960036441 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1918407319222416 as libc::c_long as uint64_t,
                            353767553059963 as libc::c_long as uint64_t,
                            1930426334528099 as libc::c_long as uint64_t,
                            1564816146005724 as libc::c_long as uint64_t,
                            1861342381708096 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2131325168777276 as libc::c_long as uint64_t,
                            1176636658428908 as libc::c_long as uint64_t,
                            1756922641512981 as libc::c_long as uint64_t,
                            1390243617176012 as libc::c_long as uint64_t,
                            1966325177038383 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2063958120364491 as libc::c_long as uint64_t,
                            2140267332393533 as libc::c_long as uint64_t,
                            699896251574968 as libc::c_long as uint64_t,
                            273268351312140 as libc::c_long as uint64_t,
                            375580724713232 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2024297515263178 as libc::c_long as uint64_t,
                            416959329722687 as libc::c_long as uint64_t,
                            1079014235017302 as libc::c_long as uint64_t,
                            171612225573183 as libc::c_long as uint64_t,
                            1031677520051053 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2033900009388450 as libc::c_long as uint64_t,
                            1744902869870788 as libc::c_long as uint64_t,
                            2190580087917640 as libc::c_long as uint64_t,
                            1949474984254121 as libc::c_long as uint64_t,
                            231049754293748 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            343868674606581 as libc::c_long as uint64_t,
                            550155864008088 as libc::c_long as uint64_t,
                            1450580864229630 as libc::c_long as uint64_t,
                            481603765195050 as libc::c_long as uint64_t,
                            896972360018042 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2151139328380127 as libc::c_long as uint64_t,
                            314745882084928 as libc::c_long as uint64_t,
                            59756825775204 as libc::c_long as uint64_t,
                            1676664391494651 as libc::c_long as uint64_t,
                            2048348075599360 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1528930066340597 as libc::c_long as uint64_t,
                            1605003907059576 as libc::c_long as uint64_t,
                            1055061081337675 as libc::c_long as uint64_t,
                            1458319101947665 as libc::c_long as uint64_t,
                            1234195845213142 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            830430507734812 as libc::c_long as uint64_t,
                            1780282976102377 as libc::c_long as uint64_t,
                            1425386760709037 as libc::c_long as uint64_t,
                            362399353095425 as libc::c_long as uint64_t,
                            2168861579799910 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1155762232730333 as libc::c_long as uint64_t,
                            980662895504006 as libc::c_long as uint64_t,
                            2053766700883521 as libc::c_long as uint64_t,
                            490966214077606 as libc::c_long as uint64_t,
                            510405877041357 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1683750316716132 as libc::c_long as uint64_t,
                            652278688286128 as libc::c_long as uint64_t,
                            1221798761193539 as libc::c_long as uint64_t,
                            1897360681476669 as libc::c_long as uint64_t,
                            319658166027343 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            618808732869972 as libc::c_long as uint64_t,
                            72755186759744 as libc::c_long as uint64_t,
                            2060379135624181 as libc::c_long as uint64_t,
                            1730731526741822 as libc::c_long as uint64_t,
                            48862757828238 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1463171970593505 as libc::c_long as uint64_t,
                            1143040711767452 as libc::c_long as uint64_t,
                            614590986558883 as libc::c_long as uint64_t,
                            1409210575145591 as libc::c_long as uint64_t,
                            1882816996436803 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2230133264691131 as libc::c_long as uint64_t,
                            563950955091024 as libc::c_long as uint64_t,
                            2042915975426398 as libc::c_long as uint64_t,
                            827314356293472 as libc::c_long as uint64_t,
                            672028980152815 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            264204366029760 as libc::c_long as uint64_t,
                            1654686424479449 as libc::c_long as uint64_t,
                            2185050199932931 as libc::c_long as uint64_t,
                            2207056159091748 as libc::c_long as uint64_t,
                            506015669043634 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1784446333136569 as libc::c_long as uint64_t,
                            1973746527984364 as libc::c_long as uint64_t,
                            334856327359575 as libc::c_long as uint64_t,
                            1156769775884610 as libc::c_long as uint64_t,
                            1023950124675478 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2065270940578383 as libc::c_long as uint64_t,
                            31477096270353 as libc::c_long as uint64_t,
                            306421879113491 as libc::c_long as uint64_t,
                            181958643936686 as libc::c_long as uint64_t,
                            1907105536686083 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1496516440779464 as libc::c_long as uint64_t,
                            1748485652986458 as libc::c_long as uint64_t,
                            872778352227340 as libc::c_long as uint64_t,
                            818358834654919 as libc::c_long as uint64_t,
                            97932669284220 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            471636015770351 as libc::c_long as uint64_t,
                            672455402793577 as libc::c_long as uint64_t,
                            1804995246884103 as libc::c_long as uint64_t,
                            1842309243470804 as libc::c_long as uint64_t,
                            1501862504981682 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1013216974933691 as libc::c_long as uint64_t,
                            538921919682598 as libc::c_long as uint64_t,
                            1915776722521558 as libc::c_long as uint64_t,
                            1742822441583877 as libc::c_long as uint64_t,
                            1886550687916656 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            2094270000643336 as libc::c_long as uint64_t,
                            303971879192276 as libc::c_long as uint64_t,
                            40801275554748 as libc::c_long as uint64_t,
                            649448917027930 as libc::c_long as uint64_t,
                            1818544418535447 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2241737709499165 as libc::c_long as uint64_t,
                            549397817447461 as libc::c_long as uint64_t,
                            838180519319392 as libc::c_long as uint64_t,
                            1725686958520781 as libc::c_long as uint64_t,
                            1705639080897747 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1216074541925116 as libc::c_long as uint64_t,
                            50120933933509 as libc::c_long as uint64_t,
                            1565829004133810 as libc::c_long as uint64_t,
                            721728156134580 as libc::c_long as uint64_t,
                            349206064666188 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            948617110470858 as libc::c_long as uint64_t,
                            346222547451945 as libc::c_long as uint64_t,
                            1126511960599975 as libc::c_long as uint64_t,
                            1759386906004538 as libc::c_long as uint64_t,
                            493053284802266 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1454933046815146 as libc::c_long as uint64_t,
                            874696014266362 as libc::c_long as uint64_t,
                            1467170975468588 as libc::c_long as uint64_t,
                            1432316382418897 as libc::c_long as uint64_t,
                            2111710746366763 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2105387117364450 as libc::c_long as uint64_t,
                            1996463405126433 as libc::c_long as uint64_t,
                            1303008614294500 as libc::c_long as uint64_t,
                            851908115948209 as libc::c_long as uint64_t,
                            1353742049788635 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            750300956351719 as libc::c_long as uint64_t,
                            1487736556065813 as libc::c_long as uint64_t,
                            15158817002104 as libc::c_long as uint64_t,
                            1511998221598392 as libc::c_long as uint64_t,
                            971739901354129 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1874648163531693 as libc::c_long as uint64_t,
                            2124487685930551 as libc::c_long as uint64_t,
                            1810030029384882 as libc::c_long as uint64_t,
                            918400043048335 as libc::c_long as uint64_t,
                            586348627300650 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1235084464747900 as libc::c_long as uint64_t,
                            1166111146432082 as libc::c_long as uint64_t,
                            1745394857881591 as libc::c_long as uint64_t,
                            1405516473883040 as libc::c_long as uint64_t,
                            4463504151617 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1663810156463827 as libc::c_long as uint64_t,
                            327797390285791 as libc::c_long as uint64_t,
                            1341846161759410 as libc::c_long as uint64_t,
                            1964121122800605 as libc::c_long as uint64_t,
                            1747470312055380 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            660005247548233 as libc::c_long as uint64_t,
                            2071860029952887 as libc::c_long as uint64_t,
                            1358748199950107 as libc::c_long as uint64_t,
                            911703252219107 as libc::c_long as uint64_t,
                            1014379923023831 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2206641276178231 as libc::c_long as uint64_t,
                            1690587809721504 as libc::c_long as uint64_t,
                            1600173622825126 as libc::c_long as uint64_t,
                            2156096097634421 as libc::c_long as uint64_t,
                            1106822408548216 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1344788193552206 as libc::c_long as uint64_t,
                            1949552134239140 as libc::c_long as uint64_t,
                            1735915881729557 as libc::c_long as uint64_t,
                            675891104100469 as libc::c_long as uint64_t,
                            1834220014427292 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1920949492387964 as libc::c_long as uint64_t,
                            158885288387530 as libc::c_long as uint64_t,
                            70308263664033 as libc::c_long as uint64_t,
                            626038464897817 as libc::c_long as uint64_t,
                            1468081726101009 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            622221042073383 as libc::c_long as uint64_t,
                            1210146474039168 as libc::c_long as uint64_t,
                            1742246422343683 as libc::c_long as uint64_t,
                            1403839361379025 as libc::c_long as uint64_t,
                            417189490895736 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            22727256592983 as libc::c_long as uint64_t,
                            168471543384997 as libc::c_long as uint64_t,
                            1324340989803650 as libc::c_long as uint64_t,
                            1839310709638189 as libc::c_long as uint64_t,
                            504999476432775 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1313240518756327 as libc::c_long as uint64_t,
                            1721896294296942 as libc::c_long as uint64_t,
                            52263574587266 as libc::c_long as uint64_t,
                            2065069734239232 as libc::c_long as uint64_t,
                            804910473424630 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1337466662091884 as libc::c_long as uint64_t,
                            1287645354669772 as libc::c_long as uint64_t,
                            2018019646776184 as libc::c_long as uint64_t,
                            652181229374245 as libc::c_long as uint64_t,
                            898011753211715 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1969792547910734 as libc::c_long as uint64_t,
                            779969968247557 as libc::c_long as uint64_t,
                            2011350094423418 as libc::c_long as uint64_t,
                            1823964252907487 as libc::c_long as uint64_t,
                            1058949448296945 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            207343737062002 as libc::c_long as uint64_t,
                            1118176942430253 as libc::c_long as uint64_t,
                            758894594548164 as libc::c_long as uint64_t,
                            806764629546266 as libc::c_long as uint64_t,
                            1157700123092949 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1273565321399022 as libc::c_long as uint64_t,
                            1638509681964574 as libc::c_long as uint64_t,
                            759235866488935 as libc::c_long as uint64_t,
                            666015124346707 as libc::c_long as uint64_t,
                            897983460943405 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1717263794012298 as libc::c_long as uint64_t,
                            1059601762860786 as libc::c_long as uint64_t,
                            1837819172257618 as libc::c_long as uint64_t,
                            1054130665797229 as libc::c_long as uint64_t,
                            680893204263559 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2237039662793603 as libc::c_long as uint64_t,
                            2249022333361206 as libc::c_long as uint64_t,
                            2058613546633703 as libc::c_long as uint64_t,
                            149454094845279 as libc::c_long as uint64_t,
                            2215176649164582 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            79472182719605 as libc::c_long as uint64_t,
                            1851130257050174 as libc::c_long as uint64_t,
                            1825744808933107 as libc::c_long as uint64_t,
                            821667333481068 as libc::c_long as uint64_t,
                            781795293511946 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            755822026485370 as libc::c_long as uint64_t,
                            152464789723500 as libc::c_long as uint64_t,
                            1178207602290608 as libc::c_long as uint64_t,
                            410307889503239 as libc::c_long as uint64_t,
                            156581253571278 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1418185496130297 as libc::c_long as uint64_t,
                            484520167728613 as libc::c_long as uint64_t,
                            1646737281442950 as libc::c_long as uint64_t,
                            1401487684670265 as libc::c_long as uint64_t,
                            1349185550126961 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1495380034400429 as libc::c_long as uint64_t,
                            325049476417173 as libc::c_long as uint64_t,
                            46346894893933 as libc::c_long as uint64_t,
                            1553408840354856 as libc::c_long as uint64_t,
                            828980101835683 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1280337889310282 as libc::c_long as uint64_t,
                            2070832742866672 as libc::c_long as uint64_t,
                            1640940617225222 as libc::c_long as uint64_t,
                            2098284908289951 as libc::c_long as uint64_t,
                            450929509534434 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            407703353998781 as libc::c_long as uint64_t,
                            126572141483652 as libc::c_long as uint64_t,
                            286039827513621 as libc::c_long as uint64_t,
                            1999255076709338 as libc::c_long as uint64_t,
                            2030511179441770 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1254958221100483 as libc::c_long as uint64_t,
                            1153235960999843 as libc::c_long as uint64_t,
                            942907704968834 as libc::c_long as uint64_t,
                            637105404087392 as libc::c_long as uint64_t,
                            1149293270147267 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            894249020470196 as libc::c_long as uint64_t,
                            400291701616810 as libc::c_long as uint64_t,
                            406878712230981 as libc::c_long as uint64_t,
                            1599128793487393 as libc::c_long as uint64_t,
                            1145868722604026 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1497955250203334 as libc::c_long as uint64_t,
                            110116344653260 as libc::c_long as uint64_t,
                            1128535642171976 as libc::c_long as uint64_t,
                            1900106496009660 as libc::c_long as uint64_t,
                            129792717460909 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            452487513298665 as libc::c_long as uint64_t,
                            1352120549024569 as libc::c_long as uint64_t,
                            1173495883910956 as libc::c_long as uint64_t,
                            1999111705922009 as libc::c_long as uint64_t,
                            367328130454226 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1717539401269642 as libc::c_long as uint64_t,
                            1475188995688487 as libc::c_long as uint64_t,
                            891921989653942 as libc::c_long as uint64_t,
                            836824441505699 as libc::c_long as uint64_t,
                            1885988485608364 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1241784121422547 as libc::c_long as uint64_t,
                            187337051947583 as libc::c_long as uint64_t,
                            1118481812236193 as libc::c_long as uint64_t,
                            428747751936362 as libc::c_long as uint64_t,
                            30358898927325 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2022432361201842 as libc::c_long as uint64_t,
                            1088816090685051 as libc::c_long as uint64_t,
                            1977843398539868 as libc::c_long as uint64_t,
                            1854834215890724 as libc::c_long as uint64_t,
                            564238862029357 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            938868489100585 as libc::c_long as uint64_t,
                            1100285072929025 as libc::c_long as uint64_t,
                            1017806255688848 as libc::c_long as uint64_t,
                            1957262154788833 as libc::c_long as uint64_t,
                            152787950560442 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            867319417678923 as libc::c_long as uint64_t,
                            620471962942542 as libc::c_long as uint64_t,
                            226032203305716 as libc::c_long as uint64_t,
                            342001443957629 as libc::c_long as uint64_t,
                            1761675818237336 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1295072362439987 as libc::c_long as uint64_t,
                            931227904689414 as libc::c_long as uint64_t,
                            1355731432641687 as libc::c_long as uint64_t,
                            922235735834035 as libc::c_long as uint64_t,
                            892227229410209 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1680989767906154 as libc::c_long as uint64_t,
                            535362787031440 as libc::c_long as uint64_t,
                            2136691276706570 as libc::c_long as uint64_t,
                            1942228485381244 as libc::c_long as uint64_t,
                            1267350086882274 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            366018233770527 as libc::c_long as uint64_t,
                            432660629755596 as libc::c_long as uint64_t,
                            126409707644535 as libc::c_long as uint64_t,
                            1973842949591662 as libc::c_long as uint64_t,
                            645627343442376 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            535509430575217 as libc::c_long as uint64_t,
                            546885533737322 as libc::c_long as uint64_t,
                            1524675609547799 as libc::c_long as uint64_t,
                            2138095752851703 as libc::c_long as uint64_t,
                            1260738089896827 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1159906385590467 as libc::c_long as uint64_t,
                            2198530004321610 as libc::c_long as uint64_t,
                            714559485023225 as libc::c_long as uint64_t,
                            81880727882151 as libc::c_long as uint64_t,
                            1484020820037082 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1377485731340769 as libc::c_long as uint64_t,
                            2046328105512000 as libc::c_long as uint64_t,
                            1802058637158797 as libc::c_long as uint64_t,
                            62146136768173 as libc::c_long as uint64_t,
                            1356993908853901 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            2013612215646735 as libc::c_long as uint64_t,
                            1830770575920375 as libc::c_long as uint64_t,
                            536135310219832 as libc::c_long as uint64_t,
                            609272325580394 as libc::c_long as uint64_t,
                            270684344495013 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1237542585982777 as libc::c_long as uint64_t,
                            2228682050256790 as libc::c_long as uint64_t,
                            1385281931622824 as libc::c_long as uint64_t,
                            593183794882890 as libc::c_long as uint64_t,
                            493654978552689 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
    [
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            47341488007760 as libc::c_long as uint64_t,
                            1891414891220257 as libc::c_long as uint64_t,
                            983894663308928 as libc::c_long as uint64_t,
                            176161768286818 as libc::c_long as uint64_t,
                            1126261115179708 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1694030170963455 as libc::c_long as uint64_t,
                            502038567066200 as libc::c_long as uint64_t,
                            1691160065225467 as libc::c_long as uint64_t,
                            949628319562187 as libc::c_long as uint64_t,
                            275110186693066 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1124515748676336 as libc::c_long as uint64_t,
                            1661673816593408 as libc::c_long as uint64_t,
                            1499640319059718 as libc::c_long as uint64_t,
                            1584929449166988 as libc::c_long as uint64_t,
                            558148594103306 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1784525599998356 as libc::c_long as uint64_t,
                            1619698033617383 as libc::c_long as uint64_t,
                            2097300287550715 as libc::c_long as uint64_t,
                            258265458103756 as libc::c_long as uint64_t,
                            1905684794832758 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1288941072872766 as libc::c_long as uint64_t,
                            931787902039402 as libc::c_long as uint64_t,
                            190731008859042 as libc::c_long as uint64_t,
                            2006859954667190 as libc::c_long as uint64_t,
                            1005931482221702 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1465551264822703 as libc::c_long as uint64_t,
                            152905080555927 as libc::c_long as uint64_t,
                            680334307368453 as libc::c_long as uint64_t,
                            173227184634745 as libc::c_long as uint64_t,
                            666407097159852 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2111017076203943 as libc::c_long as uint64_t,
                            1378760485794347 as libc::c_long as uint64_t,
                            1248583954016456 as libc::c_long as uint64_t,
                            1352289194864422 as libc::c_long as uint64_t,
                            1895180776543896 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            171348223915638 as libc::c_long as uint64_t,
                            662766099800389 as libc::c_long as uint64_t,
                            462338943760497 as libc::c_long as uint64_t,
                            466917763340314 as libc::c_long as uint64_t,
                            656911292869115 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            488623681976577 as libc::c_long as uint64_t,
                            866497561541722 as libc::c_long as uint64_t,
                            1708105560937768 as libc::c_long as uint64_t,
                            1673781214218839 as libc::c_long as uint64_t,
                            1506146329818807 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            160425464456957 as libc::c_long as uint64_t,
                            950394373239689 as libc::c_long as uint64_t,
                            430497123340934 as libc::c_long as uint64_t,
                            711676555398832 as libc::c_long as uint64_t,
                            320964687779005 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            988979367990485 as libc::c_long as uint64_t,
                            1359729327576302 as libc::c_long as uint64_t,
                            1301834257246029 as libc::c_long as uint64_t,
                            294141160829308 as libc::c_long as uint64_t,
                            29348272277475 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1434382743317910 as libc::c_long as uint64_t,
                            100082049942065 as libc::c_long as uint64_t,
                            221102347892623 as libc::c_long as uint64_t,
                            186982837860588 as libc::c_long as uint64_t,
                            1305765053501834 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            2205916462268190 as libc::c_long as uint64_t,
                            499863829790820 as libc::c_long as uint64_t,
                            961960554686616 as libc::c_long as uint64_t,
                            158062762756985 as libc::c_long as uint64_t,
                            1841471168298305 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1191737341426592 as libc::c_long as uint64_t,
                            1847042034978363 as libc::c_long as uint64_t,
                            1382213545049056 as libc::c_long as uint64_t,
                            1039952395710448 as libc::c_long as uint64_t,
                            788812858896859 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1346965964571152 as libc::c_long as uint64_t,
                            1291881610839830 as libc::c_long as uint64_t,
                            2142916164336056 as libc::c_long as uint64_t,
                            786821641205979 as libc::c_long as uint64_t,
                            1571709146321039 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            787164375951248 as libc::c_long as uint64_t,
                            202869205373189 as libc::c_long as uint64_t,
                            1356590421032140 as libc::c_long as uint64_t,
                            1431233331032510 as libc::c_long as uint64_t,
                            786341368775957 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            492448143532951 as libc::c_long as uint64_t,
                            304105152670757 as libc::c_long as uint64_t,
                            1761767168301056 as libc::c_long as uint64_t,
                            233782684697790 as libc::c_long as uint64_t,
                            1981295323106089 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            665807507761866 as libc::c_long as uint64_t,
                            1343384868355425 as libc::c_long as uint64_t,
                            895831046139653 as libc::c_long as uint64_t,
                            439338948736892 as libc::c_long as uint64_t,
                            1986828765695105 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            756096210874553 as libc::c_long as uint64_t,
                            1721699973539149 as libc::c_long as uint64_t,
                            258765301727885 as libc::c_long as uint64_t,
                            1390588532210645 as libc::c_long as uint64_t,
                            1212530909934781 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            852891097972275 as libc::c_long as uint64_t,
                            1816988871354562 as libc::c_long as uint64_t,
                            1543772755726524 as libc::c_long as uint64_t,
                            1174710635522444 as libc::c_long as uint64_t,
                            202129090724628 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1205281565824323 as libc::c_long as uint64_t,
                            22430498399418 as libc::c_long as uint64_t,
                            992947814485516 as libc::c_long as uint64_t,
                            1392458699738672 as libc::c_long as uint64_t,
                            688441466734558 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
        {
            let mut init = ge_precomp {
                yplusx: {
                    let mut init = fe_loose {
                        v: [
                            1050627428414972 as libc::c_long as uint64_t,
                            1955849529137135 as libc::c_long as uint64_t,
                            2171162376368357 as libc::c_long as uint64_t,
                            91745868298214 as libc::c_long as uint64_t,
                            447733118757826 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                yminusx: {
                    let mut init = fe_loose {
                        v: [
                            1287181461435438 as libc::c_long as uint64_t,
                            622722465530711 as libc::c_long as uint64_t,
                            880952150571872 as libc::c_long as uint64_t,
                            741035693459198 as libc::c_long as uint64_t,
                            311565274989772 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
                xy2d: {
                    let mut init = fe_loose {
                        v: [
                            1003649078149734 as libc::c_long as uint64_t,
                            545233927396469 as libc::c_long as uint64_t,
                            1849786171789880 as libc::c_long as uint64_t,
                            1318943684880434 as libc::c_long as uint64_t,
                            280345687170552 as libc::c_long as uint64_t,
                        ],
                    };
                    init
                },
            };
            init
        },
    ],
];
static mut k25519Bi: [ge_precomp; 8] = [
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        1288382639258501 as libc::c_long as uint64_t,
                        245678601348599 as libc::c_long as uint64_t,
                        269427782077623 as libc::c_long as uint64_t,
                        1462984067271730 as libc::c_long as uint64_t,
                        137412439391563 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        62697248952638 as libc::c_long as uint64_t,
                        204681361388450 as libc::c_long as uint64_t,
                        631292143396476 as libc::c_long as uint64_t,
                        338455783676468 as libc::c_long as uint64_t,
                        1213667448819585 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        301289933810280 as libc::c_long as uint64_t,
                        1259582250014073 as libc::c_long as uint64_t,
                        1422107436869536 as libc::c_long as uint64_t,
                        796239922652654 as libc::c_long as uint64_t,
                        1953934009299142 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        1601611775252272 as libc::c_long as uint64_t,
                        1720807796594148 as libc::c_long as uint64_t,
                        1132070835939856 as libc::c_long as uint64_t,
                        1260455018889551 as libc::c_long as uint64_t,
                        2147779492816911 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        316559037616741 as libc::c_long as uint64_t,
                        2177824224946892 as libc::c_long as uint64_t,
                        1459442586438991 as libc::c_long as uint64_t,
                        1461528397712656 as libc::c_long as uint64_t,
                        751590696113597 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        1850748884277385 as libc::c_long as uint64_t,
                        1200145853858453 as libc::c_long as uint64_t,
                        1068094770532492 as libc::c_long as uint64_t,
                        672251375690438 as libc::c_long as uint64_t,
                        1586055907191707 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        769950342298419 as libc::c_long as uint64_t,
                        132954430919746 as libc::c_long as uint64_t,
                        844085933195555 as libc::c_long as uint64_t,
                        974092374476333 as libc::c_long as uint64_t,
                        726076285546016 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        425251763115706 as libc::c_long as uint64_t,
                        608463272472562 as libc::c_long as uint64_t,
                        442562545713235 as libc::c_long as uint64_t,
                        837766094556764 as libc::c_long as uint64_t,
                        374555092627893 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        1086255230780037 as libc::c_long as uint64_t,
                        274979815921559 as libc::c_long as uint64_t,
                        1960002765731872 as libc::c_long as uint64_t,
                        929474102396301 as libc::c_long as uint64_t,
                        1190409889297339 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        665000864555967 as libc::c_long as uint64_t,
                        2065379846933859 as libc::c_long as uint64_t,
                        370231110385876 as libc::c_long as uint64_t,
                        350988370788628 as libc::c_long as uint64_t,
                        1233371373142985 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        2019367628972465 as libc::c_long as uint64_t,
                        676711900706637 as libc::c_long as uint64_t,
                        110710997811333 as libc::c_long as uint64_t,
                        1108646842542025 as libc::c_long as uint64_t,
                        517791959672113 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        965130719900578 as libc::c_long as uint64_t,
                        247011430587952 as libc::c_long as uint64_t,
                        526356006571389 as libc::c_long as uint64_t,
                        91986625355052 as libc::c_long as uint64_t,
                        2157223321444601 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        1802695059465007 as libc::c_long as uint64_t,
                        1664899123557221 as libc::c_long as uint64_t,
                        593559490740857 as libc::c_long as uint64_t,
                        2160434469266659 as libc::c_long as uint64_t,
                        927570450755031 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        1725674970513508 as libc::c_long as uint64_t,
                        1933645953859181 as libc::c_long as uint64_t,
                        1542344539275782 as libc::c_long as uint64_t,
                        1767788773573747 as libc::c_long as uint64_t,
                        1297447965928905 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        1381809363726107 as libc::c_long as uint64_t,
                        1430341051343062 as libc::c_long as uint64_t,
                        2061843536018959 as libc::c_long as uint64_t,
                        1551778050872521 as libc::c_long as uint64_t,
                        2036394857967624 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        1970894096313054 as libc::c_long as uint64_t,
                        528066325833207 as libc::c_long as uint64_t,
                        1619374932191227 as libc::c_long as uint64_t,
                        2207306624415883 as libc::c_long as uint64_t,
                        1169170329061080 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        2070390218572616 as libc::c_long as uint64_t,
                        1458919061857835 as libc::c_long as uint64_t,
                        624171843017421 as libc::c_long as uint64_t,
                        1055332792707765 as libc::c_long as uint64_t,
                        433987520732508 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        893653801273833 as libc::c_long as uint64_t,
                        1168026499324677 as libc::c_long as uint64_t,
                        1242553501121234 as libc::c_long as uint64_t,
                        1306366254304474 as libc::c_long as uint64_t,
                        1086752658510815 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        213454002618221 as libc::c_long as uint64_t,
                        939771523987438 as libc::c_long as uint64_t,
                        1159882208056014 as libc::c_long as uint64_t,
                        317388369627517 as libc::c_long as uint64_t,
                        621213314200687 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        1971678598905747 as libc::c_long as uint64_t,
                        338026507889165 as libc::c_long as uint64_t,
                        762398079972271 as libc::c_long as uint64_t,
                        655096486107477 as libc::c_long as uint64_t,
                        42299032696322 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        177130678690680 as libc::c_long as uint64_t,
                        1754759263300204 as libc::c_long as uint64_t,
                        1864311296286618 as libc::c_long as uint64_t,
                        1180675631479880 as libc::c_long as uint64_t,
                        1292726903152791 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        1913163449625248 as libc::c_long as uint64_t,
                        460779200291993 as libc::c_long as uint64_t,
                        2193883288642314 as libc::c_long as uint64_t,
                        1008900146920800 as libc::c_long as uint64_t,
                        1721983679009502 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        1070401523076875 as libc::c_long as uint64_t,
                        1272492007800961 as libc::c_long as uint64_t,
                        1910153608563310 as libc::c_long as uint64_t,
                        2075579521696771 as libc::c_long as uint64_t,
                        1191169788841221 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        692896803108118 as libc::c_long as uint64_t,
                        500174642072499 as libc::c_long as uint64_t,
                        2068223309439677 as libc::c_long as uint64_t,
                        1162190621851337 as libc::c_long as uint64_t,
                        1426986007309901 as libc::c_long as uint64_t,
                    ],
                };
                init
            },
        };
        init
    },
];
#[inline]
unsafe extern "C" fn fiat_25519_value_barrier_u64(mut a: uint64_t) -> uint64_t {
    asm!("", inlateout(reg) a, options(preserves_flags, pure, readonly, att_syntax));
    return a;
}
#[inline]
unsafe extern "C" fn fiat_25519_addcarryx_u51(
    mut out1: *mut uint64_t,
    mut out2: *mut fiat_25519_uint1,
    mut arg1: fiat_25519_uint1,
    mut arg2: uint64_t,
    mut arg3: uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: fiat_25519_uint1 = 0;
    x1 = (arg1 as uint64_t).wrapping_add(arg2).wrapping_add(arg3);
    x2 = x1 & 0x7ffffffffffff as libc::c_ulong;
    x3 = (x1 >> 51 as libc::c_int) as fiat_25519_uint1;
    *out1 = x2;
    *out2 = x3;
}
#[inline]
unsafe extern "C" fn fiat_25519_subborrowx_u51(
    mut out1: *mut uint64_t,
    mut out2: *mut fiat_25519_uint1,
    mut arg1: fiat_25519_uint1,
    mut arg2: uint64_t,
    mut arg3: uint64_t,
) {
    let mut x1: int64_t = 0;
    let mut x2: fiat_25519_int1 = 0;
    let mut x3: uint64_t = 0;
    x1 = arg2.wrapping_sub(arg1 as int64_t as uint64_t) as int64_t - arg3 as int64_t;
    x2 = (x1 >> 51 as libc::c_int) as fiat_25519_int1;
    x3 = x1 as libc::c_ulong & 0x7ffffffffffff as libc::c_ulong;
    *out1 = x3;
    *out2 = (0 as libc::c_int - x2 as libc::c_int) as fiat_25519_uint1;
}
#[inline]
unsafe extern "C" fn fiat_25519_cmovznz_u64(
    mut out1: *mut uint64_t,
    mut arg1: fiat_25519_uint1,
    mut arg2: uint64_t,
    mut arg3: uint64_t,
) {
    let mut x1: fiat_25519_uint1 = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    x1 = (arg1 != 0) as libc::c_int as fiat_25519_uint1;
    x2 = (0 as libc::c_int - x1 as libc::c_int) as fiat_25519_int1 as libc::c_ulong
        & 0xffffffffffffffff as libc::c_ulong;
    x3 = fiat_25519_value_barrier_u64(x2) & arg3
        | fiat_25519_value_barrier_u64(!x2) & arg2;
    *out1 = x3;
}
#[inline]
unsafe extern "C" fn fiat_25519_carry_mul(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
    mut arg2: *const uint64_t,
) {
    let mut x1: fiat_25519_uint128 = 0;
    let mut x2: fiat_25519_uint128 = 0;
    let mut x3: fiat_25519_uint128 = 0;
    let mut x4: fiat_25519_uint128 = 0;
    let mut x5: fiat_25519_uint128 = 0;
    let mut x6: fiat_25519_uint128 = 0;
    let mut x7: fiat_25519_uint128 = 0;
    let mut x8: fiat_25519_uint128 = 0;
    let mut x9: fiat_25519_uint128 = 0;
    let mut x10: fiat_25519_uint128 = 0;
    let mut x11: fiat_25519_uint128 = 0;
    let mut x12: fiat_25519_uint128 = 0;
    let mut x13: fiat_25519_uint128 = 0;
    let mut x14: fiat_25519_uint128 = 0;
    let mut x15: fiat_25519_uint128 = 0;
    let mut x16: fiat_25519_uint128 = 0;
    let mut x17: fiat_25519_uint128 = 0;
    let mut x18: fiat_25519_uint128 = 0;
    let mut x19: fiat_25519_uint128 = 0;
    let mut x20: fiat_25519_uint128 = 0;
    let mut x21: fiat_25519_uint128 = 0;
    let mut x22: fiat_25519_uint128 = 0;
    let mut x23: fiat_25519_uint128 = 0;
    let mut x24: fiat_25519_uint128 = 0;
    let mut x25: fiat_25519_uint128 = 0;
    let mut x26: fiat_25519_uint128 = 0;
    let mut x27: uint64_t = 0;
    let mut x28: uint64_t = 0;
    let mut x29: fiat_25519_uint128 = 0;
    let mut x30: fiat_25519_uint128 = 0;
    let mut x31: fiat_25519_uint128 = 0;
    let mut x32: fiat_25519_uint128 = 0;
    let mut x33: fiat_25519_uint128 = 0;
    let mut x34: uint64_t = 0;
    let mut x35: uint64_t = 0;
    let mut x36: fiat_25519_uint128 = 0;
    let mut x37: uint64_t = 0;
    let mut x38: uint64_t = 0;
    let mut x39: fiat_25519_uint128 = 0;
    let mut x40: uint64_t = 0;
    let mut x41: uint64_t = 0;
    let mut x42: fiat_25519_uint128 = 0;
    let mut x43: uint64_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: uint64_t = 0;
    let mut x46: uint64_t = 0;
    let mut x47: uint64_t = 0;
    let mut x48: uint64_t = 0;
    let mut x49: uint64_t = 0;
    let mut x50: fiat_25519_uint1 = 0;
    let mut x51: uint64_t = 0;
    let mut x52: uint64_t = 0;
    x1 = *arg1.offset(4 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(4 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x2 = *arg1.offset(4 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(3 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x3 = *arg1.offset(4 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(2 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x4 = *arg1.offset(4 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(1 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x5 = *arg1.offset(3 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(4 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x6 = *arg1.offset(3 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(3 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x7 = *arg1.offset(3 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(2 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x8 = *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(4 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x9 = *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(3 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x10 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * (*arg2.offset(4 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t)
            as fiat_25519_uint128;
    x11 = *arg1.offset(4 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(0 as libc::c_int as isize) as fiat_25519_uint128;
    x12 = *arg1.offset(3 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(1 as libc::c_int as isize) as fiat_25519_uint128;
    x13 = *arg1.offset(3 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(0 as libc::c_int as isize) as fiat_25519_uint128;
    x14 = *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(2 as libc::c_int as isize) as fiat_25519_uint128;
    x15 = *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(1 as libc::c_int as isize) as fiat_25519_uint128;
    x16 = *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(0 as libc::c_int as isize) as fiat_25519_uint128;
    x17 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(3 as libc::c_int as isize) as fiat_25519_uint128;
    x18 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(2 as libc::c_int as isize) as fiat_25519_uint128;
    x19 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(1 as libc::c_int as isize) as fiat_25519_uint128;
    x20 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(0 as libc::c_int as isize) as fiat_25519_uint128;
    x21 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(4 as libc::c_int as isize) as fiat_25519_uint128;
    x22 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(3 as libc::c_int as isize) as fiat_25519_uint128;
    x23 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(2 as libc::c_int as isize) as fiat_25519_uint128;
    x24 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(1 as libc::c_int as isize) as fiat_25519_uint128;
    x25 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * *arg2.offset(0 as libc::c_int as isize) as fiat_25519_uint128;
    x26 = x25.wrapping_add(x10.wrapping_add(x9.wrapping_add(x7.wrapping_add(x4))));
    x27 = (x26 >> 51 as libc::c_int) as uint64_t;
    x28 = (x26 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x29 = x21.wrapping_add(x17.wrapping_add(x14.wrapping_add(x12.wrapping_add(x11))));
    x30 = x22.wrapping_add(x18.wrapping_add(x15.wrapping_add(x13.wrapping_add(x1))));
    x31 = x23.wrapping_add(x19.wrapping_add(x16.wrapping_add(x5.wrapping_add(x2))));
    x32 = x24.wrapping_add(x20.wrapping_add(x8.wrapping_add(x6.wrapping_add(x3))));
    x33 = (x27 as fiat_25519_uint128).wrapping_add(x32);
    x34 = (x33 >> 51 as libc::c_int) as uint64_t;
    x35 = (x33 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x36 = (x34 as fiat_25519_uint128).wrapping_add(x31);
    x37 = (x36 >> 51 as libc::c_int) as uint64_t;
    x38 = (x36 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x39 = (x37 as fiat_25519_uint128).wrapping_add(x30);
    x40 = (x39 >> 51 as libc::c_int) as uint64_t;
    x41 = (x39 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x42 = (x40 as fiat_25519_uint128).wrapping_add(x29);
    x43 = (x42 >> 51 as libc::c_int) as uint64_t;
    x44 = (x42 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x45 = x43 * 0x13 as libc::c_int as uint64_t;
    x46 = x28.wrapping_add(x45);
    x47 = x46 >> 51 as libc::c_int;
    x48 = x46 & 0x7ffffffffffff as libc::c_ulong;
    x49 = x47.wrapping_add(x35);
    x50 = (x49 >> 51 as libc::c_int) as fiat_25519_uint1;
    x51 = x49 & 0x7ffffffffffff as libc::c_ulong;
    x52 = (x50 as uint64_t).wrapping_add(x38);
    *out1.offset(0 as libc::c_int as isize) = x48;
    *out1.offset(1 as libc::c_int as isize) = x51;
    *out1.offset(2 as libc::c_int as isize) = x52;
    *out1.offset(3 as libc::c_int as isize) = x41;
    *out1.offset(4 as libc::c_int as isize) = x44;
}
#[inline]
unsafe extern "C" fn fiat_25519_carry_square(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: uint64_t = 0;
    let mut x9: fiat_25519_uint128 = 0;
    let mut x10: fiat_25519_uint128 = 0;
    let mut x11: fiat_25519_uint128 = 0;
    let mut x12: fiat_25519_uint128 = 0;
    let mut x13: fiat_25519_uint128 = 0;
    let mut x14: fiat_25519_uint128 = 0;
    let mut x15: fiat_25519_uint128 = 0;
    let mut x16: fiat_25519_uint128 = 0;
    let mut x17: fiat_25519_uint128 = 0;
    let mut x18: fiat_25519_uint128 = 0;
    let mut x19: fiat_25519_uint128 = 0;
    let mut x20: fiat_25519_uint128 = 0;
    let mut x21: fiat_25519_uint128 = 0;
    let mut x22: fiat_25519_uint128 = 0;
    let mut x23: fiat_25519_uint128 = 0;
    let mut x24: fiat_25519_uint128 = 0;
    let mut x25: uint64_t = 0;
    let mut x26: uint64_t = 0;
    let mut x27: fiat_25519_uint128 = 0;
    let mut x28: fiat_25519_uint128 = 0;
    let mut x29: fiat_25519_uint128 = 0;
    let mut x30: fiat_25519_uint128 = 0;
    let mut x31: fiat_25519_uint128 = 0;
    let mut x32: uint64_t = 0;
    let mut x33: uint64_t = 0;
    let mut x34: fiat_25519_uint128 = 0;
    let mut x35: uint64_t = 0;
    let mut x36: uint64_t = 0;
    let mut x37: fiat_25519_uint128 = 0;
    let mut x38: uint64_t = 0;
    let mut x39: uint64_t = 0;
    let mut x40: fiat_25519_uint128 = 0;
    let mut x41: uint64_t = 0;
    let mut x42: uint64_t = 0;
    let mut x43: uint64_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: uint64_t = 0;
    let mut x46: uint64_t = 0;
    let mut x47: uint64_t = 0;
    let mut x48: fiat_25519_uint1 = 0;
    let mut x49: uint64_t = 0;
    let mut x50: uint64_t = 0;
    x1 = *arg1.offset(4 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t;
    x2 = x1 * 0x2 as libc::c_int as uint64_t;
    x3 = *arg1.offset(4 as libc::c_int as isize) * 0x2 as libc::c_int as uint64_t;
    x4 = *arg1.offset(3 as libc::c_int as isize) * 0x13 as libc::c_int as uint64_t;
    x5 = x4 * 0x2 as libc::c_int as uint64_t;
    x6 = *arg1.offset(3 as libc::c_int as isize) * 0x2 as libc::c_int as uint64_t;
    x7 = *arg1.offset(2 as libc::c_int as isize) * 0x2 as libc::c_int as uint64_t;
    x8 = *arg1.offset(1 as libc::c_int as isize) * 0x2 as libc::c_int as uint64_t;
    x9 = *arg1.offset(4 as libc::c_int as isize) as fiat_25519_uint128
        * x1 as fiat_25519_uint128;
    x10 = *arg1.offset(3 as libc::c_int as isize) as fiat_25519_uint128
        * x2 as fiat_25519_uint128;
    x11 = *arg1.offset(3 as libc::c_int as isize) as fiat_25519_uint128
        * x4 as fiat_25519_uint128;
    x12 = *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128
        * x2 as fiat_25519_uint128;
    x13 = *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128
        * x5 as fiat_25519_uint128;
    x14 = *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128
        * *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128;
    x15 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * x2 as fiat_25519_uint128;
    x16 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * x6 as fiat_25519_uint128;
    x17 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * x7 as fiat_25519_uint128;
    x18 = *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128
        * *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128;
    x19 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * x3 as fiat_25519_uint128;
    x20 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * x6 as fiat_25519_uint128;
    x21 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * x7 as fiat_25519_uint128;
    x22 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * x8 as fiat_25519_uint128;
    x23 = *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128
        * *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128;
    x24 = x23.wrapping_add(x15.wrapping_add(x13));
    x25 = (x24 >> 51 as libc::c_int) as uint64_t;
    x26 = (x24 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x27 = x19.wrapping_add(x16.wrapping_add(x14));
    x28 = x20.wrapping_add(x17.wrapping_add(x9));
    x29 = x21.wrapping_add(x18.wrapping_add(x10));
    x30 = x22.wrapping_add(x12.wrapping_add(x11));
    x31 = (x25 as fiat_25519_uint128).wrapping_add(x30);
    x32 = (x31 >> 51 as libc::c_int) as uint64_t;
    x33 = (x31 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x34 = (x32 as fiat_25519_uint128).wrapping_add(x29);
    x35 = (x34 >> 51 as libc::c_int) as uint64_t;
    x36 = (x34 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x37 = (x35 as fiat_25519_uint128).wrapping_add(x28);
    x38 = (x37 >> 51 as libc::c_int) as uint64_t;
    x39 = (x37 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x40 = (x38 as fiat_25519_uint128).wrapping_add(x27);
    x41 = (x40 >> 51 as libc::c_int) as uint64_t;
    x42 = (x40 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x43 = x41 * 0x13 as libc::c_int as uint64_t;
    x44 = x26.wrapping_add(x43);
    x45 = x44 >> 51 as libc::c_int;
    x46 = x44 & 0x7ffffffffffff as libc::c_ulong;
    x47 = x45.wrapping_add(x33);
    x48 = (x47 >> 51 as libc::c_int) as fiat_25519_uint1;
    x49 = x47 & 0x7ffffffffffff as libc::c_ulong;
    x50 = (x48 as uint64_t).wrapping_add(x36);
    *out1.offset(0 as libc::c_int as isize) = x46;
    *out1.offset(1 as libc::c_int as isize) = x49;
    *out1.offset(2 as libc::c_int as isize) = x50;
    *out1.offset(3 as libc::c_int as isize) = x39;
    *out1.offset(4 as libc::c_int as isize) = x42;
}
#[inline]
unsafe extern "C" fn fiat_25519_carry(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: uint64_t = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: uint64_t = 0;
    let mut x12: uint64_t = 0;
    x1 = *arg1.offset(0 as libc::c_int as isize);
    x2 = (x1 >> 51 as libc::c_int).wrapping_add(*arg1.offset(1 as libc::c_int as isize));
    x3 = (x2 >> 51 as libc::c_int).wrapping_add(*arg1.offset(2 as libc::c_int as isize));
    x4 = (x3 >> 51 as libc::c_int).wrapping_add(*arg1.offset(3 as libc::c_int as isize));
    x5 = (x4 >> 51 as libc::c_int).wrapping_add(*arg1.offset(4 as libc::c_int as isize));
    x6 = (x1 & 0x7ffffffffffff as libc::c_ulong)
        .wrapping_add((x5 >> 51 as libc::c_int) * 0x13 as libc::c_int as uint64_t);
    x7 = ((x6 >> 51 as libc::c_int) as fiat_25519_uint1 as libc::c_ulong)
        .wrapping_add(x2 & 0x7ffffffffffff as libc::c_ulong);
    x8 = x6 & 0x7ffffffffffff as libc::c_ulong;
    x9 = x7 & 0x7ffffffffffff as libc::c_ulong;
    x10 = ((x7 >> 51 as libc::c_int) as fiat_25519_uint1 as libc::c_ulong)
        .wrapping_add(x3 & 0x7ffffffffffff as libc::c_ulong);
    x11 = x4 & 0x7ffffffffffff as libc::c_ulong;
    x12 = x5 & 0x7ffffffffffff as libc::c_ulong;
    *out1.offset(0 as libc::c_int as isize) = x8;
    *out1.offset(1 as libc::c_int as isize) = x9;
    *out1.offset(2 as libc::c_int as isize) = x10;
    *out1.offset(3 as libc::c_int as isize) = x11;
    *out1.offset(4 as libc::c_int as isize) = x12;
}
#[inline]
unsafe extern "C" fn fiat_25519_add(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
    mut arg2: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    x1 = (*arg1.offset(0 as libc::c_int as isize))
        .wrapping_add(*arg2.offset(0 as libc::c_int as isize));
    x2 = (*arg1.offset(1 as libc::c_int as isize))
        .wrapping_add(*arg2.offset(1 as libc::c_int as isize));
    x3 = (*arg1.offset(2 as libc::c_int as isize))
        .wrapping_add(*arg2.offset(2 as libc::c_int as isize));
    x4 = (*arg1.offset(3 as libc::c_int as isize))
        .wrapping_add(*arg2.offset(3 as libc::c_int as isize));
    x5 = (*arg1.offset(4 as libc::c_int as isize))
        .wrapping_add(*arg2.offset(4 as libc::c_int as isize));
    *out1.offset(0 as libc::c_int as isize) = x1;
    *out1.offset(1 as libc::c_int as isize) = x2;
    *out1.offset(2 as libc::c_int as isize) = x3;
    *out1.offset(3 as libc::c_int as isize) = x4;
    *out1.offset(4 as libc::c_int as isize) = x5;
}
#[inline]
unsafe extern "C" fn fiat_25519_sub(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
    mut arg2: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    x1 = (0xfffffffffffda as libc::c_ulong)
        .wrapping_add(*arg1.offset(0 as libc::c_int as isize))
        .wrapping_sub(*arg2.offset(0 as libc::c_int as isize));
    x2 = (0xffffffffffffe as libc::c_ulong)
        .wrapping_add(*arg1.offset(1 as libc::c_int as isize))
        .wrapping_sub(*arg2.offset(1 as libc::c_int as isize));
    x3 = (0xffffffffffffe as libc::c_ulong)
        .wrapping_add(*arg1.offset(2 as libc::c_int as isize))
        .wrapping_sub(*arg2.offset(2 as libc::c_int as isize));
    x4 = (0xffffffffffffe as libc::c_ulong)
        .wrapping_add(*arg1.offset(3 as libc::c_int as isize))
        .wrapping_sub(*arg2.offset(3 as libc::c_int as isize));
    x5 = (0xffffffffffffe as libc::c_ulong)
        .wrapping_add(*arg1.offset(4 as libc::c_int as isize))
        .wrapping_sub(*arg2.offset(4 as libc::c_int as isize));
    *out1.offset(0 as libc::c_int as isize) = x1;
    *out1.offset(1 as libc::c_int as isize) = x2;
    *out1.offset(2 as libc::c_int as isize) = x3;
    *out1.offset(3 as libc::c_int as isize) = x4;
    *out1.offset(4 as libc::c_int as isize) = x5;
}
#[inline]
unsafe extern "C" fn fiat_25519_opp(mut out1: *mut uint64_t, mut arg1: *const uint64_t) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    x1 = (0xfffffffffffda as libc::c_ulong)
        .wrapping_sub(*arg1.offset(0 as libc::c_int as isize));
    x2 = (0xffffffffffffe as libc::c_ulong)
        .wrapping_sub(*arg1.offset(1 as libc::c_int as isize));
    x3 = (0xffffffffffffe as libc::c_ulong)
        .wrapping_sub(*arg1.offset(2 as libc::c_int as isize));
    x4 = (0xffffffffffffe as libc::c_ulong)
        .wrapping_sub(*arg1.offset(3 as libc::c_int as isize));
    x5 = (0xffffffffffffe as libc::c_ulong)
        .wrapping_sub(*arg1.offset(4 as libc::c_int as isize));
    *out1.offset(0 as libc::c_int as isize) = x1;
    *out1.offset(1 as libc::c_int as isize) = x2;
    *out1.offset(2 as libc::c_int as isize) = x3;
    *out1.offset(3 as libc::c_int as isize) = x4;
    *out1.offset(4 as libc::c_int as isize) = x5;
}
#[inline]
unsafe extern "C" fn fiat_25519_selectznz(
    mut out1: *mut uint64_t,
    mut arg1: fiat_25519_uint1,
    mut arg2: *const uint64_t,
    mut arg3: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    fiat_25519_cmovznz_u64(
        &mut x1,
        arg1,
        *arg2.offset(0 as libc::c_int as isize),
        *arg3.offset(0 as libc::c_int as isize),
    );
    fiat_25519_cmovznz_u64(
        &mut x2,
        arg1,
        *arg2.offset(1 as libc::c_int as isize),
        *arg3.offset(1 as libc::c_int as isize),
    );
    fiat_25519_cmovznz_u64(
        &mut x3,
        arg1,
        *arg2.offset(2 as libc::c_int as isize),
        *arg3.offset(2 as libc::c_int as isize),
    );
    fiat_25519_cmovznz_u64(
        &mut x4,
        arg1,
        *arg2.offset(3 as libc::c_int as isize),
        *arg3.offset(3 as libc::c_int as isize),
    );
    fiat_25519_cmovznz_u64(
        &mut x5,
        arg1,
        *arg2.offset(4 as libc::c_int as isize),
        *arg3.offset(4 as libc::c_int as isize),
    );
    *out1.offset(0 as libc::c_int as isize) = x1;
    *out1.offset(1 as libc::c_int as isize) = x2;
    *out1.offset(2 as libc::c_int as isize) = x3;
    *out1.offset(3 as libc::c_int as isize) = x4;
    *out1.offset(4 as libc::c_int as isize) = x5;
}
#[inline]
unsafe extern "C" fn fiat_25519_to_bytes(
    mut out1: *mut uint8_t,
    mut arg1: *const uint64_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: fiat_25519_uint1 = 0;
    let mut x3: uint64_t = 0;
    let mut x4: fiat_25519_uint1 = 0;
    let mut x5: uint64_t = 0;
    let mut x6: fiat_25519_uint1 = 0;
    let mut x7: uint64_t = 0;
    let mut x8: fiat_25519_uint1 = 0;
    let mut x9: uint64_t = 0;
    let mut x10: fiat_25519_uint1 = 0;
    let mut x11: uint64_t = 0;
    let mut x12: uint64_t = 0;
    let mut x13: fiat_25519_uint1 = 0;
    let mut x14: uint64_t = 0;
    let mut x15: fiat_25519_uint1 = 0;
    let mut x16: uint64_t = 0;
    let mut x17: fiat_25519_uint1 = 0;
    let mut x18: uint64_t = 0;
    let mut x19: fiat_25519_uint1 = 0;
    let mut x20: uint64_t = 0;
    let mut x21: fiat_25519_uint1 = 0;
    let mut x22: uint64_t = 0;
    let mut x23: uint64_t = 0;
    let mut x24: uint64_t = 0;
    let mut x25: uint64_t = 0;
    let mut x26: uint8_t = 0;
    let mut x27: uint64_t = 0;
    let mut x28: uint8_t = 0;
    let mut x29: uint64_t = 0;
    let mut x30: uint8_t = 0;
    let mut x31: uint64_t = 0;
    let mut x32: uint8_t = 0;
    let mut x33: uint64_t = 0;
    let mut x34: uint8_t = 0;
    let mut x35: uint64_t = 0;
    let mut x36: uint8_t = 0;
    let mut x37: uint8_t = 0;
    let mut x38: uint64_t = 0;
    let mut x39: uint8_t = 0;
    let mut x40: uint64_t = 0;
    let mut x41: uint8_t = 0;
    let mut x42: uint64_t = 0;
    let mut x43: uint8_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: uint8_t = 0;
    let mut x46: uint64_t = 0;
    let mut x47: uint8_t = 0;
    let mut x48: uint64_t = 0;
    let mut x49: uint8_t = 0;
    let mut x50: uint8_t = 0;
    let mut x51: uint64_t = 0;
    let mut x52: uint8_t = 0;
    let mut x53: uint64_t = 0;
    let mut x54: uint8_t = 0;
    let mut x55: uint64_t = 0;
    let mut x56: uint8_t = 0;
    let mut x57: uint64_t = 0;
    let mut x58: uint8_t = 0;
    let mut x59: uint64_t = 0;
    let mut x60: uint8_t = 0;
    let mut x61: uint64_t = 0;
    let mut x62: uint8_t = 0;
    let mut x63: uint64_t = 0;
    let mut x64: uint8_t = 0;
    let mut x65: fiat_25519_uint1 = 0;
    let mut x66: uint64_t = 0;
    let mut x67: uint8_t = 0;
    let mut x68: uint64_t = 0;
    let mut x69: uint8_t = 0;
    let mut x70: uint64_t = 0;
    let mut x71: uint8_t = 0;
    let mut x72: uint64_t = 0;
    let mut x73: uint8_t = 0;
    let mut x74: uint64_t = 0;
    let mut x75: uint8_t = 0;
    let mut x76: uint64_t = 0;
    let mut x77: uint8_t = 0;
    let mut x78: uint8_t = 0;
    let mut x79: uint64_t = 0;
    let mut x80: uint8_t = 0;
    let mut x81: uint64_t = 0;
    let mut x82: uint8_t = 0;
    let mut x83: uint64_t = 0;
    let mut x84: uint8_t = 0;
    let mut x85: uint64_t = 0;
    let mut x86: uint8_t = 0;
    let mut x87: uint64_t = 0;
    let mut x88: uint8_t = 0;
    let mut x89: uint64_t = 0;
    let mut x90: uint8_t = 0;
    let mut x91: uint8_t = 0;
    fiat_25519_subborrowx_u51(
        &mut x1,
        &mut x2,
        0 as libc::c_int as fiat_25519_uint1,
        *arg1.offset(0 as libc::c_int as isize),
        0x7ffffffffffed as libc::c_ulong,
    );
    fiat_25519_subborrowx_u51(
        &mut x3,
        &mut x4,
        x2,
        *arg1.offset(1 as libc::c_int as isize),
        0x7ffffffffffff as libc::c_ulong,
    );
    fiat_25519_subborrowx_u51(
        &mut x5,
        &mut x6,
        x4,
        *arg1.offset(2 as libc::c_int as isize),
        0x7ffffffffffff as libc::c_ulong,
    );
    fiat_25519_subborrowx_u51(
        &mut x7,
        &mut x8,
        x6,
        *arg1.offset(3 as libc::c_int as isize),
        0x7ffffffffffff as libc::c_ulong,
    );
    fiat_25519_subborrowx_u51(
        &mut x9,
        &mut x10,
        x8,
        *arg1.offset(4 as libc::c_int as isize),
        0x7ffffffffffff as libc::c_ulong,
    );
    fiat_25519_cmovznz_u64(
        &mut x11,
        x10,
        0 as libc::c_int as uint64_t,
        0xffffffffffffffff as libc::c_ulong,
    );
    fiat_25519_addcarryx_u51(
        &mut x12,
        &mut x13,
        0 as libc::c_int as fiat_25519_uint1,
        x1,
        x11 & 0x7ffffffffffed as libc::c_ulong,
    );
    fiat_25519_addcarryx_u51(
        &mut x14,
        &mut x15,
        x13,
        x3,
        x11 & 0x7ffffffffffff as libc::c_ulong,
    );
    fiat_25519_addcarryx_u51(
        &mut x16,
        &mut x17,
        x15,
        x5,
        x11 & 0x7ffffffffffff as libc::c_ulong,
    );
    fiat_25519_addcarryx_u51(
        &mut x18,
        &mut x19,
        x17,
        x7,
        x11 & 0x7ffffffffffff as libc::c_ulong,
    );
    fiat_25519_addcarryx_u51(
        &mut x20,
        &mut x21,
        x19,
        x9,
        x11 & 0x7ffffffffffff as libc::c_ulong,
    );
    x22 = x20 << 4 as libc::c_int;
    x23 = x18 * 0x2 as libc::c_int as uint64_t;
    x24 = x16 << 6 as libc::c_int;
    x25 = x14 << 3 as libc::c_int;
    x26 = (x12 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x27 = x12 >> 8 as libc::c_int;
    x28 = (x27 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x29 = x27 >> 8 as libc::c_int;
    x30 = (x29 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x31 = x29 >> 8 as libc::c_int;
    x32 = (x31 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x33 = x31 >> 8 as libc::c_int;
    x34 = (x33 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x35 = x33 >> 8 as libc::c_int;
    x36 = (x35 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x37 = (x35 >> 8 as libc::c_int) as uint8_t;
    x38 = x25.wrapping_add(x37 as uint64_t);
    x39 = (x38 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x40 = x38 >> 8 as libc::c_int;
    x41 = (x40 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x42 = x40 >> 8 as libc::c_int;
    x43 = (x42 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x44 = x42 >> 8 as libc::c_int;
    x45 = (x44 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x46 = x44 >> 8 as libc::c_int;
    x47 = (x46 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x48 = x46 >> 8 as libc::c_int;
    x49 = (x48 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x50 = (x48 >> 8 as libc::c_int) as uint8_t;
    x51 = x24.wrapping_add(x50 as uint64_t);
    x52 = (x51 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x53 = x51 >> 8 as libc::c_int;
    x54 = (x53 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x55 = x53 >> 8 as libc::c_int;
    x56 = (x55 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x57 = x55 >> 8 as libc::c_int;
    x58 = (x57 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x59 = x57 >> 8 as libc::c_int;
    x60 = (x59 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x61 = x59 >> 8 as libc::c_int;
    x62 = (x61 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x63 = x61 >> 8 as libc::c_int;
    x64 = (x63 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x65 = (x63 >> 8 as libc::c_int) as fiat_25519_uint1;
    x66 = x23.wrapping_add(x65 as uint64_t);
    x67 = (x66 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x68 = x66 >> 8 as libc::c_int;
    x69 = (x68 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x70 = x68 >> 8 as libc::c_int;
    x71 = (x70 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x72 = x70 >> 8 as libc::c_int;
    x73 = (x72 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x74 = x72 >> 8 as libc::c_int;
    x75 = (x74 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x76 = x74 >> 8 as libc::c_int;
    x77 = (x76 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x78 = (x76 >> 8 as libc::c_int) as uint8_t;
    x79 = x22.wrapping_add(x78 as uint64_t);
    x80 = (x79 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x81 = x79 >> 8 as libc::c_int;
    x82 = (x81 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x83 = x81 >> 8 as libc::c_int;
    x84 = (x83 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x85 = x83 >> 8 as libc::c_int;
    x86 = (x85 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x87 = x85 >> 8 as libc::c_int;
    x88 = (x87 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x89 = x87 >> 8 as libc::c_int;
    x90 = (x89 & 0xff as libc::c_int as uint64_t) as uint8_t;
    x91 = (x89 >> 8 as libc::c_int) as uint8_t;
    *out1.offset(0 as libc::c_int as isize) = x26;
    *out1.offset(1 as libc::c_int as isize) = x28;
    *out1.offset(2 as libc::c_int as isize) = x30;
    *out1.offset(3 as libc::c_int as isize) = x32;
    *out1.offset(4 as libc::c_int as isize) = x34;
    *out1.offset(5 as libc::c_int as isize) = x36;
    *out1.offset(6 as libc::c_int as isize) = x39;
    *out1.offset(7 as libc::c_int as isize) = x41;
    *out1.offset(8 as libc::c_int as isize) = x43;
    *out1.offset(9 as libc::c_int as isize) = x45;
    *out1.offset(10 as libc::c_int as isize) = x47;
    *out1.offset(11 as libc::c_int as isize) = x49;
    *out1.offset(12 as libc::c_int as isize) = x52;
    *out1.offset(13 as libc::c_int as isize) = x54;
    *out1.offset(14 as libc::c_int as isize) = x56;
    *out1.offset(15 as libc::c_int as isize) = x58;
    *out1.offset(16 as libc::c_int as isize) = x60;
    *out1.offset(17 as libc::c_int as isize) = x62;
    *out1.offset(18 as libc::c_int as isize) = x64;
    *out1.offset(19 as libc::c_int as isize) = x67;
    *out1.offset(20 as libc::c_int as isize) = x69;
    *out1.offset(21 as libc::c_int as isize) = x71;
    *out1.offset(22 as libc::c_int as isize) = x73;
    *out1.offset(23 as libc::c_int as isize) = x75;
    *out1.offset(24 as libc::c_int as isize) = x77;
    *out1.offset(25 as libc::c_int as isize) = x80;
    *out1.offset(26 as libc::c_int as isize) = x82;
    *out1.offset(27 as libc::c_int as isize) = x84;
    *out1.offset(28 as libc::c_int as isize) = x86;
    *out1.offset(29 as libc::c_int as isize) = x88;
    *out1.offset(30 as libc::c_int as isize) = x90;
    *out1.offset(31 as libc::c_int as isize) = x91;
}
#[inline]
unsafe extern "C" fn fiat_25519_from_bytes(
    mut out1: *mut uint64_t,
    mut arg1: *const uint8_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: uint64_t = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: uint64_t = 0;
    let mut x12: uint64_t = 0;
    let mut x13: uint64_t = 0;
    let mut x14: uint64_t = 0;
    let mut x15: uint64_t = 0;
    let mut x16: uint64_t = 0;
    let mut x17: uint64_t = 0;
    let mut x18: uint64_t = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint64_t = 0;
    let mut x21: uint64_t = 0;
    let mut x22: uint64_t = 0;
    let mut x23: uint64_t = 0;
    let mut x24: uint64_t = 0;
    let mut x25: uint64_t = 0;
    let mut x26: uint64_t = 0;
    let mut x27: uint64_t = 0;
    let mut x28: uint64_t = 0;
    let mut x29: uint64_t = 0;
    let mut x30: uint64_t = 0;
    let mut x31: uint64_t = 0;
    let mut x32: uint8_t = 0;
    let mut x33: uint64_t = 0;
    let mut x34: uint64_t = 0;
    let mut x35: uint64_t = 0;
    let mut x36: uint64_t = 0;
    let mut x37: uint64_t = 0;
    let mut x38: uint64_t = 0;
    let mut x39: uint64_t = 0;
    let mut x40: uint8_t = 0;
    let mut x41: uint64_t = 0;
    let mut x42: uint64_t = 0;
    let mut x43: uint64_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: uint64_t = 0;
    let mut x46: uint64_t = 0;
    let mut x47: uint64_t = 0;
    let mut x48: uint8_t = 0;
    let mut x49: uint64_t = 0;
    let mut x50: uint64_t = 0;
    let mut x51: uint64_t = 0;
    let mut x52: uint64_t = 0;
    let mut x53: uint64_t = 0;
    let mut x54: uint64_t = 0;
    let mut x55: uint64_t = 0;
    let mut x56: uint64_t = 0;
    let mut x57: uint8_t = 0;
    let mut x58: uint64_t = 0;
    let mut x59: uint64_t = 0;
    let mut x60: uint64_t = 0;
    let mut x61: uint64_t = 0;
    let mut x62: uint64_t = 0;
    let mut x63: uint64_t = 0;
    let mut x64: uint64_t = 0;
    let mut x65: uint8_t = 0;
    let mut x66: uint64_t = 0;
    let mut x67: uint64_t = 0;
    let mut x68: uint64_t = 0;
    let mut x69: uint64_t = 0;
    let mut x70: uint64_t = 0;
    let mut x71: uint64_t = 0;
    x1 = (*arg1.offset(31 as libc::c_int as isize) as uint64_t) << 44 as libc::c_int;
    x2 = (*arg1.offset(30 as libc::c_int as isize) as uint64_t) << 36 as libc::c_int;
    x3 = (*arg1.offset(29 as libc::c_int as isize) as uint64_t) << 28 as libc::c_int;
    x4 = (*arg1.offset(28 as libc::c_int as isize) as uint64_t) << 20 as libc::c_int;
    x5 = (*arg1.offset(27 as libc::c_int as isize) as uint64_t) << 12 as libc::c_int;
    x6 = (*arg1.offset(26 as libc::c_int as isize) as uint64_t) << 4 as libc::c_int;
    x7 = (*arg1.offset(25 as libc::c_int as isize) as uint64_t) << 47 as libc::c_int;
    x8 = (*arg1.offset(24 as libc::c_int as isize) as uint64_t) << 39 as libc::c_int;
    x9 = (*arg1.offset(23 as libc::c_int as isize) as uint64_t) << 31 as libc::c_int;
    x10 = (*arg1.offset(22 as libc::c_int as isize) as uint64_t) << 23 as libc::c_int;
    x11 = (*arg1.offset(21 as libc::c_int as isize) as uint64_t) << 15 as libc::c_int;
    x12 = (*arg1.offset(20 as libc::c_int as isize) as uint64_t) << 7 as libc::c_int;
    x13 = (*arg1.offset(19 as libc::c_int as isize) as uint64_t) << 50 as libc::c_int;
    x14 = (*arg1.offset(18 as libc::c_int as isize) as uint64_t) << 42 as libc::c_int;
    x15 = (*arg1.offset(17 as libc::c_int as isize) as uint64_t) << 34 as libc::c_int;
    x16 = (*arg1.offset(16 as libc::c_int as isize) as uint64_t) << 26 as libc::c_int;
    x17 = (*arg1.offset(15 as libc::c_int as isize) as uint64_t) << 18 as libc::c_int;
    x18 = (*arg1.offset(14 as libc::c_int as isize) as uint64_t) << 10 as libc::c_int;
    x19 = (*arg1.offset(13 as libc::c_int as isize) as uint64_t) << 2 as libc::c_int;
    x20 = (*arg1.offset(12 as libc::c_int as isize) as uint64_t) << 45 as libc::c_int;
    x21 = (*arg1.offset(11 as libc::c_int as isize) as uint64_t) << 37 as libc::c_int;
    x22 = (*arg1.offset(10 as libc::c_int as isize) as uint64_t) << 29 as libc::c_int;
    x23 = (*arg1.offset(9 as libc::c_int as isize) as uint64_t) << 21 as libc::c_int;
    x24 = (*arg1.offset(8 as libc::c_int as isize) as uint64_t) << 13 as libc::c_int;
    x25 = (*arg1.offset(7 as libc::c_int as isize) as uint64_t) << 5 as libc::c_int;
    x26 = (*arg1.offset(6 as libc::c_int as isize) as uint64_t) << 48 as libc::c_int;
    x27 = (*arg1.offset(5 as libc::c_int as isize) as uint64_t) << 40 as libc::c_int;
    x28 = (*arg1.offset(4 as libc::c_int as isize) as uint64_t) << 32 as libc::c_int;
    x29 = (*arg1.offset(3 as libc::c_int as isize) as uint64_t) << 24 as libc::c_int;
    x30 = (*arg1.offset(2 as libc::c_int as isize) as uint64_t) << 16 as libc::c_int;
    x31 = (*arg1.offset(1 as libc::c_int as isize) as uint64_t) << 8 as libc::c_int;
    x32 = *arg1.offset(0 as libc::c_int as isize);
    x33 = x31.wrapping_add(x32 as uint64_t);
    x34 = x30.wrapping_add(x33);
    x35 = x29.wrapping_add(x34);
    x36 = x28.wrapping_add(x35);
    x37 = x27.wrapping_add(x36);
    x38 = x26.wrapping_add(x37);
    x39 = x38 & 0x7ffffffffffff as libc::c_ulong;
    x40 = (x38 >> 51 as libc::c_int) as uint8_t;
    x41 = x25.wrapping_add(x40 as uint64_t);
    x42 = x24.wrapping_add(x41);
    x43 = x23.wrapping_add(x42);
    x44 = x22.wrapping_add(x43);
    x45 = x21.wrapping_add(x44);
    x46 = x20.wrapping_add(x45);
    x47 = x46 & 0x7ffffffffffff as libc::c_ulong;
    x48 = (x46 >> 51 as libc::c_int) as uint8_t;
    x49 = x19.wrapping_add(x48 as uint64_t);
    x50 = x18.wrapping_add(x49);
    x51 = x17.wrapping_add(x50);
    x52 = x16.wrapping_add(x51);
    x53 = x15.wrapping_add(x52);
    x54 = x14.wrapping_add(x53);
    x55 = x13.wrapping_add(x54);
    x56 = x55 & 0x7ffffffffffff as libc::c_ulong;
    x57 = (x55 >> 51 as libc::c_int) as uint8_t;
    x58 = x12.wrapping_add(x57 as uint64_t);
    x59 = x11.wrapping_add(x58);
    x60 = x10.wrapping_add(x59);
    x61 = x9.wrapping_add(x60);
    x62 = x8.wrapping_add(x61);
    x63 = x7.wrapping_add(x62);
    x64 = x63 & 0x7ffffffffffff as libc::c_ulong;
    x65 = (x63 >> 51 as libc::c_int) as uint8_t;
    x66 = x6.wrapping_add(x65 as uint64_t);
    x67 = x5.wrapping_add(x66);
    x68 = x4.wrapping_add(x67);
    x69 = x3.wrapping_add(x68);
    x70 = x2.wrapping_add(x69);
    x71 = x1.wrapping_add(x70);
    *out1.offset(0 as libc::c_int as isize) = x39;
    *out1.offset(1 as libc::c_int as isize) = x47;
    *out1.offset(2 as libc::c_int as isize) = x56;
    *out1.offset(3 as libc::c_int as isize) = x64;
    *out1.offset(4 as libc::c_int as isize) = x71;
}
#[inline]
unsafe extern "C" fn fiat_25519_carry_scmul_121666(
    mut out1: *mut uint64_t,
    mut arg1: *const uint64_t,
) {
    let mut x1: fiat_25519_uint128 = 0;
    let mut x2: fiat_25519_uint128 = 0;
    let mut x3: fiat_25519_uint128 = 0;
    let mut x4: fiat_25519_uint128 = 0;
    let mut x5: fiat_25519_uint128 = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: fiat_25519_uint128 = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: fiat_25519_uint128 = 0;
    let mut x12: uint64_t = 0;
    let mut x13: uint64_t = 0;
    let mut x14: fiat_25519_uint128 = 0;
    let mut x15: uint64_t = 0;
    let mut x16: uint64_t = 0;
    let mut x17: fiat_25519_uint128 = 0;
    let mut x18: uint64_t = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint64_t = 0;
    let mut x21: uint64_t = 0;
    let mut x22: fiat_25519_uint1 = 0;
    let mut x23: uint64_t = 0;
    let mut x24: uint64_t = 0;
    let mut x25: fiat_25519_uint1 = 0;
    let mut x26: uint64_t = 0;
    let mut x27: uint64_t = 0;
    x1 = 0x1db42 as libc::c_uint as fiat_25519_uint128
        * *arg1.offset(4 as libc::c_int as isize) as fiat_25519_uint128;
    x2 = 0x1db42 as libc::c_uint as fiat_25519_uint128
        * *arg1.offset(3 as libc::c_int as isize) as fiat_25519_uint128;
    x3 = 0x1db42 as libc::c_uint as fiat_25519_uint128
        * *arg1.offset(2 as libc::c_int as isize) as fiat_25519_uint128;
    x4 = 0x1db42 as libc::c_uint as fiat_25519_uint128
        * *arg1.offset(1 as libc::c_int as isize) as fiat_25519_uint128;
    x5 = 0x1db42 as libc::c_uint as fiat_25519_uint128
        * *arg1.offset(0 as libc::c_int as isize) as fiat_25519_uint128;
    x6 = (x5 >> 51 as libc::c_int) as uint64_t;
    x7 = (x5 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x8 = (x6 as fiat_25519_uint128).wrapping_add(x4);
    x9 = (x8 >> 51 as libc::c_int) as uint64_t;
    x10 = (x8 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x11 = (x9 as fiat_25519_uint128).wrapping_add(x3);
    x12 = (x11 >> 51 as libc::c_int) as uint64_t;
    x13 = (x11 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x14 = (x12 as fiat_25519_uint128).wrapping_add(x2);
    x15 = (x14 >> 51 as libc::c_int) as uint64_t;
    x16 = (x14 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x17 = (x15 as fiat_25519_uint128).wrapping_add(x1);
    x18 = (x17 >> 51 as libc::c_int) as uint64_t;
    x19 = (x17 & 0x7ffffffffffff as libc::c_ulong as fiat_25519_uint128) as uint64_t;
    x20 = x18 * 0x13 as libc::c_int as uint64_t;
    x21 = x7.wrapping_add(x20);
    x22 = (x21 >> 51 as libc::c_int) as fiat_25519_uint1;
    x23 = x21 & 0x7ffffffffffff as libc::c_ulong;
    x24 = (x22 as uint64_t).wrapping_add(x10);
    x25 = (x24 >> 51 as libc::c_int) as fiat_25519_uint1;
    x26 = x24 & 0x7ffffffffffff as libc::c_ulong;
    x27 = (x25 as uint64_t).wrapping_add(x13);
    *out1.offset(0 as libc::c_int as isize) = x23;
    *out1.offset(1 as libc::c_int as isize) = x26;
    *out1.offset(2 as libc::c_int as isize) = x27;
    *out1.offset(3 as libc::c_int as isize) = x16;
    *out1.offset(4 as libc::c_int as isize) = x19;
}
unsafe extern "C" fn load_3(mut in_0: *const uint8_t) -> uint64_t {
    let mut result: uint64_t = 0;
    result = *in_0.offset(0 as libc::c_int as isize) as uint64_t;
    result |= (*in_0.offset(1 as libc::c_int as isize) as uint64_t) << 8 as libc::c_int;
    result |= (*in_0.offset(2 as libc::c_int as isize) as uint64_t) << 16 as libc::c_int;
    return result;
}
unsafe extern "C" fn load_4(mut in_0: *const uint8_t) -> uint64_t {
    let mut result: uint64_t = 0;
    result = *in_0.offset(0 as libc::c_int as isize) as uint64_t;
    result |= (*in_0.offset(1 as libc::c_int as isize) as uint64_t) << 8 as libc::c_int;
    result |= (*in_0.offset(2 as libc::c_int as isize) as uint64_t) << 16 as libc::c_int;
    result |= (*in_0.offset(3 as libc::c_int as isize) as uint64_t) << 24 as libc::c_int;
    return result;
}
unsafe extern "C" fn fe_frombytes_strict(mut h: *mut fe, mut s: *const uint8_t) {
    if constant_time_declassify_int(
        (*s.offset(31 as libc::c_int as isize) as libc::c_int & 0x80 as libc::c_int
            == 0 as libc::c_int) as libc::c_int,
    ) != 0
    {} else {
        __assert_fail(
            b"constant_time_declassify_int((s[31] & 0x80) == 0)\0" as *const u8
                as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                as *const u8 as *const libc::c_char,
            149 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 48],
                &[libc::c_char; 48],
            >(b"void fe_frombytes_strict(fe *, const uint8_t *)\0"))
                .as_ptr(),
        );
    }
    'c_14166: {
        if constant_time_declassify_int(
            (*s.offset(31 as libc::c_int as isize) as libc::c_int & 0x80 as libc::c_int
                == 0 as libc::c_int) as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int((s[31] & 0x80) == 0)\0" as *const u8
                    as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                149 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"void fe_frombytes_strict(fe *, const uint8_t *)\0"))
                    .as_ptr(),
            );
        }
    };
    fiat_25519_from_bytes(((*h).v).as_mut_ptr(), s);
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*h).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                151 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"void fe_frombytes_strict(fe *, const uint8_t *)\0"))
                    .as_ptr(),
            );
        }
        'c_13143: {
            if constant_time_declassify_int(
                ((*h).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    151 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 48],
                        &[libc::c_char; 48],
                    >(b"void fe_frombytes_strict(fe *, const uint8_t *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
}
unsafe extern "C" fn fe_frombytes(mut h: *mut fe, mut s: *const uint8_t) {
    let mut s_copy: [uint8_t; 32] = [0; 32];
    OPENSSL_memcpy(
        s_copy.as_mut_ptr() as *mut libc::c_void,
        s as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    s_copy[31 as libc::c_int
        as usize] = (s_copy[31 as libc::c_int as usize] as libc::c_int
        & 0x7f as libc::c_int) as uint8_t;
    fe_frombytes_strict(h, s_copy.as_mut_ptr() as *const uint8_t);
}
unsafe extern "C" fn fe_tobytes(mut s: *mut uint8_t, mut f: *const fe) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*f).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                162 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 39],
                    &[libc::c_char; 39],
                >(b"void fe_tobytes(uint8_t *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_7932: {
            if constant_time_declassify_int(
                ((*f).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    162 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 39],
                        &[libc::c_char; 39],
                    >(b"void fe_tobytes(uint8_t *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    fiat_25519_to_bytes(s, ((*f).v).as_ptr());
}
unsafe extern "C" fn fe_0(mut h: *mut fe) {
    OPENSSL_memset(
        h as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<fe>() as libc::c_ulong,
    );
}
unsafe extern "C" fn fe_loose_0(mut h: *mut fe_loose) {
    OPENSSL_memset(
        h as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<fe_loose>() as libc::c_ulong,
    );
}
unsafe extern "C" fn fe_1(mut h: *mut fe) {
    OPENSSL_memset(
        h as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<fe>() as libc::c_ulong,
    );
    (*h).v[0 as libc::c_int as usize] = 1 as libc::c_int as uint64_t;
}
unsafe extern "C" fn fe_loose_1(mut h: *mut fe_loose) {
    OPENSSL_memset(
        h as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<fe_loose>() as libc::c_ulong,
    );
    (*h).v[0 as libc::c_int as usize] = 1 as libc::c_int as uint64_t;
}
unsafe extern "C" fn fe_add(mut h: *mut fe_loose, mut f: *const fe, mut g: *const fe) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*f).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                189 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"void fe_add(fe_loose *, const fe *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_12021: {
            if constant_time_declassify_int(
                ((*f).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    189 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 48],
                        &[libc::c_char; 48],
                    >(b"void fe_add(fe_loose *, const fe *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    let mut _assert_fe_i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_0 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*g).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(g->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                190 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"void fe_add(fe_loose *, const fe *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_11951: {
            if constant_time_declassify_int(
                ((*g).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(g->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    190 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 48],
                        &[libc::c_char; 48],
                    >(b"void fe_add(fe_loose *, const fe *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
        _assert_fe_i_0;
    }
    fiat_25519_add(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
    let mut _assert_fe_i_1: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_1 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*h).v[_assert_fe_i_1 as usize] <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                192 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"void fe_add(fe_loose *, const fe *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_11724: {
            if constant_time_declassify_int(
                ((*h).v[_assert_fe_i_1 as usize] <= 0x1a666666666664 as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    192 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 48],
                        &[libc::c_char; 48],
                    >(b"void fe_add(fe_loose *, const fe *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_1 = _assert_fe_i_1.wrapping_add(1);
        _assert_fe_i_1;
    }
}
unsafe extern "C" fn fe_sub(mut h: *mut fe_loose, mut f: *const fe, mut g: *const fe) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*f).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                198 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"void fe_sub(fe_loose *, const fe *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_12426: {
            if constant_time_declassify_int(
                ((*f).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    198 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 48],
                        &[libc::c_char; 48],
                    >(b"void fe_sub(fe_loose *, const fe *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    let mut _assert_fe_i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_0 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*g).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(g->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                199 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"void fe_sub(fe_loose *, const fe *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_12356: {
            if constant_time_declassify_int(
                ((*g).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(g->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    199 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 48],
                        &[libc::c_char; 48],
                    >(b"void fe_sub(fe_loose *, const fe *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
        _assert_fe_i_0;
    }
    fiat_25519_sub(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
    let mut _assert_fe_i_1: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_1 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*h).v[_assert_fe_i_1 as usize] <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                201 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 48],
                    &[libc::c_char; 48],
                >(b"void fe_sub(fe_loose *, const fe *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_12116: {
            if constant_time_declassify_int(
                ((*h).v[_assert_fe_i_1 as usize] <= 0x1a666666666664 as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    201 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 48],
                        &[libc::c_char; 48],
                    >(b"void fe_sub(fe_loose *, const fe *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_1 = _assert_fe_i_1.wrapping_add(1);
        _assert_fe_i_1;
    }
}
unsafe extern "C" fn fe_carry(mut h: *mut fe, mut f: *const fe_loose) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*f).v[_assert_fe_i as usize] <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                205 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void fe_carry(fe *, const fe_loose *)\0"))
                    .as_ptr(),
            );
        }
        'c_11235: {
            if constant_time_declassify_int(
                ((*f).v[_assert_fe_i as usize] <= 0x1a666666666664 as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    205 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void fe_carry(fe *, const fe_loose *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    fiat_25519_carry(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_0 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*h).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                207 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void fe_carry(fe *, const fe_loose *)\0"))
                    .as_ptr(),
            );
        }
        'c_10928: {
            if constant_time_declassify_int(
                ((*h).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    207 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void fe_carry(fe *, const fe_loose *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
        _assert_fe_i_0;
    }
}
unsafe extern "C" fn fe_mul_impl(
    mut out: *mut fe_limb_t,
    mut in1: *const fe_limb_t,
    mut in2: *const fe_limb_t,
) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            (*in1.offset(_assert_fe_i as isize) <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(in1[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                213 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 68],
                    &[libc::c_char; 68],
                >(
                    b"void fe_mul_impl(fe_limb_t *, const fe_limb_t *, const fe_limb_t *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_9195: {
            if constant_time_declassify_int(
                (*in1.offset(_assert_fe_i as isize) <= 0x1a666666666664 as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(in1[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    213 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 68],
                        &[libc::c_char; 68],
                    >(
                        b"void fe_mul_impl(fe_limb_t *, const fe_limb_t *, const fe_limb_t *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    let mut _assert_fe_i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_0 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            (*in2.offset(_assert_fe_i_0 as isize) <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(in2[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                214 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 68],
                    &[libc::c_char; 68],
                >(
                    b"void fe_mul_impl(fe_limb_t *, const fe_limb_t *, const fe_limb_t *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_9129: {
            if constant_time_declassify_int(
                (*in2.offset(_assert_fe_i_0 as isize)
                    <= 0x1a666666666664 as libc::c_ulong) as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(in2[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    214 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 68],
                        &[libc::c_char; 68],
                    >(
                        b"void fe_mul_impl(fe_limb_t *, const fe_limb_t *, const fe_limb_t *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
        _assert_fe_i_0;
    }
    fiat_25519_carry_mul(out, in1, in2);
    let mut _assert_fe_i_1: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_1 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            (*out.offset(_assert_fe_i_1 as isize) <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(out[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                216 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 68],
                    &[libc::c_char; 68],
                >(
                    b"void fe_mul_impl(fe_limb_t *, const fe_limb_t *, const fe_limb_t *)\0",
                ))
                    .as_ptr(),
            );
        }
        'c_8071: {
            if constant_time_declassify_int(
                (*out.offset(_assert_fe_i_1 as isize)
                    <= 0x8cccccccccccc as libc::c_ulong) as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(out[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    216 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 68],
                        &[libc::c_char; 68],
                    >(
                        b"void fe_mul_impl(fe_limb_t *, const fe_limb_t *, const fe_limb_t *)\0",
                    ))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_1 = _assert_fe_i_1.wrapping_add(1);
        _assert_fe_i_1;
    }
}
unsafe extern "C" fn fe_mul_ltt(
    mut h: *mut fe_loose,
    mut f: *const fe,
    mut g: *const fe,
) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_llt(
    mut h: *mut fe_loose,
    mut f: *const fe_loose,
    mut g: *const fe,
) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_ttt(mut h: *mut fe, mut f: *const fe, mut g: *const fe) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_tlt(
    mut h: *mut fe,
    mut f: *const fe_loose,
    mut g: *const fe,
) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_ttl(
    mut h: *mut fe,
    mut f: *const fe,
    mut g: *const fe_loose,
) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_tll(
    mut h: *mut fe,
    mut f: *const fe_loose,
    mut g: *const fe_loose,
) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_sq_tl(mut h: *mut fe, mut f: *const fe_loose) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*f).v[_assert_fe_i as usize] <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                244 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void fe_sq_tl(fe *, const fe_loose *)\0"))
                    .as_ptr(),
            );
        }
        'c_10757: {
            if constant_time_declassify_int(
                ((*f).v[_assert_fe_i as usize] <= 0x1a666666666664 as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    244 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void fe_sq_tl(fe *, const fe_loose *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    fiat_25519_carry_square(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_0 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*h).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                246 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 38],
                    &[libc::c_char; 38],
                >(b"void fe_sq_tl(fe *, const fe_loose *)\0"))
                    .as_ptr(),
            );
        }
        'c_10675: {
            if constant_time_declassify_int(
                ((*h).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    246 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 38],
                        &[libc::c_char; 38],
                    >(b"void fe_sq_tl(fe *, const fe_loose *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
        _assert_fe_i_0;
    }
}
unsafe extern "C" fn fe_sq_tt(mut h: *mut fe, mut f: *const fe) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*f).v[_assert_fe_i as usize] <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                250 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 32],
                    &[libc::c_char; 32],
                >(b"void fe_sq_tt(fe *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_10208: {
            if constant_time_declassify_int(
                ((*f).v[_assert_fe_i as usize] <= 0x1a666666666664 as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    250 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 32],
                        &[libc::c_char; 32],
                    >(b"void fe_sq_tt(fe *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    fiat_25519_carry_square(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_0 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*h).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                252 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 32],
                    &[libc::c_char; 32],
                >(b"void fe_sq_tt(fe *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_9377: {
            if constant_time_declassify_int(
                ((*h).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    252 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 32],
                        &[libc::c_char; 32],
                    >(b"void fe_sq_tt(fe *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
        _assert_fe_i_0;
    }
}
unsafe extern "C" fn fe_cswap(mut f: *mut fe, mut g: *mut fe, mut b: fe_limb_t) {
    b = (0 as libc::c_int as fe_limb_t).wrapping_sub(b);
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 5 as libc::c_int as libc::c_uint {
        let mut x: fe_limb_t = (*f).v[i as usize] ^ (*g).v[i as usize];
        x &= b;
        (*f).v[i as usize] ^= x;
        (*g).v[i as usize] ^= x;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn fe_mul121666(mut h: *mut fe, mut f: *const fe_loose) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*f).v[_assert_fe_i as usize] <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                270 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 42],
                    &[libc::c_char; 42],
                >(b"void fe_mul121666(fe *, const fe_loose *)\0"))
                    .as_ptr(),
            );
        }
        'c_32061: {
            if constant_time_declassify_int(
                ((*f).v[_assert_fe_i as usize] <= 0x1a666666666664 as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    270 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 42],
                        &[libc::c_char; 42],
                    >(b"void fe_mul121666(fe *, const fe_loose *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    fiat_25519_carry_scmul_121666(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_0 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*h).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                272 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 42],
                    &[libc::c_char; 42],
                >(b"void fe_mul121666(fe *, const fe_loose *)\0"))
                    .as_ptr(),
            );
        }
        'c_31605: {
            if constant_time_declassify_int(
                ((*h).v[_assert_fe_i_0 as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    272 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 42],
                        &[libc::c_char; 42],
                    >(b"void fe_mul121666(fe *, const fe_loose *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
        _assert_fe_i_0;
    }
}
unsafe extern "C" fn fe_neg(mut h: *mut fe_loose, mut f: *const fe) {
    let mut _assert_fe_i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*f).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                277 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"void fe_neg(fe_loose *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_11520: {
            if constant_time_declassify_int(
                ((*f).v[_assert_fe_i as usize] <= 0x8cccccccccccc as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(f->v[_assert_fe_i] <= 0x8ccccccccccccUL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    277 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 36],
                        &[libc::c_char; 36],
                    >(b"void fe_neg(fe_loose *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
        _assert_fe_i;
    }
    fiat_25519_opp(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while _assert_fe_i_0 < 5 as libc::c_int as libc::c_uint {
        if constant_time_declassify_int(
            ((*h).v[_assert_fe_i_0 as usize] <= 0x1a666666666664 as libc::c_ulong)
                as libc::c_int,
        ) != 0
        {} else {
            __assert_fail(
                b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                    as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                    as *const u8 as *const libc::c_char,
                279 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 36],
                    &[libc::c_char; 36],
                >(b"void fe_neg(fe_loose *, const fe *)\0"))
                    .as_ptr(),
            );
        }
        'c_11322: {
            if constant_time_declassify_int(
                ((*h).v[_assert_fe_i_0 as usize] <= 0x1a666666666664 as libc::c_ulong)
                    as libc::c_int,
            ) != 0
            {} else {
                __assert_fail(
                    b"constant_time_declassify_int(h->v[_assert_fe_i] <= 0x1a666666666664UL)\0"
                        as *const u8 as *const libc::c_char,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/fipsmodule/curve25519/curve25519_nohw.c\0"
                        as *const u8 as *const libc::c_char,
                    279 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 36],
                        &[libc::c_char; 36],
                    >(b"void fe_neg(fe_loose *, const fe *)\0"))
                        .as_ptr(),
                );
            }
        };
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
        _assert_fe_i_0;
    }
}
unsafe extern "C" fn fe_cmov(
    mut f: *mut fe_loose,
    mut g: *const fe_loose,
    mut b: fe_limb_t,
) {
    b = (0 as libc::c_int as fe_limb_t).wrapping_sub(b);
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < 5 as libc::c_int as libc::c_uint {
        let mut x: fe_limb_t = (*f).v[i as usize] ^ (*g).v[i as usize];
        x &= b;
        (*f).v[i as usize] ^= x;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn fe_copy(mut h: *mut fe, mut f: *const fe) {
    OPENSSL_memmove(
        h as *mut libc::c_void,
        f as *const libc::c_void,
        ::core::mem::size_of::<fe>() as libc::c_ulong,
    );
}
unsafe extern "C" fn fe_copy_lt(mut h: *mut fe_loose, mut f: *const fe) {
    OPENSSL_memmove(
        h as *mut libc::c_void,
        f as *const libc::c_void,
        ::core::mem::size_of::<fe>() as libc::c_ulong,
    );
}
unsafe extern "C" fn fe_copy_ll(mut h: *mut fe_loose, mut f: *const fe_loose) {
    OPENSSL_memmove(
        h as *mut libc::c_void,
        f as *const libc::c_void,
        ::core::mem::size_of::<fe_loose>() as libc::c_ulong,
    );
}
unsafe extern "C" fn fe_loose_invert(mut out: *mut fe, mut z: *const fe_loose) {
    let mut t0: fe = fe { v: [0; 5] };
    let mut t1: fe = fe { v: [0; 5] };
    let mut t2: fe = fe { v: [0; 5] };
    let mut t3: fe = fe { v: [0; 5] };
    let mut i: libc::c_int = 0;
    fe_sq_tl(&mut t0, z);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as libc::c_int;
    while i < 2 as libc::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
        i;
    }
    fe_mul_tlt(&mut t1, z, &mut t1);
    fe_mul_ttt(&mut t0, &mut t0, &mut t1);
    fe_sq_tt(&mut t2, &mut t0);
    fe_mul_ttt(&mut t1, &mut t1, &mut t2);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as libc::c_int;
    while i < 5 as libc::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as libc::c_int;
    while i < 10 as libc::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t2, &mut t2, &mut t1);
    fe_sq_tt(&mut t3, &mut t2);
    i = 1 as libc::c_int;
    while i < 20 as libc::c_int {
        fe_sq_tt(&mut t3, &mut t3);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t2, &mut t3, &mut t2);
    fe_sq_tt(&mut t2, &mut t2);
    i = 1 as libc::c_int;
    while i < 10 as libc::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as libc::c_int;
    while i < 50 as libc::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t2, &mut t2, &mut t1);
    fe_sq_tt(&mut t3, &mut t2);
    i = 1 as libc::c_int;
    while i < 100 as libc::c_int {
        fe_sq_tt(&mut t3, &mut t3);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t2, &mut t3, &mut t2);
    fe_sq_tt(&mut t2, &mut t2);
    i = 1 as libc::c_int;
    while i < 50 as libc::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t1, &mut t1);
    i = 1 as libc::c_int;
    while i < 5 as libc::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
        i;
    }
    fe_mul_ttt(out, &mut t1, &mut t0);
}
unsafe extern "C" fn fe_invert(mut out: *mut fe, mut z: *const fe) {
    let mut l: fe_loose = fe_loose { v: [0; 5] };
    fe_copy_lt(&mut l, z);
    fe_loose_invert(out, &mut l);
}
unsafe extern "C" fn fe_isnonzero(mut f: *const fe_loose) -> libc::c_int {
    let mut tight: fe = fe { v: [0; 5] };
    fe_carry(&mut tight, f);
    let mut s: [uint8_t; 32] = [0; 32];
    fe_tobytes(s.as_mut_ptr(), &mut tight);
    static mut zero: [uint8_t; 32] = [
        0 as libc::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    return (CRYPTO_memcmp(
        s.as_mut_ptr() as *const libc::c_void,
        zero.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    ) != 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn fe_isnegative(mut f: *const fe) -> libc::c_int {
    let mut s: [uint8_t; 32] = [0; 32];
    fe_tobytes(s.as_mut_ptr(), f);
    return s[0 as libc::c_int as usize] as libc::c_int & 1 as libc::c_int;
}
unsafe extern "C" fn fe_sq2_tt(mut h: *mut fe, mut f: *const fe) {
    fe_sq_tt(h, f);
    let mut tmp: fe_loose = fe_loose { v: [0; 5] };
    fe_add(&mut tmp, h, h);
    fe_carry(h, &mut tmp);
}
unsafe extern "C" fn fe_pow22523(mut out: *mut fe, mut z: *const fe) {
    let mut t0: fe = fe { v: [0; 5] };
    let mut t1: fe = fe { v: [0; 5] };
    let mut t2: fe = fe { v: [0; 5] };
    let mut i: libc::c_int = 0;
    fe_sq_tt(&mut t0, z);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as libc::c_int;
    while i < 2 as libc::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t1, z, &mut t1);
    fe_mul_ttt(&mut t0, &mut t0, &mut t1);
    fe_sq_tt(&mut t0, &mut t0);
    fe_mul_ttt(&mut t0, &mut t1, &mut t0);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as libc::c_int;
    while i < 5 as libc::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t0, &mut t1, &mut t0);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as libc::c_int;
    while i < 10 as libc::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t1, &mut t1, &mut t0);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as libc::c_int;
    while i < 20 as libc::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t1, &mut t1);
    i = 1 as libc::c_int;
    while i < 10 as libc::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t0, &mut t1, &mut t0);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as libc::c_int;
    while i < 50 as libc::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t1, &mut t1, &mut t0);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as libc::c_int;
    while i < 100 as libc::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t1, &mut t1);
    i = 1 as libc::c_int;
    while i < 50 as libc::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
        i;
    }
    fe_mul_ttt(&mut t0, &mut t1, &mut t0);
    fe_sq_tt(&mut t0, &mut t0);
    i = 1 as libc::c_int;
    while i < 2 as libc::c_int {
        fe_sq_tt(&mut t0, &mut t0);
        i += 1;
        i;
    }
    fe_mul_ttt(out, &mut t0, z);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_tobytes(mut s: *mut uint8_t, mut h: *const ge_p2) {
    let mut recip: fe = fe { v: [0; 5] };
    let mut x: fe = fe { v: [0; 5] };
    let mut y: fe = fe { v: [0; 5] };
    fe_invert(&mut recip, &(*h).Z);
    fe_mul_ttt(&mut x, &(*h).X, &mut recip);
    fe_mul_ttt(&mut y, &(*h).Y, &mut recip);
    fe_tobytes(s, &mut y);
    let ref mut fresh0 = *s.offset(31 as libc::c_int as isize);
    *fresh0 = (*fresh0 as libc::c_int ^ fe_isnegative(&mut x) << 7 as libc::c_int)
        as uint8_t;
}
unsafe extern "C" fn ge_p3_tobytes(mut s: *mut uint8_t, mut h: *const ge_p3) {
    let mut recip: fe = fe { v: [0; 5] };
    let mut x: fe = fe { v: [0; 5] };
    let mut y: fe = fe { v: [0; 5] };
    fe_invert(&mut recip, &(*h).Z);
    fe_mul_ttt(&mut x, &(*h).X, &mut recip);
    fe_mul_ttt(&mut y, &(*h).Y, &mut recip);
    fe_tobytes(s, &mut y);
    let ref mut fresh1 = *s.offset(31 as libc::c_int as isize);
    *fresh1 = (*fresh1 as libc::c_int ^ fe_isnegative(&mut x) << 7 as libc::c_int)
        as uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_frombytes_vartime(
    mut h: *mut ge_p3,
    mut s: *const uint8_t,
) -> libc::c_int {
    let mut u: fe = fe { v: [0; 5] };
    let mut v: fe_loose = fe_loose { v: [0; 5] };
    let mut w: fe = fe { v: [0; 5] };
    let mut vxx: fe = fe { v: [0; 5] };
    let mut check: fe_loose = fe_loose { v: [0; 5] };
    fe_frombytes(&mut (*h).Y, s);
    fe_1(&mut (*h).Z);
    fe_sq_tt(&mut w, &mut (*h).Y);
    fe_mul_ttt(&mut vxx, &mut w, &k25519d);
    fe_sub(&mut v, &mut w, &mut (*h).Z);
    fe_carry(&mut u, &mut v);
    fe_add(&mut v, &mut vxx, &mut (*h).Z);
    fe_mul_ttl(&mut w, &mut u, &mut v);
    fe_pow22523(&mut (*h).X, &mut w);
    fe_mul_ttt(&mut (*h).X, &mut (*h).X, &mut u);
    fe_sq_tt(&mut vxx, &mut (*h).X);
    fe_mul_ttl(&mut vxx, &mut vxx, &mut v);
    fe_sub(&mut check, &mut vxx, &mut u);
    if fe_isnonzero(&mut check) != 0 {
        fe_add(&mut check, &mut vxx, &mut u);
        if fe_isnonzero(&mut check) != 0 {
            return 0 as libc::c_int;
        }
        fe_mul_ttt(&mut (*h).X, &mut (*h).X, &k25519sqrtm1);
    }
    if fe_isnegative(&mut (*h).X)
        != *s.offset(31 as libc::c_int as isize) as libc::c_int >> 7 as libc::c_int
    {
        let mut t: fe_loose = fe_loose { v: [0; 5] };
        fe_neg(&mut t, &mut (*h).X);
        fe_carry(&mut (*h).X, &mut t);
    }
    fe_mul_ttt(&mut (*h).T, &mut (*h).X, &mut (*h).Y);
    return 1 as libc::c_int;
}
unsafe extern "C" fn ge_p2_0(mut h: *mut ge_p2) {
    fe_0(&mut (*h).X);
    fe_1(&mut (*h).Y);
    fe_1(&mut (*h).Z);
}
unsafe extern "C" fn ge_p3_0(mut h: *mut ge_p3) {
    fe_0(&mut (*h).X);
    fe_1(&mut (*h).Y);
    fe_1(&mut (*h).Z);
    fe_0(&mut (*h).T);
}
unsafe extern "C" fn ge_cached_0(mut h: *mut ge_cached) {
    fe_loose_1(&mut (*h).YplusX);
    fe_loose_1(&mut (*h).YminusX);
    fe_loose_1(&mut (*h).Z);
    fe_loose_0(&mut (*h).T2d);
}
unsafe extern "C" fn ge_precomp_0(mut h: *mut ge_precomp) {
    fe_loose_1(&mut (*h).yplusx);
    fe_loose_1(&mut (*h).yminusx);
    fe_loose_0(&mut (*h).xy2d);
}
unsafe extern "C" fn ge_p3_to_p2(mut r: *mut ge_p2, mut p: *const ge_p3) {
    fe_copy(&mut (*r).X, &(*p).X);
    fe_copy(&mut (*r).Y, &(*p).Y);
    fe_copy(&mut (*r).Z, &(*p).Z);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_p3_to_cached(
    mut r: *mut ge_cached,
    mut p: *const ge_p3,
) {
    fe_add(&mut (*r).YplusX, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).YminusX, &(*p).Y, &(*p).X);
    fe_copy_lt(&mut (*r).Z, &(*p).Z);
    fe_mul_ltt(&mut (*r).T2d, &(*p).T, &k25519d2);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_p1p1_to_p2(mut r: *mut ge_p2, mut p: *const ge_p1p1) {
    fe_mul_tll(&mut (*r).X, &(*p).X, &(*p).T);
    fe_mul_tll(&mut (*r).Y, &(*p).Y, &(*p).Z);
    fe_mul_tll(&mut (*r).Z, &(*p).Z, &(*p).T);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_p1p1_to_p3(mut r: *mut ge_p3, mut p: *const ge_p1p1) {
    fe_mul_tll(&mut (*r).X, &(*p).X, &(*p).T);
    fe_mul_tll(&mut (*r).Y, &(*p).Y, &(*p).Z);
    fe_mul_tll(&mut (*r).Z, &(*p).Z, &(*p).T);
    fe_mul_tll(&mut (*r).T, &(*p).X, &(*p).Y);
}
unsafe extern "C" fn ge_p1p1_to_cached(mut r: *mut ge_cached, mut p: *const ge_p1p1) {
    let mut t: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    x25519_ge_p1p1_to_p3(&mut t, p);
    x25519_ge_p3_to_cached(r, &mut t);
}
unsafe extern "C" fn ge_p2_dbl(mut r: *mut ge_p1p1, mut p: *const ge_p2) {
    let mut trX: fe = fe { v: [0; 5] };
    let mut trZ: fe = fe { v: [0; 5] };
    let mut trT: fe = fe { v: [0; 5] };
    let mut t0: fe = fe { v: [0; 5] };
    fe_sq_tt(&mut trX, &(*p).X);
    fe_sq_tt(&mut trZ, &(*p).Y);
    fe_sq2_tt(&mut trT, &(*p).Z);
    fe_add(&mut (*r).Y, &(*p).X, &(*p).Y);
    fe_sq_tl(&mut t0, &mut (*r).Y);
    fe_add(&mut (*r).Y, &mut trZ, &mut trX);
    fe_sub(&mut (*r).Z, &mut trZ, &mut trX);
    fe_carry(&mut trZ, &mut (*r).Y);
    fe_sub(&mut (*r).X, &mut t0, &mut trZ);
    fe_carry(&mut trZ, &mut (*r).Z);
    fe_sub(&mut (*r).T, &mut trT, &mut trZ);
}
unsafe extern "C" fn ge_p3_dbl(mut r: *mut ge_p1p1, mut p: *const ge_p3) {
    let mut q: ge_p2 = ge_p2 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
    };
    ge_p3_to_p2(&mut q, p);
    ge_p2_dbl(r, &mut q);
}
unsafe extern "C" fn ge_madd(
    mut r: *mut ge_p1p1,
    mut p: *const ge_p3,
    mut q: *const ge_precomp,
) {
    let mut trY: fe = fe { v: [0; 5] };
    let mut trZ: fe = fe { v: [0; 5] };
    let mut trT: fe = fe { v: [0; 5] };
    fe_add(&mut (*r).X, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).Y, &(*p).Y, &(*p).X);
    fe_mul_tll(&mut trZ, &mut (*r).X, &(*q).yplusx);
    fe_mul_tll(&mut trY, &mut (*r).Y, &(*q).yminusx);
    fe_mul_tlt(&mut trT, &(*q).xy2d, &(*p).T);
    fe_add(&mut (*r).T, &(*p).Z, &(*p).Z);
    fe_sub(&mut (*r).X, &mut trZ, &mut trY);
    fe_add(&mut (*r).Y, &mut trZ, &mut trY);
    fe_carry(&mut trZ, &mut (*r).T);
    fe_add(&mut (*r).Z, &mut trZ, &mut trT);
    fe_sub(&mut (*r).T, &mut trZ, &mut trT);
}
unsafe extern "C" fn ge_msub(
    mut r: *mut ge_p1p1,
    mut p: *const ge_p3,
    mut q: *const ge_precomp,
) {
    let mut trY: fe = fe { v: [0; 5] };
    let mut trZ: fe = fe { v: [0; 5] };
    let mut trT: fe = fe { v: [0; 5] };
    fe_add(&mut (*r).X, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).Y, &(*p).Y, &(*p).X);
    fe_mul_tll(&mut trZ, &mut (*r).X, &(*q).yminusx);
    fe_mul_tll(&mut trY, &mut (*r).Y, &(*q).yplusx);
    fe_mul_tlt(&mut trT, &(*q).xy2d, &(*p).T);
    fe_add(&mut (*r).T, &(*p).Z, &(*p).Z);
    fe_sub(&mut (*r).X, &mut trZ, &mut trY);
    fe_add(&mut (*r).Y, &mut trZ, &mut trY);
    fe_carry(&mut trZ, &mut (*r).T);
    fe_sub(&mut (*r).Z, &mut trZ, &mut trT);
    fe_add(&mut (*r).T, &mut trZ, &mut trT);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_add(
    mut r: *mut ge_p1p1,
    mut p: *const ge_p3,
    mut q: *const ge_cached,
) {
    let mut trX: fe = fe { v: [0; 5] };
    let mut trY: fe = fe { v: [0; 5] };
    let mut trZ: fe = fe { v: [0; 5] };
    let mut trT: fe = fe { v: [0; 5] };
    fe_add(&mut (*r).X, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).Y, &(*p).Y, &(*p).X);
    fe_mul_tll(&mut trZ, &mut (*r).X, &(*q).YplusX);
    fe_mul_tll(&mut trY, &mut (*r).Y, &(*q).YminusX);
    fe_mul_tlt(&mut trT, &(*q).T2d, &(*p).T);
    fe_mul_ttl(&mut trX, &(*p).Z, &(*q).Z);
    fe_add(&mut (*r).T, &mut trX, &mut trX);
    fe_sub(&mut (*r).X, &mut trZ, &mut trY);
    fe_add(&mut (*r).Y, &mut trZ, &mut trY);
    fe_carry(&mut trZ, &mut (*r).T);
    fe_add(&mut (*r).Z, &mut trZ, &mut trT);
    fe_sub(&mut (*r).T, &mut trZ, &mut trT);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_sub(
    mut r: *mut ge_p1p1,
    mut p: *const ge_p3,
    mut q: *const ge_cached,
) {
    let mut trX: fe = fe { v: [0; 5] };
    let mut trY: fe = fe { v: [0; 5] };
    let mut trZ: fe = fe { v: [0; 5] };
    let mut trT: fe = fe { v: [0; 5] };
    fe_add(&mut (*r).X, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).Y, &(*p).Y, &(*p).X);
    fe_mul_tll(&mut trZ, &mut (*r).X, &(*q).YminusX);
    fe_mul_tll(&mut trY, &mut (*r).Y, &(*q).YplusX);
    fe_mul_tlt(&mut trT, &(*q).T2d, &(*p).T);
    fe_mul_ttl(&mut trX, &(*p).Z, &(*q).Z);
    fe_add(&mut (*r).T, &mut trX, &mut trX);
    fe_sub(&mut (*r).X, &mut trZ, &mut trY);
    fe_add(&mut (*r).Y, &mut trZ, &mut trY);
    fe_carry(&mut trZ, &mut (*r).T);
    fe_sub(&mut (*r).Z, &mut trZ, &mut trT);
    fe_add(&mut (*r).T, &mut trZ, &mut trT);
}
unsafe extern "C" fn equal(mut b: libc::c_schar, mut c: libc::c_schar) -> uint8_t {
    let mut ub: uint8_t = b as uint8_t;
    let mut uc: uint8_t = c as uint8_t;
    let mut x: uint8_t = (ub as libc::c_int ^ uc as libc::c_int) as uint8_t;
    let mut y: uint32_t = x as uint32_t;
    y = y.wrapping_sub(1 as libc::c_int as uint32_t);
    y >>= 31 as libc::c_int;
    return y as uint8_t;
}
unsafe extern "C" fn cmov(
    mut t: *mut ge_precomp,
    mut u: *const ge_precomp,
    mut b: uint8_t,
) {
    fe_cmov(&mut (*t).yplusx, &(*u).yplusx, b as fe_limb_t);
    fe_cmov(&mut (*t).yminusx, &(*u).yminusx, b as fe_limb_t);
    fe_cmov(&mut (*t).xy2d, &(*u).xy2d, b as fe_limb_t);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_scalarmult_small_precomp(
    mut h: *mut ge_p3,
    mut a: *const uint8_t,
    mut precomp_table: *const uint8_t,
) {
    let mut multiples: [ge_precomp; 15] = [ge_precomp {
        yplusx: fe_loose { v: [0; 5] },
        yminusx: fe_loose { v: [0; 5] },
        xy2d: fe_loose { v: [0; 5] },
    }; 15];
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 15 as libc::c_int as libc::c_uint {
        let mut bytes: *const uint8_t = &*precomp_table
            .offset(
                i.wrapping_mul((2 as libc::c_int * 32 as libc::c_int) as libc::c_uint)
                    as isize,
            ) as *const uint8_t;
        let mut x: fe = fe { v: [0; 5] };
        let mut y: fe = fe { v: [0; 5] };
        fe_frombytes_strict(&mut x, bytes);
        fe_frombytes_strict(&mut y, bytes.offset(32 as libc::c_int as isize));
        let mut out: *mut ge_precomp = &mut *multiples.as_mut_ptr().offset(i as isize)
            as *mut ge_precomp;
        fe_add(&mut (*out).yplusx, &mut y, &mut x);
        fe_sub(&mut (*out).yminusx, &mut y, &mut x);
        fe_mul_ltt(&mut (*out).xy2d, &mut x, &mut y);
        fe_mul_llt(&mut (*out).xy2d, &mut (*out).xy2d, &k25519d2);
        i = i.wrapping_add(1);
        i;
    }
    ge_p3_0(h);
    i = 63 as libc::c_int as libc::c_uint;
    while i < 64 as libc::c_int as libc::c_uint {
        let mut j: libc::c_uint = 0;
        let mut index: libc::c_schar = 0 as libc::c_int as libc::c_schar;
        j = 0 as libc::c_int as libc::c_uint;
        while j < 4 as libc::c_int as libc::c_uint {
            let bit: uint8_t = (1 as libc::c_int
                & *a
                    .offset(
                        (8 as libc::c_int as libc::c_uint)
                            .wrapping_mul(j)
                            .wrapping_add(
                                i.wrapping_div(8 as libc::c_int as libc::c_uint),
                            ) as isize,
                    ) as libc::c_int >> (i & 7 as libc::c_int as libc::c_uint))
                as uint8_t;
            index = (index as libc::c_int | (bit as libc::c_int) << j) as libc::c_schar;
            j = j.wrapping_add(1);
            j;
        }
        let mut e: ge_precomp = ge_precomp {
            yplusx: fe_loose { v: [0; 5] },
            yminusx: fe_loose { v: [0; 5] },
            xy2d: fe_loose { v: [0; 5] },
        };
        ge_precomp_0(&mut e);
        j = 1 as libc::c_int as libc::c_uint;
        while j < 16 as libc::c_int as libc::c_uint {
            cmov(
                &mut e,
                &mut *multiples
                    .as_mut_ptr()
                    .offset(j.wrapping_sub(1 as libc::c_int as libc::c_uint) as isize),
                equal(index, j as libc::c_schar),
            );
            j = j.wrapping_add(1);
            j;
        }
        let mut cached: ge_cached = ge_cached {
            YplusX: fe_loose { v: [0; 5] },
            YminusX: fe_loose { v: [0; 5] },
            Z: fe_loose { v: [0; 5] },
            T2d: fe_loose { v: [0; 5] },
        };
        let mut r: ge_p1p1 = ge_p1p1 {
            X: fe_loose { v: [0; 5] },
            Y: fe_loose { v: [0; 5] },
            Z: fe_loose { v: [0; 5] },
            T: fe_loose { v: [0; 5] },
        };
        x25519_ge_p3_to_cached(&mut cached, h);
        x25519_ge_add(&mut r, h, &mut cached);
        x25519_ge_p1p1_to_p3(h, &mut r);
        ge_madd(&mut r, h, &mut e);
        x25519_ge_p1p1_to_p3(h, &mut r);
        i = i.wrapping_sub(1);
        i;
    }
}
unsafe extern "C" fn negative(mut b: libc::c_schar) -> uint8_t {
    let mut x: uint32_t = b as uint32_t;
    x >>= 31 as libc::c_int;
    return x as uint8_t;
}
unsafe extern "C" fn table_select(
    mut t: *mut ge_precomp,
    mut pos: libc::c_int,
    mut b: libc::c_schar,
) {
    let mut minust: ge_precomp = ge_precomp {
        yplusx: fe_loose { v: [0; 5] },
        yminusx: fe_loose { v: [0; 5] },
        xy2d: fe_loose { v: [0; 5] },
    };
    let mut bnegative: uint8_t = negative(b);
    let mut babs: uint8_t = (b as libc::c_int
        - (((-(bnegative as libc::c_int) & b as libc::c_int) as uint8_t as libc::c_int)
            << 1 as libc::c_int)) as uint8_t;
    ge_precomp_0(t);
    cmov(
        t,
        &*(*k25519Precomp.as_ptr().offset(pos as isize))
            .as_ptr()
            .offset(0 as libc::c_int as isize),
        equal(babs as libc::c_schar, 1 as libc::c_int as libc::c_schar),
    );
    cmov(
        t,
        &*(*k25519Precomp.as_ptr().offset(pos as isize))
            .as_ptr()
            .offset(1 as libc::c_int as isize),
        equal(babs as libc::c_schar, 2 as libc::c_int as libc::c_schar),
    );
    cmov(
        t,
        &*(*k25519Precomp.as_ptr().offset(pos as isize))
            .as_ptr()
            .offset(2 as libc::c_int as isize),
        equal(babs as libc::c_schar, 3 as libc::c_int as libc::c_schar),
    );
    cmov(
        t,
        &*(*k25519Precomp.as_ptr().offset(pos as isize))
            .as_ptr()
            .offset(3 as libc::c_int as isize),
        equal(babs as libc::c_schar, 4 as libc::c_int as libc::c_schar),
    );
    cmov(
        t,
        &*(*k25519Precomp.as_ptr().offset(pos as isize))
            .as_ptr()
            .offset(4 as libc::c_int as isize),
        equal(babs as libc::c_schar, 5 as libc::c_int as libc::c_schar),
    );
    cmov(
        t,
        &*(*k25519Precomp.as_ptr().offset(pos as isize))
            .as_ptr()
            .offset(5 as libc::c_int as isize),
        equal(babs as libc::c_schar, 6 as libc::c_int as libc::c_schar),
    );
    cmov(
        t,
        &*(*k25519Precomp.as_ptr().offset(pos as isize))
            .as_ptr()
            .offset(6 as libc::c_int as isize),
        equal(babs as libc::c_schar, 7 as libc::c_int as libc::c_schar),
    );
    cmov(
        t,
        &*(*k25519Precomp.as_ptr().offset(pos as isize))
            .as_ptr()
            .offset(7 as libc::c_int as isize),
        equal(babs as libc::c_schar, 8 as libc::c_int as libc::c_schar),
    );
    fe_copy_ll(&mut minust.yplusx, &mut (*t).yminusx);
    fe_copy_ll(&mut minust.yminusx, &mut (*t).yplusx);
    let mut tmp: fe = fe { v: [0; 5] };
    fe_carry(&mut tmp, &mut (*t).xy2d);
    fe_neg(&mut minust.xy2d, &mut tmp);
    cmov(t, &mut minust, bnegative);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_scalarmult_base(
    mut h: *mut ge_p3,
    mut a: *const uint8_t,
) {
    let mut e: [libc::c_schar; 64] = [0; 64];
    let mut carry: libc::c_schar = 0;
    let mut r: ge_p1p1 = ge_p1p1 {
        X: fe_loose { v: [0; 5] },
        Y: fe_loose { v: [0; 5] },
        Z: fe_loose { v: [0; 5] },
        T: fe_loose { v: [0; 5] },
    };
    let mut s: ge_p2 = ge_p2 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
    };
    let mut t: ge_precomp = ge_precomp {
        yplusx: fe_loose { v: [0; 5] },
        yminusx: fe_loose { v: [0; 5] },
        xy2d: fe_loose { v: [0; 5] },
    };
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 32 as libc::c_int {
        e[(2 as libc::c_int * i + 0 as libc::c_int)
            as usize] = (*a.offset(i as isize) as libc::c_int >> 0 as libc::c_int
            & 15 as libc::c_int) as libc::c_schar;
        e[(2 as libc::c_int * i + 1 as libc::c_int)
            as usize] = (*a.offset(i as isize) as libc::c_int >> 4 as libc::c_int
            & 15 as libc::c_int) as libc::c_schar;
        i += 1;
        i;
    }
    carry = 0 as libc::c_int as libc::c_schar;
    i = 0 as libc::c_int;
    while i < 63 as libc::c_int {
        e[i
            as usize] = (e[i as usize] as libc::c_int + carry as libc::c_int)
            as libc::c_schar;
        carry = (e[i as usize] as libc::c_int + 8 as libc::c_int) as libc::c_schar;
        carry = (carry as libc::c_int >> 4 as libc::c_int) as libc::c_schar;
        e[i
            as usize] = (e[i as usize] as libc::c_int
            - ((carry as libc::c_int) << 4 as libc::c_int)) as libc::c_schar;
        i += 1;
        i;
    }
    e[63 as libc::c_int
        as usize] = (e[63 as libc::c_int as usize] as libc::c_int + carry as libc::c_int)
        as libc::c_schar;
    ge_p3_0(h);
    i = 1 as libc::c_int;
    while i < 64 as libc::c_int {
        table_select(&mut t, i / 2 as libc::c_int, e[i as usize]);
        ge_madd(&mut r, h, &mut t);
        x25519_ge_p1p1_to_p3(h, &mut r);
        i += 2 as libc::c_int;
    }
    ge_p3_dbl(&mut r, h);
    x25519_ge_p1p1_to_p2(&mut s, &mut r);
    ge_p2_dbl(&mut r, &mut s);
    x25519_ge_p1p1_to_p2(&mut s, &mut r);
    ge_p2_dbl(&mut r, &mut s);
    x25519_ge_p1p1_to_p2(&mut s, &mut r);
    ge_p2_dbl(&mut r, &mut s);
    x25519_ge_p1p1_to_p3(h, &mut r);
    i = 0 as libc::c_int;
    while i < 64 as libc::c_int {
        table_select(&mut t, i / 2 as libc::c_int, e[i as usize]);
        ge_madd(&mut r, h, &mut t);
        x25519_ge_p1p1_to_p3(h, &mut r);
        i += 2 as libc::c_int;
    }
}
unsafe extern "C" fn cmov_cached(
    mut t: *mut ge_cached,
    mut u: *mut ge_cached,
    mut b: uint8_t,
) {
    fe_cmov(&mut (*t).YplusX, &mut (*u).YplusX, b as fe_limb_t);
    fe_cmov(&mut (*t).YminusX, &mut (*u).YminusX, b as fe_limb_t);
    fe_cmov(&mut (*t).Z, &mut (*u).Z, b as fe_limb_t);
    fe_cmov(&mut (*t).T2d, &mut (*u).T2d, b as fe_limb_t);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_scalarmult(
    mut r: *mut ge_p2,
    mut scalar: *const uint8_t,
    mut A: *const ge_p3,
) {
    let mut Ai_p2: [ge_p2; 8] = [ge_p2 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
    }; 8];
    let mut Ai: [ge_cached; 16] = [ge_cached {
        YplusX: fe_loose { v: [0; 5] },
        YminusX: fe_loose { v: [0; 5] },
        Z: fe_loose { v: [0; 5] },
        T2d: fe_loose { v: [0; 5] },
    }; 16];
    let mut t: ge_p1p1 = ge_p1p1 {
        X: fe_loose { v: [0; 5] },
        Y: fe_loose { v: [0; 5] },
        Z: fe_loose { v: [0; 5] },
        T: fe_loose { v: [0; 5] },
    };
    ge_cached_0(&mut *Ai.as_mut_ptr().offset(0 as libc::c_int as isize));
    x25519_ge_p3_to_cached(&mut *Ai.as_mut_ptr().offset(1 as libc::c_int as isize), A);
    ge_p3_to_p2(&mut *Ai_p2.as_mut_ptr().offset(1 as libc::c_int as isize), A);
    let mut i: libc::c_uint = 0;
    i = 2 as libc::c_int as libc::c_uint;
    while i < 16 as libc::c_int as libc::c_uint {
        ge_p2_dbl(
            &mut t,
            &mut *Ai_p2
                .as_mut_ptr()
                .offset(i.wrapping_div(2 as libc::c_int as libc::c_uint) as isize),
        );
        ge_p1p1_to_cached(&mut *Ai.as_mut_ptr().offset(i as isize), &mut t);
        if i < 8 as libc::c_int as libc::c_uint {
            x25519_ge_p1p1_to_p2(&mut *Ai_p2.as_mut_ptr().offset(i as isize), &mut t);
        }
        x25519_ge_add(&mut t, A, &mut *Ai.as_mut_ptr().offset(i as isize));
        ge_p1p1_to_cached(
            &mut *Ai
                .as_mut_ptr()
                .offset(i.wrapping_add(1 as libc::c_int as libc::c_uint) as isize),
            &mut t,
        );
        if i < 7 as libc::c_int as libc::c_uint {
            x25519_ge_p1p1_to_p2(
                &mut *Ai_p2
                    .as_mut_ptr()
                    .offset(i.wrapping_add(1 as libc::c_int as libc::c_uint) as isize),
                &mut t,
            );
        }
        i = i.wrapping_add(2 as libc::c_int as libc::c_uint);
    }
    ge_p2_0(r);
    let mut u: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        ge_p2_dbl(&mut t, r);
        x25519_ge_p1p1_to_p2(r, &mut t);
        ge_p2_dbl(&mut t, r);
        x25519_ge_p1p1_to_p2(r, &mut t);
        ge_p2_dbl(&mut t, r);
        x25519_ge_p1p1_to_p2(r, &mut t);
        ge_p2_dbl(&mut t, r);
        x25519_ge_p1p1_to_p3(&mut u, &mut t);
        let mut index: uint8_t = *scalar
            .offset(
                (31 as libc::c_int as libc::c_uint)
                    .wrapping_sub(i.wrapping_div(8 as libc::c_int as libc::c_uint))
                    as isize,
            );
        index = (index as libc::c_int
            >> (4 as libc::c_int as libc::c_uint)
                .wrapping_sub(i & 4 as libc::c_int as libc::c_uint)) as uint8_t;
        index = (index as libc::c_int & 0xf as libc::c_int) as uint8_t;
        let mut j: libc::c_uint = 0;
        let mut selected: ge_cached = ge_cached {
            YplusX: fe_loose { v: [0; 5] },
            YminusX: fe_loose { v: [0; 5] },
            Z: fe_loose { v: [0; 5] },
            T2d: fe_loose { v: [0; 5] },
        };
        ge_cached_0(&mut selected);
        j = 0 as libc::c_int as libc::c_uint;
        while j < 16 as libc::c_int as libc::c_uint {
            cmov_cached(
                &mut selected,
                &mut *Ai.as_mut_ptr().offset(j as isize),
                equal(j as libc::c_schar, index as libc::c_schar),
            );
            j = j.wrapping_add(1);
            j;
        }
        x25519_ge_add(&mut t, &mut u, &mut selected);
        x25519_ge_p1p1_to_p2(r, &mut t);
        i = i.wrapping_add(4 as libc::c_int as libc::c_uint);
    }
}
unsafe extern "C" fn slide(mut r: *mut libc::c_schar, mut a: *const uint8_t) {
    let mut i: libc::c_int = 0;
    let mut b: libc::c_int = 0;
    let mut k: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 256 as libc::c_int {
        *r
            .offset(
                i as isize,
            ) = (1 as libc::c_int
            & *a.offset((i >> 3 as libc::c_int) as isize) as libc::c_int
                >> (i & 7 as libc::c_int)) as libc::c_schar;
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 256 as libc::c_int {
        if *r.offset(i as isize) != 0 {
            b = 1 as libc::c_int;
            while b <= 6 as libc::c_int && i + b < 256 as libc::c_int {
                if *r.offset((i + b) as isize) != 0 {
                    if *r.offset(i as isize) as libc::c_int
                        + ((*r.offset((i + b) as isize) as libc::c_int) << b)
                        <= 15 as libc::c_int
                    {
                        let ref mut fresh2 = *r.offset(i as isize);
                        *fresh2 = (*fresh2 as libc::c_int
                            + ((*r.offset((i + b) as isize) as libc::c_int) << b))
                            as libc::c_schar;
                        *r.offset((i + b) as isize) = 0 as libc::c_int as libc::c_schar;
                    } else {
                        if !(*r.offset(i as isize) as libc::c_int
                            - ((*r.offset((i + b) as isize) as libc::c_int) << b)
                            >= -(15 as libc::c_int))
                        {
                            break;
                        }
                        let ref mut fresh3 = *r.offset(i as isize);
                        *fresh3 = (*fresh3 as libc::c_int
                            - ((*r.offset((i + b) as isize) as libc::c_int) << b))
                            as libc::c_schar;
                        k = i + b;
                        while k < 256 as libc::c_int {
                            if *r.offset(k as isize) == 0 {
                                *r.offset(k as isize) = 1 as libc::c_int as libc::c_schar;
                                break;
                            } else {
                                *r.offset(k as isize) = 0 as libc::c_int as libc::c_schar;
                                k += 1;
                                k;
                            }
                        }
                    }
                }
                b += 1;
                b;
            }
        }
        i += 1;
        i;
    }
}
unsafe extern "C" fn ge_double_scalarmult_vartime(
    mut r: *mut ge_p2,
    mut a: *const uint8_t,
    mut A: *const ge_p3,
    mut b: *const uint8_t,
) {
    let mut aslide: [libc::c_schar; 256] = [0; 256];
    let mut bslide: [libc::c_schar; 256] = [0; 256];
    let mut Ai: [ge_cached; 8] = [ge_cached {
        YplusX: fe_loose { v: [0; 5] },
        YminusX: fe_loose { v: [0; 5] },
        Z: fe_loose { v: [0; 5] },
        T2d: fe_loose { v: [0; 5] },
    }; 8];
    let mut t: ge_p1p1 = ge_p1p1 {
        X: fe_loose { v: [0; 5] },
        Y: fe_loose { v: [0; 5] },
        Z: fe_loose { v: [0; 5] },
        T: fe_loose { v: [0; 5] },
    };
    let mut u: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    let mut A2: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    let mut i: libc::c_int = 0;
    slide(aslide.as_mut_ptr(), a);
    slide(bslide.as_mut_ptr(), b);
    x25519_ge_p3_to_cached(&mut *Ai.as_mut_ptr().offset(0 as libc::c_int as isize), A);
    ge_p3_dbl(&mut t, A);
    x25519_ge_p1p1_to_p3(&mut A2, &mut t);
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(0 as libc::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(1 as libc::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(1 as libc::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(2 as libc::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(3 as libc::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(3 as libc::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(4 as libc::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(4 as libc::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(5 as libc::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(5 as libc::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(6 as libc::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(6 as libc::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(7 as libc::c_int as isize),
        &mut u,
    );
    ge_p2_0(r);
    i = 255 as libc::c_int;
    while i >= 0 as libc::c_int {
        if aslide[i as usize] as libc::c_int != 0
            || bslide[i as usize] as libc::c_int != 0
        {
            break;
        }
        i -= 1;
        i;
    }
    while i >= 0 as libc::c_int {
        ge_p2_dbl(&mut t, r);
        if aslide[i as usize] as libc::c_int > 0 as libc::c_int {
            x25519_ge_p1p1_to_p3(&mut u, &mut t);
            x25519_ge_add(
                &mut t,
                &mut u,
                &mut *Ai
                    .as_mut_ptr()
                    .offset(
                        (*aslide.as_mut_ptr().offset(i as isize) as libc::c_int
                            / 2 as libc::c_int) as isize,
                    ),
            );
        } else if (aslide[i as usize] as libc::c_int) < 0 as libc::c_int {
            x25519_ge_p1p1_to_p3(&mut u, &mut t);
            x25519_ge_sub(
                &mut t,
                &mut u,
                &mut *Ai
                    .as_mut_ptr()
                    .offset(
                        (-(*aslide.as_mut_ptr().offset(i as isize) as libc::c_int)
                            / 2 as libc::c_int) as isize,
                    ),
            );
        }
        if bslide[i as usize] as libc::c_int > 0 as libc::c_int {
            x25519_ge_p1p1_to_p3(&mut u, &mut t);
            ge_madd(
                &mut t,
                &mut u,
                &*k25519Bi
                    .as_ptr()
                    .offset(
                        (*bslide.as_mut_ptr().offset(i as isize) as libc::c_int
                            / 2 as libc::c_int) as isize,
                    ),
            );
        } else if (bslide[i as usize] as libc::c_int) < 0 as libc::c_int {
            x25519_ge_p1p1_to_p3(&mut u, &mut t);
            ge_msub(
                &mut t,
                &mut u,
                &*k25519Bi
                    .as_ptr()
                    .offset(
                        (-(*bslide.as_mut_ptr().offset(i as isize) as libc::c_int)
                            / 2 as libc::c_int) as isize,
                    ),
            );
        }
        x25519_ge_p1p1_to_p2(r, &mut t);
        i -= 1;
        i;
    }
}
#[inline]
unsafe extern "C" fn int64_lshift21(mut a: int64_t) -> int64_t {
    return ((a as uint64_t) << 21 as libc::c_int) as int64_t;
}
#[no_mangle]
pub unsafe extern "C" fn x25519_sc_reduce(mut s: *mut uint8_t) {
    let mut s0: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s as *const uint8_t)) as int64_t;
    let mut s1: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(2 as libc::c_int as isize) as *const uint8_t)
            >> 5 as libc::c_int) as int64_t;
    let mut s2: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(5 as libc::c_int as isize) as *const uint8_t)
            >> 2 as libc::c_int) as int64_t;
    let mut s3: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(7 as libc::c_int as isize) as *const uint8_t)
            >> 7 as libc::c_int) as int64_t;
    let mut s4: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(10 as libc::c_int as isize) as *const uint8_t)
            >> 4 as libc::c_int) as int64_t;
    let mut s5: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(13 as libc::c_int as isize) as *const uint8_t)
            >> 1 as libc::c_int) as int64_t;
    let mut s6: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(15 as libc::c_int as isize) as *const uint8_t)
            >> 6 as libc::c_int) as int64_t;
    let mut s7: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(18 as libc::c_int as isize) as *const uint8_t)
            >> 3 as libc::c_int) as int64_t;
    let mut s8: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(21 as libc::c_int as isize) as *const uint8_t)) as int64_t;
    let mut s9: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(23 as libc::c_int as isize) as *const uint8_t)
            >> 5 as libc::c_int) as int64_t;
    let mut s10: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(26 as libc::c_int as isize) as *const uint8_t)
            >> 2 as libc::c_int) as int64_t;
    let mut s11: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(28 as libc::c_int as isize) as *const uint8_t)
            >> 7 as libc::c_int) as int64_t;
    let mut s12: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(31 as libc::c_int as isize) as *const uint8_t)
            >> 4 as libc::c_int) as int64_t;
    let mut s13: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(34 as libc::c_int as isize) as *const uint8_t)
            >> 1 as libc::c_int) as int64_t;
    let mut s14: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(36 as libc::c_int as isize) as *const uint8_t)
            >> 6 as libc::c_int) as int64_t;
    let mut s15: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(39 as libc::c_int as isize) as *const uint8_t)
            >> 3 as libc::c_int) as int64_t;
    let mut s16: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(42 as libc::c_int as isize) as *const uint8_t)) as int64_t;
    let mut s17: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(44 as libc::c_int as isize) as *const uint8_t)
            >> 5 as libc::c_int) as int64_t;
    let mut s18: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(47 as libc::c_int as isize) as *const uint8_t)
            >> 2 as libc::c_int) as int64_t;
    let mut s19: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(49 as libc::c_int as isize) as *const uint8_t)
            >> 7 as libc::c_int) as int64_t;
    let mut s20: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(52 as libc::c_int as isize) as *const uint8_t)
            >> 4 as libc::c_int) as int64_t;
    let mut s21: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(s.offset(55 as libc::c_int as isize) as *const uint8_t)
            >> 1 as libc::c_int) as int64_t;
    let mut s22: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(s.offset(57 as libc::c_int as isize) as *const uint8_t)
            >> 6 as libc::c_int) as int64_t;
    let mut s23: int64_t = (load_4(
        s.offset(60 as libc::c_int as isize) as *const uint8_t,
    ) >> 3 as libc::c_int) as int64_t;
    let mut carry0: int64_t = 0;
    let mut carry1: int64_t = 0;
    let mut carry2: int64_t = 0;
    let mut carry3: int64_t = 0;
    let mut carry4: int64_t = 0;
    let mut carry5: int64_t = 0;
    let mut carry6: int64_t = 0;
    let mut carry7: int64_t = 0;
    let mut carry8: int64_t = 0;
    let mut carry9: int64_t = 0;
    let mut carry10: int64_t = 0;
    let mut carry11: int64_t = 0;
    let mut carry12: int64_t = 0;
    let mut carry13: int64_t = 0;
    let mut carry14: int64_t = 0;
    let mut carry15: int64_t = 0;
    let mut carry16: int64_t = 0;
    s11 += s23 * 666643 as libc::c_int as int64_t;
    s12 += s23 * 470296 as libc::c_int as int64_t;
    s13 += s23 * 654183 as libc::c_int as int64_t;
    s14 -= s23 * 997805 as libc::c_int as int64_t;
    s15 += s23 * 136657 as libc::c_int as int64_t;
    s16 -= s23 * 683901 as libc::c_int as int64_t;
    s23 = 0 as libc::c_int as int64_t;
    s10 += s22 * 666643 as libc::c_int as int64_t;
    s11 += s22 * 470296 as libc::c_int as int64_t;
    s12 += s22 * 654183 as libc::c_int as int64_t;
    s13 -= s22 * 997805 as libc::c_int as int64_t;
    s14 += s22 * 136657 as libc::c_int as int64_t;
    s15 -= s22 * 683901 as libc::c_int as int64_t;
    s22 = 0 as libc::c_int as int64_t;
    s9 += s21 * 666643 as libc::c_int as int64_t;
    s10 += s21 * 470296 as libc::c_int as int64_t;
    s11 += s21 * 654183 as libc::c_int as int64_t;
    s12 -= s21 * 997805 as libc::c_int as int64_t;
    s13 += s21 * 136657 as libc::c_int as int64_t;
    s14 -= s21 * 683901 as libc::c_int as int64_t;
    s21 = 0 as libc::c_int as int64_t;
    s8 += s20 * 666643 as libc::c_int as int64_t;
    s9 += s20 * 470296 as libc::c_int as int64_t;
    s10 += s20 * 654183 as libc::c_int as int64_t;
    s11 -= s20 * 997805 as libc::c_int as int64_t;
    s12 += s20 * 136657 as libc::c_int as int64_t;
    s13 -= s20 * 683901 as libc::c_int as int64_t;
    s20 = 0 as libc::c_int as int64_t;
    s7 += s19 * 666643 as libc::c_int as int64_t;
    s8 += s19 * 470296 as libc::c_int as int64_t;
    s9 += s19 * 654183 as libc::c_int as int64_t;
    s10 -= s19 * 997805 as libc::c_int as int64_t;
    s11 += s19 * 136657 as libc::c_int as int64_t;
    s12 -= s19 * 683901 as libc::c_int as int64_t;
    s19 = 0 as libc::c_int as int64_t;
    s6 += s18 * 666643 as libc::c_int as int64_t;
    s7 += s18 * 470296 as libc::c_int as int64_t;
    s8 += s18 * 654183 as libc::c_int as int64_t;
    s9 -= s18 * 997805 as libc::c_int as int64_t;
    s10 += s18 * 136657 as libc::c_int as int64_t;
    s11 -= s18 * 683901 as libc::c_int as int64_t;
    s18 = 0 as libc::c_int as int64_t;
    carry6 = s6 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = s8 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = s10 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = s12 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = s14 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = s16 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);
    carry7 = s7 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = s9 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = s11 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = s13 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = s15 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);
    s5 += s17 * 666643 as libc::c_int as int64_t;
    s6 += s17 * 470296 as libc::c_int as int64_t;
    s7 += s17 * 654183 as libc::c_int as int64_t;
    s8 -= s17 * 997805 as libc::c_int as int64_t;
    s9 += s17 * 136657 as libc::c_int as int64_t;
    s10 -= s17 * 683901 as libc::c_int as int64_t;
    s17 = 0 as libc::c_int as int64_t;
    s4 += s16 * 666643 as libc::c_int as int64_t;
    s5 += s16 * 470296 as libc::c_int as int64_t;
    s6 += s16 * 654183 as libc::c_int as int64_t;
    s7 -= s16 * 997805 as libc::c_int as int64_t;
    s8 += s16 * 136657 as libc::c_int as int64_t;
    s9 -= s16 * 683901 as libc::c_int as int64_t;
    s16 = 0 as libc::c_int as int64_t;
    s3 += s15 * 666643 as libc::c_int as int64_t;
    s4 += s15 * 470296 as libc::c_int as int64_t;
    s5 += s15 * 654183 as libc::c_int as int64_t;
    s6 -= s15 * 997805 as libc::c_int as int64_t;
    s7 += s15 * 136657 as libc::c_int as int64_t;
    s8 -= s15 * 683901 as libc::c_int as int64_t;
    s15 = 0 as libc::c_int as int64_t;
    s2 += s14 * 666643 as libc::c_int as int64_t;
    s3 += s14 * 470296 as libc::c_int as int64_t;
    s4 += s14 * 654183 as libc::c_int as int64_t;
    s5 -= s14 * 997805 as libc::c_int as int64_t;
    s6 += s14 * 136657 as libc::c_int as int64_t;
    s7 -= s14 * 683901 as libc::c_int as int64_t;
    s14 = 0 as libc::c_int as int64_t;
    s1 += s13 * 666643 as libc::c_int as int64_t;
    s2 += s13 * 470296 as libc::c_int as int64_t;
    s3 += s13 * 654183 as libc::c_int as int64_t;
    s4 -= s13 * 997805 as libc::c_int as int64_t;
    s5 += s13 * 136657 as libc::c_int as int64_t;
    s6 -= s13 * 683901 as libc::c_int as int64_t;
    s13 = 0 as libc::c_int as int64_t;
    s0 += s12 * 666643 as libc::c_int as int64_t;
    s1 += s12 * 470296 as libc::c_int as int64_t;
    s2 += s12 * 654183 as libc::c_int as int64_t;
    s3 -= s12 * 997805 as libc::c_int as int64_t;
    s4 += s12 * 136657 as libc::c_int as int64_t;
    s5 -= s12 * 683901 as libc::c_int as int64_t;
    s12 = 0 as libc::c_int as int64_t;
    carry0 = s0 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = s2 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = s4 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = s6 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = s8 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = s10 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry1 = s1 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = s3 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = s5 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = s7 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = s9 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = s11 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    s0 += s12 * 666643 as libc::c_int as int64_t;
    s1 += s12 * 470296 as libc::c_int as int64_t;
    s2 += s12 * 654183 as libc::c_int as int64_t;
    s3 -= s12 * 997805 as libc::c_int as int64_t;
    s4 += s12 * 136657 as libc::c_int as int64_t;
    s5 -= s12 * 683901 as libc::c_int as int64_t;
    s12 = 0 as libc::c_int as int64_t;
    carry0 = s0 >> 21 as libc::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21 as libc::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21 as libc::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21 as libc::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21 as libc::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21 as libc::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry11 = s11 >> 21 as libc::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    s0 += s12 * 666643 as libc::c_int as int64_t;
    s1 += s12 * 470296 as libc::c_int as int64_t;
    s2 += s12 * 654183 as libc::c_int as int64_t;
    s3 -= s12 * 997805 as libc::c_int as int64_t;
    s4 += s12 * 136657 as libc::c_int as int64_t;
    s5 -= s12 * 683901 as libc::c_int as int64_t;
    s12 = 0 as libc::c_int as int64_t;
    carry0 = s0 >> 21 as libc::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21 as libc::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21 as libc::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21 as libc::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21 as libc::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21 as libc::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    *s.offset(0 as libc::c_int as isize) = (s0 >> 0 as libc::c_int) as uint8_t;
    *s.offset(1 as libc::c_int as isize) = (s0 >> 8 as libc::c_int) as uint8_t;
    *s
        .offset(
            2 as libc::c_int as isize,
        ) = (s0 >> 16 as libc::c_int | s1 << 5 as libc::c_int) as uint8_t;
    *s.offset(3 as libc::c_int as isize) = (s1 >> 3 as libc::c_int) as uint8_t;
    *s.offset(4 as libc::c_int as isize) = (s1 >> 11 as libc::c_int) as uint8_t;
    *s
        .offset(
            5 as libc::c_int as isize,
        ) = (s1 >> 19 as libc::c_int | s2 << 2 as libc::c_int) as uint8_t;
    *s.offset(6 as libc::c_int as isize) = (s2 >> 6 as libc::c_int) as uint8_t;
    *s
        .offset(
            7 as libc::c_int as isize,
        ) = (s2 >> 14 as libc::c_int | s3 << 7 as libc::c_int) as uint8_t;
    *s.offset(8 as libc::c_int as isize) = (s3 >> 1 as libc::c_int) as uint8_t;
    *s.offset(9 as libc::c_int as isize) = (s3 >> 9 as libc::c_int) as uint8_t;
    *s
        .offset(
            10 as libc::c_int as isize,
        ) = (s3 >> 17 as libc::c_int | s4 << 4 as libc::c_int) as uint8_t;
    *s.offset(11 as libc::c_int as isize) = (s4 >> 4 as libc::c_int) as uint8_t;
    *s.offset(12 as libc::c_int as isize) = (s4 >> 12 as libc::c_int) as uint8_t;
    *s
        .offset(
            13 as libc::c_int as isize,
        ) = (s4 >> 20 as libc::c_int | s5 << 1 as libc::c_int) as uint8_t;
    *s.offset(14 as libc::c_int as isize) = (s5 >> 7 as libc::c_int) as uint8_t;
    *s
        .offset(
            15 as libc::c_int as isize,
        ) = (s5 >> 15 as libc::c_int | s6 << 6 as libc::c_int) as uint8_t;
    *s.offset(16 as libc::c_int as isize) = (s6 >> 2 as libc::c_int) as uint8_t;
    *s.offset(17 as libc::c_int as isize) = (s6 >> 10 as libc::c_int) as uint8_t;
    *s
        .offset(
            18 as libc::c_int as isize,
        ) = (s6 >> 18 as libc::c_int | s7 << 3 as libc::c_int) as uint8_t;
    *s.offset(19 as libc::c_int as isize) = (s7 >> 5 as libc::c_int) as uint8_t;
    *s.offset(20 as libc::c_int as isize) = (s7 >> 13 as libc::c_int) as uint8_t;
    *s.offset(21 as libc::c_int as isize) = (s8 >> 0 as libc::c_int) as uint8_t;
    *s.offset(22 as libc::c_int as isize) = (s8 >> 8 as libc::c_int) as uint8_t;
    *s
        .offset(
            23 as libc::c_int as isize,
        ) = (s8 >> 16 as libc::c_int | s9 << 5 as libc::c_int) as uint8_t;
    *s.offset(24 as libc::c_int as isize) = (s9 >> 3 as libc::c_int) as uint8_t;
    *s.offset(25 as libc::c_int as isize) = (s9 >> 11 as libc::c_int) as uint8_t;
    *s
        .offset(
            26 as libc::c_int as isize,
        ) = (s9 >> 19 as libc::c_int | s10 << 2 as libc::c_int) as uint8_t;
    *s.offset(27 as libc::c_int as isize) = (s10 >> 6 as libc::c_int) as uint8_t;
    *s
        .offset(
            28 as libc::c_int as isize,
        ) = (s10 >> 14 as libc::c_int | s11 << 7 as libc::c_int) as uint8_t;
    *s.offset(29 as libc::c_int as isize) = (s11 >> 1 as libc::c_int) as uint8_t;
    *s.offset(30 as libc::c_int as isize) = (s11 >> 9 as libc::c_int) as uint8_t;
    *s.offset(31 as libc::c_int as isize) = (s11 >> 17 as libc::c_int) as uint8_t;
}
unsafe extern "C" fn sc_muladd(
    mut s: *mut uint8_t,
    mut a: *const uint8_t,
    mut b: *const uint8_t,
    mut c: *const uint8_t,
) {
    let mut a0: int64_t = (2097151 as libc::c_int as uint64_t & load_3(a)) as int64_t;
    let mut a1: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(a.offset(2 as libc::c_int as isize)) >> 5 as libc::c_int) as int64_t;
    let mut a2: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(a.offset(5 as libc::c_int as isize)) >> 2 as libc::c_int) as int64_t;
    let mut a3: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(a.offset(7 as libc::c_int as isize)) >> 7 as libc::c_int) as int64_t;
    let mut a4: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(a.offset(10 as libc::c_int as isize)) >> 4 as libc::c_int) as int64_t;
    let mut a5: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(a.offset(13 as libc::c_int as isize)) >> 1 as libc::c_int) as int64_t;
    let mut a6: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(a.offset(15 as libc::c_int as isize)) >> 6 as libc::c_int) as int64_t;
    let mut a7: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(a.offset(18 as libc::c_int as isize)) >> 3 as libc::c_int) as int64_t;
    let mut a8: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(a.offset(21 as libc::c_int as isize))) as int64_t;
    let mut a9: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(a.offset(23 as libc::c_int as isize)) >> 5 as libc::c_int) as int64_t;
    let mut a10: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(a.offset(26 as libc::c_int as isize)) >> 2 as libc::c_int) as int64_t;
    let mut a11: int64_t = (load_4(a.offset(28 as libc::c_int as isize))
        >> 7 as libc::c_int) as int64_t;
    let mut b0: int64_t = (2097151 as libc::c_int as uint64_t & load_3(b)) as int64_t;
    let mut b1: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(b.offset(2 as libc::c_int as isize)) >> 5 as libc::c_int) as int64_t;
    let mut b2: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(b.offset(5 as libc::c_int as isize)) >> 2 as libc::c_int) as int64_t;
    let mut b3: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(b.offset(7 as libc::c_int as isize)) >> 7 as libc::c_int) as int64_t;
    let mut b4: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(b.offset(10 as libc::c_int as isize)) >> 4 as libc::c_int) as int64_t;
    let mut b5: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(b.offset(13 as libc::c_int as isize)) >> 1 as libc::c_int) as int64_t;
    let mut b6: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(b.offset(15 as libc::c_int as isize)) >> 6 as libc::c_int) as int64_t;
    let mut b7: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(b.offset(18 as libc::c_int as isize)) >> 3 as libc::c_int) as int64_t;
    let mut b8: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(b.offset(21 as libc::c_int as isize))) as int64_t;
    let mut b9: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(b.offset(23 as libc::c_int as isize)) >> 5 as libc::c_int) as int64_t;
    let mut b10: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(b.offset(26 as libc::c_int as isize)) >> 2 as libc::c_int) as int64_t;
    let mut b11: int64_t = (load_4(b.offset(28 as libc::c_int as isize))
        >> 7 as libc::c_int) as int64_t;
    let mut c0: int64_t = (2097151 as libc::c_int as uint64_t & load_3(c)) as int64_t;
    let mut c1: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(c.offset(2 as libc::c_int as isize)) >> 5 as libc::c_int) as int64_t;
    let mut c2: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(c.offset(5 as libc::c_int as isize)) >> 2 as libc::c_int) as int64_t;
    let mut c3: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(c.offset(7 as libc::c_int as isize)) >> 7 as libc::c_int) as int64_t;
    let mut c4: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(c.offset(10 as libc::c_int as isize)) >> 4 as libc::c_int) as int64_t;
    let mut c5: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(c.offset(13 as libc::c_int as isize)) >> 1 as libc::c_int) as int64_t;
    let mut c6: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(c.offset(15 as libc::c_int as isize)) >> 6 as libc::c_int) as int64_t;
    let mut c7: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(c.offset(18 as libc::c_int as isize)) >> 3 as libc::c_int) as int64_t;
    let mut c8: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(c.offset(21 as libc::c_int as isize))) as int64_t;
    let mut c9: int64_t = (2097151 as libc::c_int as uint64_t
        & load_4(c.offset(23 as libc::c_int as isize)) >> 5 as libc::c_int) as int64_t;
    let mut c10: int64_t = (2097151 as libc::c_int as uint64_t
        & load_3(c.offset(26 as libc::c_int as isize)) >> 2 as libc::c_int) as int64_t;
    let mut c11: int64_t = (load_4(c.offset(28 as libc::c_int as isize))
        >> 7 as libc::c_int) as int64_t;
    let mut s0: int64_t = 0;
    let mut s1: int64_t = 0;
    let mut s2: int64_t = 0;
    let mut s3: int64_t = 0;
    let mut s4: int64_t = 0;
    let mut s5: int64_t = 0;
    let mut s6: int64_t = 0;
    let mut s7: int64_t = 0;
    let mut s8: int64_t = 0;
    let mut s9: int64_t = 0;
    let mut s10: int64_t = 0;
    let mut s11: int64_t = 0;
    let mut s12: int64_t = 0;
    let mut s13: int64_t = 0;
    let mut s14: int64_t = 0;
    let mut s15: int64_t = 0;
    let mut s16: int64_t = 0;
    let mut s17: int64_t = 0;
    let mut s18: int64_t = 0;
    let mut s19: int64_t = 0;
    let mut s20: int64_t = 0;
    let mut s21: int64_t = 0;
    let mut s22: int64_t = 0;
    let mut s23: int64_t = 0;
    let mut carry0: int64_t = 0;
    let mut carry1: int64_t = 0;
    let mut carry2: int64_t = 0;
    let mut carry3: int64_t = 0;
    let mut carry4: int64_t = 0;
    let mut carry5: int64_t = 0;
    let mut carry6: int64_t = 0;
    let mut carry7: int64_t = 0;
    let mut carry8: int64_t = 0;
    let mut carry9: int64_t = 0;
    let mut carry10: int64_t = 0;
    let mut carry11: int64_t = 0;
    let mut carry12: int64_t = 0;
    let mut carry13: int64_t = 0;
    let mut carry14: int64_t = 0;
    let mut carry15: int64_t = 0;
    let mut carry16: int64_t = 0;
    let mut carry17: int64_t = 0;
    let mut carry18: int64_t = 0;
    let mut carry19: int64_t = 0;
    let mut carry20: int64_t = 0;
    let mut carry21: int64_t = 0;
    let mut carry22: int64_t = 0;
    s0 = c0 + a0 * b0;
    s1 = c1 + a0 * b1 + a1 * b0;
    s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1
        + a7 * b0;
    s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2
        + a7 * b1 + a8 * b0;
    s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3
        + a7 * b2 + a8 * b1 + a9 * b0;
    s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4
        + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
    s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5
        + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
    s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4
        + a9 * b3 + a10 * b2 + a11 * b1;
    s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4
        + a10 * b3 + a11 * b2;
    s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5
        + a10 * b4 + a11 * b3;
    s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5
        + a11 * b4;
    s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s20 = a9 * b11 + a10 * b10 + a11 * b9;
    s21 = a10 * b11 + a11 * b10;
    s22 = a11 * b11;
    s23 = 0 as libc::c_int as int64_t;
    carry0 = s0 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = s2 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = s4 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = s6 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = s8 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = s10 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = s12 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = s14 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = s16 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);
    carry18 = s18 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s19 += carry18;
    s18 -= int64_lshift21(carry18);
    carry20 = s20 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s21 += carry20;
    s20 -= int64_lshift21(carry20);
    carry22 = s22 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s23 += carry22;
    s22 -= int64_lshift21(carry22);
    carry1 = s1 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = s3 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = s5 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = s7 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = s9 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = s11 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = s13 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = s15 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);
    carry17 = s17 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s18 += carry17;
    s17 -= int64_lshift21(carry17);
    carry19 = s19 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s20 += carry19;
    s19 -= int64_lshift21(carry19);
    carry21 = s21 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s22 += carry21;
    s21 -= int64_lshift21(carry21);
    s11 += s23 * 666643 as libc::c_int as int64_t;
    s12 += s23 * 470296 as libc::c_int as int64_t;
    s13 += s23 * 654183 as libc::c_int as int64_t;
    s14 -= s23 * 997805 as libc::c_int as int64_t;
    s15 += s23 * 136657 as libc::c_int as int64_t;
    s16 -= s23 * 683901 as libc::c_int as int64_t;
    s23 = 0 as libc::c_int as int64_t;
    s10 += s22 * 666643 as libc::c_int as int64_t;
    s11 += s22 * 470296 as libc::c_int as int64_t;
    s12 += s22 * 654183 as libc::c_int as int64_t;
    s13 -= s22 * 997805 as libc::c_int as int64_t;
    s14 += s22 * 136657 as libc::c_int as int64_t;
    s15 -= s22 * 683901 as libc::c_int as int64_t;
    s22 = 0 as libc::c_int as int64_t;
    s9 += s21 * 666643 as libc::c_int as int64_t;
    s10 += s21 * 470296 as libc::c_int as int64_t;
    s11 += s21 * 654183 as libc::c_int as int64_t;
    s12 -= s21 * 997805 as libc::c_int as int64_t;
    s13 += s21 * 136657 as libc::c_int as int64_t;
    s14 -= s21 * 683901 as libc::c_int as int64_t;
    s21 = 0 as libc::c_int as int64_t;
    s8 += s20 * 666643 as libc::c_int as int64_t;
    s9 += s20 * 470296 as libc::c_int as int64_t;
    s10 += s20 * 654183 as libc::c_int as int64_t;
    s11 -= s20 * 997805 as libc::c_int as int64_t;
    s12 += s20 * 136657 as libc::c_int as int64_t;
    s13 -= s20 * 683901 as libc::c_int as int64_t;
    s20 = 0 as libc::c_int as int64_t;
    s7 += s19 * 666643 as libc::c_int as int64_t;
    s8 += s19 * 470296 as libc::c_int as int64_t;
    s9 += s19 * 654183 as libc::c_int as int64_t;
    s10 -= s19 * 997805 as libc::c_int as int64_t;
    s11 += s19 * 136657 as libc::c_int as int64_t;
    s12 -= s19 * 683901 as libc::c_int as int64_t;
    s19 = 0 as libc::c_int as int64_t;
    s6 += s18 * 666643 as libc::c_int as int64_t;
    s7 += s18 * 470296 as libc::c_int as int64_t;
    s8 += s18 * 654183 as libc::c_int as int64_t;
    s9 -= s18 * 997805 as libc::c_int as int64_t;
    s10 += s18 * 136657 as libc::c_int as int64_t;
    s11 -= s18 * 683901 as libc::c_int as int64_t;
    s18 = 0 as libc::c_int as int64_t;
    carry6 = s6 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = s8 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = s10 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = s12 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = s14 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = s16 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);
    carry7 = s7 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = s9 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = s11 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = s13 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = s15 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);
    s5 += s17 * 666643 as libc::c_int as int64_t;
    s6 += s17 * 470296 as libc::c_int as int64_t;
    s7 += s17 * 654183 as libc::c_int as int64_t;
    s8 -= s17 * 997805 as libc::c_int as int64_t;
    s9 += s17 * 136657 as libc::c_int as int64_t;
    s10 -= s17 * 683901 as libc::c_int as int64_t;
    s17 = 0 as libc::c_int as int64_t;
    s4 += s16 * 666643 as libc::c_int as int64_t;
    s5 += s16 * 470296 as libc::c_int as int64_t;
    s6 += s16 * 654183 as libc::c_int as int64_t;
    s7 -= s16 * 997805 as libc::c_int as int64_t;
    s8 += s16 * 136657 as libc::c_int as int64_t;
    s9 -= s16 * 683901 as libc::c_int as int64_t;
    s16 = 0 as libc::c_int as int64_t;
    s3 += s15 * 666643 as libc::c_int as int64_t;
    s4 += s15 * 470296 as libc::c_int as int64_t;
    s5 += s15 * 654183 as libc::c_int as int64_t;
    s6 -= s15 * 997805 as libc::c_int as int64_t;
    s7 += s15 * 136657 as libc::c_int as int64_t;
    s8 -= s15 * 683901 as libc::c_int as int64_t;
    s15 = 0 as libc::c_int as int64_t;
    s2 += s14 * 666643 as libc::c_int as int64_t;
    s3 += s14 * 470296 as libc::c_int as int64_t;
    s4 += s14 * 654183 as libc::c_int as int64_t;
    s5 -= s14 * 997805 as libc::c_int as int64_t;
    s6 += s14 * 136657 as libc::c_int as int64_t;
    s7 -= s14 * 683901 as libc::c_int as int64_t;
    s14 = 0 as libc::c_int as int64_t;
    s1 += s13 * 666643 as libc::c_int as int64_t;
    s2 += s13 * 470296 as libc::c_int as int64_t;
    s3 += s13 * 654183 as libc::c_int as int64_t;
    s4 -= s13 * 997805 as libc::c_int as int64_t;
    s5 += s13 * 136657 as libc::c_int as int64_t;
    s6 -= s13 * 683901 as libc::c_int as int64_t;
    s13 = 0 as libc::c_int as int64_t;
    s0 += s12 * 666643 as libc::c_int as int64_t;
    s1 += s12 * 470296 as libc::c_int as int64_t;
    s2 += s12 * 654183 as libc::c_int as int64_t;
    s3 -= s12 * 997805 as libc::c_int as int64_t;
    s4 += s12 * 136657 as libc::c_int as int64_t;
    s5 -= s12 * 683901 as libc::c_int as int64_t;
    s12 = 0 as libc::c_int as int64_t;
    carry0 = s0 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = s2 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = s4 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = s6 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = s8 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = s10 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry1 = s1 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = s3 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = s5 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = s7 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = s9 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = s11 + ((1 as libc::c_int) << 20 as libc::c_int) as int64_t
        >> 21 as libc::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    s0 += s12 * 666643 as libc::c_int as int64_t;
    s1 += s12 * 470296 as libc::c_int as int64_t;
    s2 += s12 * 654183 as libc::c_int as int64_t;
    s3 -= s12 * 997805 as libc::c_int as int64_t;
    s4 += s12 * 136657 as libc::c_int as int64_t;
    s5 -= s12 * 683901 as libc::c_int as int64_t;
    s12 = 0 as libc::c_int as int64_t;
    carry0 = s0 >> 21 as libc::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21 as libc::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21 as libc::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21 as libc::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21 as libc::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21 as libc::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry11 = s11 >> 21 as libc::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    s0 += s12 * 666643 as libc::c_int as int64_t;
    s1 += s12 * 470296 as libc::c_int as int64_t;
    s2 += s12 * 654183 as libc::c_int as int64_t;
    s3 -= s12 * 997805 as libc::c_int as int64_t;
    s4 += s12 * 136657 as libc::c_int as int64_t;
    s5 -= s12 * 683901 as libc::c_int as int64_t;
    s12 = 0 as libc::c_int as int64_t;
    carry0 = s0 >> 21 as libc::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21 as libc::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21 as libc::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21 as libc::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21 as libc::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21 as libc::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21 as libc::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21 as libc::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21 as libc::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21 as libc::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21 as libc::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    *s.offset(0 as libc::c_int as isize) = (s0 >> 0 as libc::c_int) as uint8_t;
    *s.offset(1 as libc::c_int as isize) = (s0 >> 8 as libc::c_int) as uint8_t;
    *s
        .offset(
            2 as libc::c_int as isize,
        ) = (s0 >> 16 as libc::c_int | s1 << 5 as libc::c_int) as uint8_t;
    *s.offset(3 as libc::c_int as isize) = (s1 >> 3 as libc::c_int) as uint8_t;
    *s.offset(4 as libc::c_int as isize) = (s1 >> 11 as libc::c_int) as uint8_t;
    *s
        .offset(
            5 as libc::c_int as isize,
        ) = (s1 >> 19 as libc::c_int | s2 << 2 as libc::c_int) as uint8_t;
    *s.offset(6 as libc::c_int as isize) = (s2 >> 6 as libc::c_int) as uint8_t;
    *s
        .offset(
            7 as libc::c_int as isize,
        ) = (s2 >> 14 as libc::c_int | s3 << 7 as libc::c_int) as uint8_t;
    *s.offset(8 as libc::c_int as isize) = (s3 >> 1 as libc::c_int) as uint8_t;
    *s.offset(9 as libc::c_int as isize) = (s3 >> 9 as libc::c_int) as uint8_t;
    *s
        .offset(
            10 as libc::c_int as isize,
        ) = (s3 >> 17 as libc::c_int | s4 << 4 as libc::c_int) as uint8_t;
    *s.offset(11 as libc::c_int as isize) = (s4 >> 4 as libc::c_int) as uint8_t;
    *s.offset(12 as libc::c_int as isize) = (s4 >> 12 as libc::c_int) as uint8_t;
    *s
        .offset(
            13 as libc::c_int as isize,
        ) = (s4 >> 20 as libc::c_int | s5 << 1 as libc::c_int) as uint8_t;
    *s.offset(14 as libc::c_int as isize) = (s5 >> 7 as libc::c_int) as uint8_t;
    *s
        .offset(
            15 as libc::c_int as isize,
        ) = (s5 >> 15 as libc::c_int | s6 << 6 as libc::c_int) as uint8_t;
    *s.offset(16 as libc::c_int as isize) = (s6 >> 2 as libc::c_int) as uint8_t;
    *s.offset(17 as libc::c_int as isize) = (s6 >> 10 as libc::c_int) as uint8_t;
    *s
        .offset(
            18 as libc::c_int as isize,
        ) = (s6 >> 18 as libc::c_int | s7 << 3 as libc::c_int) as uint8_t;
    *s.offset(19 as libc::c_int as isize) = (s7 >> 5 as libc::c_int) as uint8_t;
    *s.offset(20 as libc::c_int as isize) = (s7 >> 13 as libc::c_int) as uint8_t;
    *s.offset(21 as libc::c_int as isize) = (s8 >> 0 as libc::c_int) as uint8_t;
    *s.offset(22 as libc::c_int as isize) = (s8 >> 8 as libc::c_int) as uint8_t;
    *s
        .offset(
            23 as libc::c_int as isize,
        ) = (s8 >> 16 as libc::c_int | s9 << 5 as libc::c_int) as uint8_t;
    *s.offset(24 as libc::c_int as isize) = (s9 >> 3 as libc::c_int) as uint8_t;
    *s.offset(25 as libc::c_int as isize) = (s9 >> 11 as libc::c_int) as uint8_t;
    *s
        .offset(
            26 as libc::c_int as isize,
        ) = (s9 >> 19 as libc::c_int | s10 << 2 as libc::c_int) as uint8_t;
    *s.offset(27 as libc::c_int as isize) = (s10 >> 6 as libc::c_int) as uint8_t;
    *s
        .offset(
            28 as libc::c_int as isize,
        ) = (s10 >> 14 as libc::c_int | s11 << 7 as libc::c_int) as uint8_t;
    *s.offset(29 as libc::c_int as isize) = (s11 >> 1 as libc::c_int) as uint8_t;
    *s.offset(30 as libc::c_int as isize) = (s11 >> 9 as libc::c_int) as uint8_t;
    *s.offset(31 as libc::c_int as isize) = (s11 >> 17 as libc::c_int) as uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn x25519_scalar_mult_generic_nohw(
    mut out_shared_key: *mut uint8_t,
    mut private_key: *const uint8_t,
    mut peer_public_value: *const uint8_t,
) {
    let mut x1: fe = fe { v: [0; 5] };
    let mut x2: fe = fe { v: [0; 5] };
    let mut z2: fe = fe { v: [0; 5] };
    let mut x3: fe = fe { v: [0; 5] };
    let mut z3: fe = fe { v: [0; 5] };
    let mut tmp0: fe = fe { v: [0; 5] };
    let mut tmp1: fe = fe { v: [0; 5] };
    let mut x2l: fe_loose = fe_loose { v: [0; 5] };
    let mut z2l: fe_loose = fe_loose { v: [0; 5] };
    let mut x3l: fe_loose = fe_loose { v: [0; 5] };
    let mut tmp0l: fe_loose = fe_loose { v: [0; 5] };
    let mut tmp1l: fe_loose = fe_loose { v: [0; 5] };
    let mut e: [uint8_t; 32] = [0; 32];
    OPENSSL_memcpy(
        e.as_mut_ptr() as *mut libc::c_void,
        private_key as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    e[0 as libc::c_int
        as usize] = (e[0 as libc::c_int as usize] as libc::c_int & 248 as libc::c_int)
        as uint8_t;
    e[31 as libc::c_int
        as usize] = (e[31 as libc::c_int as usize] as libc::c_int & 127 as libc::c_int)
        as uint8_t;
    e[31 as libc::c_int
        as usize] = (e[31 as libc::c_int as usize] as libc::c_int | 64 as libc::c_int)
        as uint8_t;
    fe_frombytes(&mut x1, peer_public_value);
    fe_1(&mut x2);
    fe_0(&mut z2);
    fe_copy(&mut x3, &mut x1);
    fe_1(&mut z3);
    let mut swap: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut pos: libc::c_int = 0;
    pos = 254 as libc::c_int;
    while pos >= 0 as libc::c_int {
        let mut b: libc::c_uint = (1 as libc::c_int
            & e[(pos / 8 as libc::c_int) as usize] as libc::c_int
                >> (pos & 7 as libc::c_int)) as libc::c_uint;
        swap ^= b;
        fe_cswap(&mut x2, &mut x3, swap as fe_limb_t);
        fe_cswap(&mut z2, &mut z3, swap as fe_limb_t);
        swap = b;
        fe_sub(&mut tmp0l, &mut x3, &mut z3);
        fe_sub(&mut tmp1l, &mut x2, &mut z2);
        fe_add(&mut x2l, &mut x2, &mut z2);
        fe_add(&mut z2l, &mut x3, &mut z3);
        fe_mul_tll(&mut z3, &mut tmp0l, &mut x2l);
        fe_mul_tll(&mut z2, &mut z2l, &mut tmp1l);
        fe_sq_tl(&mut tmp0, &mut tmp1l);
        fe_sq_tl(&mut tmp1, &mut x2l);
        fe_add(&mut x3l, &mut z3, &mut z2);
        fe_sub(&mut z2l, &mut z3, &mut z2);
        fe_mul_ttt(&mut x2, &mut tmp1, &mut tmp0);
        fe_sub(&mut tmp1l, &mut tmp1, &mut tmp0);
        fe_sq_tl(&mut z2, &mut z2l);
        fe_mul121666(&mut z3, &mut tmp1l);
        fe_sq_tl(&mut x3, &mut x3l);
        fe_add(&mut tmp0l, &mut tmp0, &mut z3);
        fe_mul_ttt(&mut z3, &mut x1, &mut z2);
        fe_mul_tll(&mut z2, &mut tmp1l, &mut tmp0l);
        pos -= 1;
        pos;
    }
    fe_cswap(&mut x2, &mut x3, swap as fe_limb_t);
    fe_cswap(&mut z2, &mut z3, swap as fe_limb_t);
    fe_invert(&mut z2, &mut z2);
    fe_mul_ttt(&mut x2, &mut x2, &mut z2);
    fe_tobytes(out_shared_key, &mut x2);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_public_from_private_nohw(
    mut out_public_value: *mut uint8_t,
    mut private_key: *const uint8_t,
) {
    let mut e: [uint8_t; 32] = [0; 32];
    OPENSSL_memcpy(
        e.as_mut_ptr() as *mut libc::c_void,
        private_key as *const libc::c_void,
        32 as libc::c_int as size_t,
    );
    e[0 as libc::c_int
        as usize] = (e[0 as libc::c_int as usize] as libc::c_int & 248 as libc::c_int)
        as uint8_t;
    e[31 as libc::c_int
        as usize] = (e[31 as libc::c_int as usize] as libc::c_int & 127 as libc::c_int)
        as uint8_t;
    e[31 as libc::c_int
        as usize] = (e[31 as libc::c_int as usize] as libc::c_int | 64 as libc::c_int)
        as uint8_t;
    let mut A: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    x25519_ge_scalarmult_base(&mut A, e.as_mut_ptr() as *const uint8_t);
    let mut zplusy: fe_loose = fe_loose { v: [0; 5] };
    let mut zminusy: fe_loose = fe_loose { v: [0; 5] };
    let mut zminusy_inv: fe = fe { v: [0; 5] };
    fe_add(&mut zplusy, &mut A.Z, &mut A.Y);
    fe_sub(&mut zminusy, &mut A.Z, &mut A.Y);
    fe_loose_invert(&mut zminusy_inv, &mut zminusy);
    fe_mul_tlt(&mut zminusy_inv, &mut zplusy, &mut zminusy_inv);
    fe_tobytes(out_public_value, &mut zminusy_inv);
}
#[no_mangle]
pub unsafe extern "C" fn ed25519_public_key_from_hashed_seed_nohw(
    mut out_public_key: *mut uint8_t,
    mut az: *mut uint8_t,
) {
    let mut A: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    x25519_ge_scalarmult_base(&mut A, az as *const uint8_t);
    ge_p3_tobytes(out_public_key, &mut A);
}
#[no_mangle]
pub unsafe extern "C" fn ed25519_sign_nohw(
    mut out_sig: *mut uint8_t,
    mut r: *mut uint8_t,
    mut s: *const uint8_t,
    mut A: *const uint8_t,
    mut message: *const libc::c_void,
    mut message_len: size_t,
    mut dom2: *const uint8_t,
    mut dom2_len: size_t,
) {
    x25519_sc_reduce(r);
    let mut R: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    x25519_ge_scalarmult_base(&mut R, r as *const uint8_t);
    ge_p3_tobytes(out_sig, &mut R);
    let mut k: [uint8_t; 64] = [0; 64];
    if dom2_len > 0 as libc::c_int as size_t {
        ed25519_sha512(
            k.as_mut_ptr(),
            dom2 as *const libc::c_void,
            dom2_len,
            out_sig as *const libc::c_void,
            32 as libc::c_int as size_t,
            A as *const libc::c_void,
            32 as libc::c_int as size_t,
            message,
            message_len,
        );
    } else {
        ed25519_sha512(
            k.as_mut_ptr(),
            out_sig as *const libc::c_void,
            32 as libc::c_int as size_t,
            A as *const libc::c_void,
            32 as libc::c_int as size_t,
            message,
            message_len,
            0 as *const libc::c_void,
            0 as libc::c_int as size_t,
        );
    }
    x25519_sc_reduce(k.as_mut_ptr());
    sc_muladd(
        out_sig.offset(32 as libc::c_int as isize),
        k.as_mut_ptr(),
        s,
        r as *const uint8_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn ed25519_verify_nohw(
    mut R_computed_encoded: *mut uint8_t,
    mut public_key: *const uint8_t,
    mut R_expected: *mut uint8_t,
    mut S: *mut uint8_t,
    mut message: *const uint8_t,
    mut message_len: size_t,
    mut dom2: *const uint8_t,
    mut dom2_len: size_t,
) -> libc::c_int {
    let mut A: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    if x25519_ge_frombytes_vartime(&mut A, public_key) == 0 {
        return 0 as libc::c_int;
    }
    let mut k: [uint8_t; 64] = [0; 64];
    if dom2_len > 0 as libc::c_int as size_t {
        ed25519_sha512(
            k.as_mut_ptr(),
            dom2 as *const libc::c_void,
            dom2_len,
            R_expected as *const libc::c_void,
            32 as libc::c_int as size_t,
            public_key as *const libc::c_void,
            32 as libc::c_int as size_t,
            message as *const libc::c_void,
            message_len,
        );
    } else {
        ed25519_sha512(
            k.as_mut_ptr(),
            R_expected as *const libc::c_void,
            32 as libc::c_int as size_t,
            public_key as *const libc::c_void,
            32 as libc::c_int as size_t,
            message as *const libc::c_void,
            message_len,
            0 as *const libc::c_void,
            0 as libc::c_int as size_t,
        );
    }
    x25519_sc_reduce(k.as_mut_ptr());
    let mut t: fe_loose = fe_loose { v: [0; 5] };
    fe_neg(&mut t, &mut A.X);
    fe_carry(&mut A.X, &mut t);
    fe_neg(&mut t, &mut A.T);
    fe_carry(&mut A.T, &mut t);
    let mut R_computed: ge_p2 = ge_p2 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
    };
    ge_double_scalarmult_vartime(
        &mut R_computed,
        k.as_mut_ptr(),
        &mut A,
        S as *const uint8_t,
    );
    x25519_ge_tobytes(R_computed_encoded, &mut R_computed);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ed25519_check_public_key_nohw(
    mut public_key: *const uint8_t,
) -> libc::c_int {
    let mut A: ge_p3 = ge_p3 {
        X: fe { v: [0; 5] },
        Y: fe { v: [0; 5] },
        Z: fe { v: [0; 5] },
        T: fe { v: [0; 5] },
    };
    if x25519_ge_frombytes_vartime(&mut A, public_key) == 0 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
