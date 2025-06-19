#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nid_triple {
    pub sign_nid: libc::c_int,
    pub digest_nid: libc::c_int,
    pub pkey_nid: libc::c_int,
}
static mut kTriples: [nid_triple; 23] = [
    {
        let mut init = nid_triple {
            sign_nid: 396 as libc::c_int,
            digest_nid: 257 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 8 as libc::c_int,
            digest_nid: 4 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 65 as libc::c_int,
            digest_nid: 64 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 671 as libc::c_int,
            digest_nid: 675 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 668 as libc::c_int,
            digest_nid: 672 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 669 as libc::c_int,
            digest_nid: 673 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 670 as libc::c_int,
            digest_nid: 674 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 104 as libc::c_int,
            digest_nid: 4 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 115 as libc::c_int,
            digest_nid: 64 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 113 as libc::c_int,
            digest_nid: 64 as libc::c_int,
            pkey_nid: 116 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 70 as libc::c_int,
            digest_nid: 64 as libc::c_int,
            pkey_nid: 67 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 802 as libc::c_int,
            digest_nid: 675 as libc::c_int,
            pkey_nid: 116 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 803 as libc::c_int,
            digest_nid: 672 as libc::c_int,
            pkey_nid: 116 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 416 as libc::c_int,
            digest_nid: 64 as libc::c_int,
            pkey_nid: 408 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 793 as libc::c_int,
            digest_nid: 675 as libc::c_int,
            pkey_nid: 408 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 794 as libc::c_int,
            digest_nid: 672 as libc::c_int,
            pkey_nid: 408 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 795 as libc::c_int,
            digest_nid: 673 as libc::c_int,
            pkey_nid: 408 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 796 as libc::c_int,
            digest_nid: 674 as libc::c_int,
            pkey_nid: 408 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 912 as libc::c_int,
            digest_nid: 0 as libc::c_int,
            pkey_nid: 6 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 949 as libc::c_int,
            digest_nid: 0 as libc::c_int,
            pkey_nid: 949 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 994 as libc::c_int,
            digest_nid: 0 as libc::c_int,
            pkey_nid: 994 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 995 as libc::c_int,
            digest_nid: 0 as libc::c_int,
            pkey_nid: 995 as libc::c_int,
        };
        init
    },
    {
        let mut init = nid_triple {
            sign_nid: 996 as libc::c_int,
            digest_nid: 0 as libc::c_int,
            pkey_nid: 996 as libc::c_int,
        };
        init
    },
];
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_find_sigid_algs(
    mut sign_nid: libc::c_int,
    mut out_digest_nid: *mut libc::c_int,
    mut out_pkey_nid: *mut libc::c_int,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[nid_triple; 23]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<nid_triple>() as libc::c_ulong)
    {
        if kTriples[i as usize].sign_nid == sign_nid {
            if !out_digest_nid.is_null() {
                *out_digest_nid = kTriples[i as usize].digest_nid;
            }
            if !out_pkey_nid.is_null() {
                *out_pkey_nid = kTriples[i as usize].pkey_nid;
            }
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OBJ_find_sigid_by_algs(
    mut out_sign_nid: *mut libc::c_int,
    mut digest_nid: libc::c_int,
    mut pkey_nid: libc::c_int,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[nid_triple; 23]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<nid_triple>() as libc::c_ulong)
    {
        if kTriples[i as usize].digest_nid == digest_nid
            && kTriples[i as usize].pkey_nid == pkey_nid
        {
            if !out_sign_nid.is_null() {
                *out_sign_nid = kTriples[i as usize].sign_nid;
            }
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
