#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
unsafe extern "C" {
    pub type evp_pkey_ctx_st;
    fn BLAKE2B256_Init(b2b: *mut BLAKE2B_CTX);
    fn BLAKE2B256_Update(b2b: *mut BLAKE2B_CTX, data: *const libc::c_void, len: size_t);
    fn BLAKE2B256_Final(out: *mut uint8_t, b2b: *mut BLAKE2B_CTX);
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn EVP_md4() -> *const EVP_MD;
    fn EVP_md5() -> *const EVP_MD;
    fn EVP_ripemd160() -> *const EVP_MD;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha224() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_sha384() -> *const EVP_MD;
    fn EVP_sha512() -> *const EVP_MD;
    fn EVP_sha512_224() -> *const EVP_MD;
    fn EVP_sha512_256() -> *const EVP_MD;
    fn EVP_sha3_224() -> *const EVP_MD;
    fn EVP_sha3_256() -> *const EVP_MD;
    fn EVP_sha3_384() -> *const EVP_MD;
    fn EVP_sha3_512() -> *const EVP_MD;
    fn EVP_shake128() -> *const EVP_MD;
    fn EVP_shake256() -> *const EVP_MD;
    fn EVP_md5_sha1() -> *const EVP_MD;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn OBJ_get0_data(obj: *const ASN1_OBJECT) -> *const uint8_t;
    fn OBJ_length(obj: *const ASN1_OBJECT) -> size_t;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type CBS_ASN1_TAG = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_object_st {
    pub sn: *const libc::c_char,
    pub ln: *const libc::c_char,
    pub nid: libc::c_int,
    pub length: libc::c_int,
    pub data: *const libc::c_uchar,
    pub flags: libc::c_int,
}
pub type ASN1_OBJECT = asn1_object_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct blake2b_state_st {
    pub h: [uint64_t; 8],
    pub t_low: uint64_t,
    pub t_high: uint64_t,
    pub block: [uint8_t; 128],
    pub block_used: size_t,
}
pub type BLAKE2B_CTX = blake2b_state_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub base: cbb_buffer_st,
    pub child: cbb_child_st,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_child_st {
    pub base: *mut cbb_buffer_st,
    pub offset: size_t,
    pub pending_len_len: uint8_t,
    #[bitfield(name = "pending_is_asn1", ty = "libc::c_uint", bits = "0..=0")]
    pub pending_is_asn1: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct cbb_buffer_st {
    pub buf: *mut uint8_t,
    pub len: size_t,
    pub cap: size_t,
    #[bitfield(name = "can_resize", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "error", ty = "libc::c_uint", bits = "1..=1")]
    pub can_resize_error: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type CBB = cbb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_ctx_st {
    pub digest: *const EVP_MD,
    pub md_data: *mut libc::c_void,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub pctx: *mut EVP_PKEY_CTX,
    pub pctx_ops: *const evp_md_pctx_ops,
    pub flags: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_md_pctx_ops {
    pub free: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> ()>,
    pub dup: Option::<unsafe extern "C" fn(*mut EVP_PKEY_CTX) -> *mut EVP_PKEY_CTX>,
}
pub type EVP_PKEY_CTX = evp_pkey_ctx_st;
pub type EVP_MD_CTX = env_md_ctx_st;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_st {
    pub type_0: libc::c_int,
    pub md_size: libc::c_uint,
    pub flags: uint32_t,
    pub init: Option::<unsafe extern "C" fn(*mut EVP_MD_CTX) -> ()>,
    pub update: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *const libc::c_void, size_t) -> libc::c_int,
    >,
    pub final_0: Option::<unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> ()>,
    pub block_size: libc::c_uint,
    pub ctx_size: libc::c_uint,
    pub finalXOF: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> libc::c_int,
    >,
    pub squeezeXOF: Option::<
        unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t, size_t) -> (),
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nid_to_digest {
    pub nid: libc::c_int,
    pub md_func: Option::<unsafe extern "C" fn() -> *const EVP_MD>,
    pub short_name: *const libc::c_char,
    pub long_name: *const libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub oid: [uint8_t; 9],
    pub oid_len: uint8_t,
    pub nid: libc::c_int,
}
#[inline]
unsafe extern "C" fn OPENSSL_memcmp(
    mut s1: *const libc::c_void,
    mut s2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    if n == 0 as libc::c_int as size_t {
        return 0 as libc::c_int;
    }
    return memcmp(s1, s2, n);
}
static mut nid_to_digest_mapping: [nid_to_digest; 26] = unsafe {
    [
        {
            let mut init = nid_to_digest {
                nid: 257 as libc::c_int,
                md_func: Some(EVP_md4 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"MD4\0" as *const u8 as *const libc::c_char,
                long_name: b"md4\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 4 as libc::c_int,
                md_func: Some(EVP_md5 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"MD5\0" as *const u8 as *const libc::c_char,
                long_name: b"md5\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 117 as libc::c_int,
                md_func: Some(EVP_ripemd160 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"RIPEMD160\0" as *const u8 as *const libc::c_char,
                long_name: b"ripemd160\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 64 as libc::c_int,
                md_func: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA1\0" as *const u8 as *const libc::c_char,
                long_name: b"sha1\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 675 as libc::c_int,
                md_func: Some(EVP_sha224 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA224\0" as *const u8 as *const libc::c_char,
                long_name: b"sha224\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 672 as libc::c_int,
                md_func: Some(EVP_sha256 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA256\0" as *const u8 as *const libc::c_char,
                long_name: b"sha256\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 673 as libc::c_int,
                md_func: Some(EVP_sha384 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA384\0" as *const u8 as *const libc::c_char,
                long_name: b"sha384\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 674 as libc::c_int,
                md_func: Some(EVP_sha512 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA512\0" as *const u8 as *const libc::c_char,
                long_name: b"sha512\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 978 as libc::c_int,
                md_func: Some(EVP_sha512_224 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA512-224\0" as *const u8 as *const libc::c_char,
                long_name: b"sha512-224\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 962 as libc::c_int,
                md_func: Some(EVP_sha512_256 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA512-256\0" as *const u8 as *const libc::c_char,
                long_name: b"sha512-256\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 965 as libc::c_int,
                md_func: Some(EVP_sha3_224 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA3-224\0" as *const u8 as *const libc::c_char,
                long_name: b"sha3-224\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 966 as libc::c_int,
                md_func: Some(EVP_sha3_256 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA3-256\0" as *const u8 as *const libc::c_char,
                long_name: b"sha3-256\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 967 as libc::c_int,
                md_func: Some(EVP_sha3_384 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA3-384\0" as *const u8 as *const libc::c_char,
                long_name: b"sha3-384\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 968 as libc::c_int,
                md_func: Some(EVP_sha3_512 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHA3-512\0" as *const u8 as *const libc::c_char,
                long_name: b"sha3-512\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 979 as libc::c_int,
                md_func: Some(EVP_shake128 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHAKE128\0" as *const u8 as *const libc::c_char,
                long_name: b"shake128\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 980 as libc::c_int,
                md_func: Some(EVP_shake256 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"SHAKE256\0" as *const u8 as *const libc::c_char,
                long_name: b"shake256\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 114 as libc::c_int,
                md_func: Some(EVP_md5_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"MD5-SHA1\0" as *const u8 as *const libc::c_char,
                long_name: b"md5-sha1\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"DSA-SHA\0" as *const u8 as *const libc::c_char,
                long_name: b"dsaWithSHA\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"DSA-SHA1\0" as *const u8 as *const libc::c_char,
                long_name: b"dsaWithSHA1\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"ecdsa-with-SHA1\0" as *const u8 as *const libc::c_char,
                long_name: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_md5 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"RSA-MD5\0" as *const u8 as *const libc::c_char,
                long_name: b"md5WithRSAEncryption\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_sha1 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"RSA-SHA1\0" as *const u8 as *const libc::c_char,
                long_name: b"sha1WithRSAEncryption\0" as *const u8 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_sha224 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"RSA-SHA224\0" as *const u8 as *const libc::c_char,
                long_name: b"sha224WithRSAEncryption\0" as *const u8
                    as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_sha256 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"RSA-SHA256\0" as *const u8 as *const libc::c_char,
                long_name: b"sha256WithRSAEncryption\0" as *const u8
                    as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_sha384 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"RSA-SHA384\0" as *const u8 as *const libc::c_char,
                long_name: b"sha384WithRSAEncryption\0" as *const u8
                    as *const libc::c_char,
            };
            init
        },
        {
            let mut init = nid_to_digest {
                nid: 0 as libc::c_int,
                md_func: Some(EVP_sha512 as unsafe extern "C" fn() -> *const EVP_MD),
                short_name: b"RSA-SHA512\0" as *const u8 as *const libc::c_char,
                long_name: b"sha512WithRSAEncryption\0" as *const u8
                    as *const libc::c_char,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_get_digestbynid(mut nid: libc::c_int) -> *const EVP_MD {
    if nid == 0 as libc::c_int {
        return 0 as *const EVP_MD;
    }
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::core::mem::size_of::<[nid_to_digest; 26]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<nid_to_digest>() as libc::c_ulong)
    {
        if nid_to_digest_mapping[i as usize].nid == nid {
            return (nid_to_digest_mapping[i as usize].md_func)
                .expect("non-null function pointer")();
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_MD;
}
static mut kMDOIDs: [C2RustUnnamed_0; 8] = [
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0xf7 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0,
            ],
            oid_len: 8 as libc::c_int as uint8_t,
            nid: 257 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x2a as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0xf7 as libc::c_int as uint8_t,
                0xd as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x5 as libc::c_int as uint8_t,
                0,
            ],
            oid_len: 8 as libc::c_int as uint8_t,
            nid: 4 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x2b as libc::c_int as uint8_t,
                0x24 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0,
                0,
                0,
                0,
            ],
            oid_len: 5 as libc::c_int as uint8_t,
            nid: 117 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x2b as libc::c_int as uint8_t,
                0xe as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x1a as libc::c_int as uint8_t,
                0,
                0,
                0,
                0,
            ],
            oid_len: 5 as libc::c_int as uint8_t,
            nid: 64 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            nid: 672 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            nid: 673 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            nid: 674 as libc::c_int,
        };
        init
    },
    {
        let mut init = C2RustUnnamed_0 {
            oid: [
                0x60 as libc::c_int as uint8_t,
                0x86 as libc::c_int as uint8_t,
                0x48 as libc::c_int as uint8_t,
                0x1 as libc::c_int as uint8_t,
                0x65 as libc::c_int as uint8_t,
                0x3 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
                0x2 as libc::c_int as uint8_t,
                0x4 as libc::c_int as uint8_t,
            ],
            oid_len: 9 as libc::c_int as uint8_t,
            nid: 675 as libc::c_int,
        };
        init
    },
];
unsafe extern "C" fn cbs_to_md(mut cbs: *const CBS) -> *const EVP_MD {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[C2RustUnnamed_0; 8]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<C2RustUnnamed_0>() as libc::c_ulong)
    {
        if CBS_len(cbs) == kMDOIDs[i as usize].oid_len as size_t
            && OPENSSL_memcmp(
                CBS_data(cbs) as *const libc::c_void,
                (kMDOIDs[i as usize].oid).as_ptr() as *const libc::c_void,
                kMDOIDs[i as usize].oid_len as size_t,
            ) == 0 as libc::c_int
        {
            return EVP_get_digestbynid(kMDOIDs[i as usize].nid);
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_MD;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_get_digestbyobj(
    mut obj: *const ASN1_OBJECT,
) -> *const EVP_MD {
    if obj.is_null() {
        return 0 as *const EVP_MD;
    }
    if (*obj).nid != 0 as libc::c_int {
        return EVP_get_digestbynid((*obj).nid);
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, OBJ_get0_data(obj), OBJ_length(obj));
    return cbs_to_md(&mut cbs);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_parse_digest_algorithm(mut cbs: *mut CBS) -> *const EVP_MD {
    let mut algorithm: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut oid: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut algorithm,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_get_asn1(&mut algorithm, &mut oid, 0x6 as libc::c_uint) == 0
    {
        ERR_put_error(
            29 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/digest_extra/digest_extra.c\0"
                as *const u8 as *const libc::c_char,
            186 as libc::c_int as libc::c_uint,
        );
        return 0 as *const EVP_MD;
    }
    let mut ret: *const EVP_MD = cbs_to_md(&mut oid);
    if ret.is_null() {
        ERR_put_error(
            29 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/digest_extra/digest_extra.c\0"
                as *const u8 as *const libc::c_char,
            192 as libc::c_int as libc::c_uint,
        );
        return 0 as *const EVP_MD;
    }
    if CBS_len(&mut algorithm) > 0 as libc::c_int as size_t {
        let mut param: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(&mut algorithm, &mut param, 0x5 as libc::c_uint) == 0
            || CBS_len(&mut param) != 0 as libc::c_int as size_t
            || CBS_len(&mut algorithm) != 0 as libc::c_int as size_t
        {
            ERR_put_error(
                29 as libc::c_int,
                0 as libc::c_int,
                101 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/digest_extra/digest_extra.c\0"
                    as *const u8 as *const libc::c_char,
                205 as libc::c_int as libc::c_uint,
            );
            return 0 as *const EVP_MD;
        }
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_marshal_digest_algorithm(
    mut cbb: *mut CBB,
    mut md: *const EVP_MD,
) -> libc::c_int {
    let mut algorithm: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut oid: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut null: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_add_asn1(
        cbb,
        &mut algorithm,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1(&mut algorithm, &mut oid, 0x6 as libc::c_uint) == 0
    {
        return 0 as libc::c_int;
    }
    let mut found: libc::c_int = 0 as libc::c_int;
    let mut nid: libc::c_int = EVP_MD_type(md);
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[C2RustUnnamed_0; 8]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<C2RustUnnamed_0>() as libc::c_ulong)
    {
        if nid == kMDOIDs[i as usize].nid {
            if CBB_add_bytes(
                &mut oid,
                (kMDOIDs[i as usize].oid).as_ptr(),
                kMDOIDs[i as usize].oid_len as size_t,
            ) == 0
            {
                return 0 as libc::c_int;
            }
            found = 1 as libc::c_int;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if found == 0 {
        ERR_put_error(
            29 as libc::c_int,
            0 as libc::c_int,
            102 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/digest_extra/digest_extra.c\0"
                as *const u8 as *const libc::c_char,
            233 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBB_add_asn1(&mut algorithm, &mut null, 0x5 as libc::c_uint) == 0
        || CBB_flush(cbb) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_get_digestbyname(
    mut name: *const libc::c_char,
) -> *const EVP_MD {
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::core::mem::size_of::<[nid_to_digest; 26]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<nid_to_digest>() as libc::c_ulong)
    {
        let mut short_name: *const libc::c_char = nid_to_digest_mapping[i as usize]
            .short_name;
        let mut long_name: *const libc::c_char = nid_to_digest_mapping[i as usize]
            .long_name;
        if !short_name.is_null() && strcmp(short_name, name) == 0 as libc::c_int
            || !long_name.is_null() && strcmp(long_name, name) == 0 as libc::c_int
        {
            return (nid_to_digest_mapping[i as usize].md_func)
                .expect("non-null function pointer")();
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *const EVP_MD;
}
unsafe extern "C" fn blake2b256_init(mut ctx: *mut EVP_MD_CTX) {
    BLAKE2B256_Init((*ctx).md_data as *mut BLAKE2B_CTX);
}
unsafe extern "C" fn blake2b256_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    BLAKE2B256_Update((*ctx).md_data as *mut BLAKE2B_CTX, data, len);
    return 1 as libc::c_int;
}
unsafe extern "C" fn blake2b256_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut uint8_t) {
    BLAKE2B256_Final(md, (*ctx).md_data as *mut BLAKE2B_CTX);
}
static mut evp_md_blake2b256: EVP_MD = unsafe {
    {
        let mut init = env_md_st {
            type_0: 0 as libc::c_int,
            md_size: (256 as libc::c_int / 8 as libc::c_int) as libc::c_uint,
            flags: 0 as libc::c_int as uint32_t,
            init: Some(blake2b256_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ()),
            update: Some(
                blake2b256_update
                    as unsafe extern "C" fn(
                        *mut EVP_MD_CTX,
                        *const libc::c_void,
                        size_t,
                    ) -> libc::c_int,
            ),
            final_0: Some(
                blake2b256_final
                    as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut uint8_t) -> (),
            ),
            block_size: 128 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<BLAKE2B_CTX>() as libc::c_ulong
                as libc::c_uint,
            finalXOF: None,
            squeezeXOF: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_blake2b256() -> *const EVP_MD {
    return &evp_md_blake2b256;
}
unsafe extern "C" fn null_init(mut ctx: *mut EVP_MD_CTX) {}
unsafe extern "C" fn null_update(
    mut ctx: *mut EVP_MD_CTX,
    mut data: *const libc::c_void,
    mut count: size_t,
) -> libc::c_int {
    return 1 as libc::c_int;
}
unsafe extern "C" fn null_final(mut ctx: *mut EVP_MD_CTX, mut md: *mut libc::c_uchar) {}
static mut evp_md_null: EVP_MD = unsafe {
    {
        let mut init = env_md_st {
            type_0: 0 as libc::c_int,
            md_size: 0 as libc::c_int as libc::c_uint,
            flags: 0 as libc::c_int as uint32_t,
            init: Some(null_init as unsafe extern "C" fn(*mut EVP_MD_CTX) -> ()),
            update: Some(
                null_update
                    as unsafe extern "C" fn(
                        *mut EVP_MD_CTX,
                        *const libc::c_void,
                        size_t,
                    ) -> libc::c_int,
            ),
            final_0: Some(
                null_final
                    as unsafe extern "C" fn(*mut EVP_MD_CTX, *mut libc::c_uchar) -> (),
            ),
            block_size: 0 as libc::c_int as libc::c_uint,
            ctx_size: ::core::mem::size_of::<EVP_MD_CTX>() as libc::c_ulong
                as libc::c_uint,
            finalXOF: None,
            squeezeXOF: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_md_null() -> *const EVP_MD {
    return &evp_md_null;
}
