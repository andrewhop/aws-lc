#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types)]
extern "C" {
    pub type env_md_st;
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_int64(cbs: *mut CBS, out: *mut int64_t) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha224() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_sha384() -> *const EVP_MD;
    fn EVP_sha512() -> *const EVP_MD;
    fn EVP_MD_type(md: *const EVP_MD) -> libc::c_int;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type CBS_ASN1_TAG = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbs_st {
    pub data: *const uint8_t,
    pub len: size_t,
}
pub type CBS = cbs_st;
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsassa_pss_params_st {
    pub hash_algor: *mut RSA_ALGOR_IDENTIFIER,
    pub mask_gen_algor: *mut RSA_MGA_IDENTIFIER,
    pub salt_len: *mut RSA_INTEGER,
    pub trailer_field: *mut RSA_INTEGER,
}
pub type RSA_INTEGER = rsa_integer_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_integer_st {
    pub value: int64_t,
}
pub type RSA_MGA_IDENTIFIER = rsa_mga_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_mga_identifier_st {
    pub mask_gen: *mut RSA_ALGOR_IDENTIFIER,
    pub one_way_hash: *mut RSA_ALGOR_IDENTIFIER,
}
pub type RSA_ALGOR_IDENTIFIER = rsa_algor_identifier_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_algor_identifier_st {
    pub nid: libc::c_int,
}
pub type RSASSA_PSS_PARAMS = rsassa_pss_params_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rsa_pss_supported_algor_st {
    pub nid: libc::c_int,
    pub oid: [uint8_t; 9],
    pub oid_len: uint8_t,
}
pub type RSA_PSS_SUPPORTED_ALGOR = rsa_pss_supported_algor_st;
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
#[no_mangle]
pub static mut sha1_func: RSA_PSS_SUPPORTED_ALGOR = {
    let mut init = rsa_pss_supported_algor_st {
        nid: 64 as libc::c_int,
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
    };
    init
};
#[no_mangle]
pub static mut sha224_func: RSA_PSS_SUPPORTED_ALGOR = {
    let mut init = rsa_pss_supported_algor_st {
        nid: 675 as libc::c_int,
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
    };
    init
};
#[no_mangle]
pub static mut sha256_func: RSA_PSS_SUPPORTED_ALGOR = {
    let mut init = rsa_pss_supported_algor_st {
        nid: 672 as libc::c_int,
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
    };
    init
};
#[no_mangle]
pub static mut sha384_func: RSA_PSS_SUPPORTED_ALGOR = {
    let mut init = rsa_pss_supported_algor_st {
        nid: 673 as libc::c_int,
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
    };
    init
};
#[no_mangle]
pub static mut sha512_func: RSA_PSS_SUPPORTED_ALGOR = {
    let mut init = rsa_pss_supported_algor_st {
        nid: 674 as libc::c_int,
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
    };
    init
};
static mut rsa_pss_hash_functions: [*const RSA_PSS_SUPPORTED_ALGOR; 5] = unsafe {
    [
        &sha1_func as *const RSA_PSS_SUPPORTED_ALGOR,
        &sha224_func as *const RSA_PSS_SUPPORTED_ALGOR,
        &sha256_func as *const RSA_PSS_SUPPORTED_ALGOR,
        &sha384_func as *const RSA_PSS_SUPPORTED_ALGOR,
        &sha512_func as *const RSA_PSS_SUPPORTED_ALGOR,
    ]
};
#[no_mangle]
pub static mut MGF1: RSA_PSS_SUPPORTED_ALGOR = {
    let mut init = rsa_pss_supported_algor_st {
        nid: 911 as libc::c_int,
        oid: [
            0x2a as libc::c_int as uint8_t,
            0x86 as libc::c_int as uint8_t,
            0x48 as libc::c_int as uint8_t,
            0x86 as libc::c_int as uint8_t,
            0xf7 as libc::c_int as uint8_t,
            0xd as libc::c_int as uint8_t,
            0x1 as libc::c_int as uint8_t,
            0x1 as libc::c_int as uint8_t,
            0x8 as libc::c_int as uint8_t,
        ],
        oid_len: 9 as libc::c_int as uint8_t,
    };
    init
};
static mut rsa_pss_mg_functions: [*const RSA_PSS_SUPPORTED_ALGOR; 1] = unsafe {
    [&MGF1 as *const RSA_PSS_SUPPORTED_ALGOR]
};
unsafe extern "C" fn parse_oid(
    mut oid: *mut CBS,
    mut supported_algors: *const *const RSA_PSS_SUPPORTED_ALGOR,
    mut size: size_t,
    mut out: *mut *mut RSA_ALGOR_IDENTIFIER,
) -> libc::c_int {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < size {
        let mut supported_algr: *const RSA_PSS_SUPPORTED_ALGOR = *supported_algors
            .offset(i as isize);
        if CBS_len(oid) == (*supported_algr).oid_len as size_t
            && OPENSSL_memcmp(
                CBS_data(oid) as *const libc::c_void,
                ((*supported_algr).oid).as_ptr() as *const libc::c_void,
                (*supported_algr).oid_len as size_t,
            ) == 0 as libc::c_int
        {
            *out = RSA_ALGOR_IDENTIFIER_new();
            if (*out).is_null() {
                return 0 as libc::c_int;
            }
            (**out).nid = (*supported_algr).nid;
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        128 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
            as *const u8 as *const libc::c_char,
        93 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn is_absent_or_null(mut params: *mut CBS) -> libc::c_int {
    let mut null: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    return (CBS_len(params) == 0 as libc::c_int as size_t
        || CBS_get_asn1(params, &mut null, 0x5 as libc::c_uint) != 0
            && CBS_len(&mut null) == 0 as libc::c_int as size_t
            && CBS_len(params) == 0 as libc::c_int as size_t) as libc::c_int;
}
unsafe extern "C" fn decode_one_way_hash(
    mut cbs: *mut CBS,
    mut hash_algor: *mut *mut RSA_ALGOR_IDENTIFIER,
) -> libc::c_int {
    let mut seq: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut oid: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        cbs,
        &mut seq,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) != 0 && CBS_len(cbs) == 0 as libc::c_int as size_t
        && CBS_get_asn1(&mut seq, &mut oid, 0x6 as libc::c_uint) != 0
        && is_absent_or_null(&mut seq) != 0
        && parse_oid(
            &mut oid,
            rsa_pss_hash_functions.as_ptr(),
            (::core::mem::size_of::<[*const RSA_PSS_SUPPORTED_ALGOR; 5]>()
                as libc::c_ulong)
                .wrapping_div(
                    ::core::mem::size_of::<*const RSA_PSS_SUPPORTED_ALGOR>()
                        as libc::c_ulong,
                ),
            hash_algor,
        ) != 0
    {
        return 1 as libc::c_int;
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        102 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
            as *const u8 as *const libc::c_char,
        119 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn decode_mask_gen(
    mut cbs: *mut CBS,
    mut mga: *mut *mut RSA_MGA_IDENTIFIER,
) -> libc::c_int {
    let mut seq: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut mgf1_oid: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut hash_seq: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut hash_oid: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut mgf1: *mut RSA_ALGOR_IDENTIFIER = 0 as *mut RSA_ALGOR_IDENTIFIER;
    let mut hash_algor: *mut RSA_ALGOR_IDENTIFIER = 0 as *mut RSA_ALGOR_IDENTIFIER;
    if CBS_get_asn1(
        cbs,
        &mut seq,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) != 0 && CBS_len(cbs) == 0 as libc::c_int as size_t
        && CBS_get_asn1(&mut seq, &mut mgf1_oid, 0x6 as libc::c_uint) != 0
        && parse_oid(
            &mut mgf1_oid,
            rsa_pss_mg_functions.as_ptr(),
            (::core::mem::size_of::<[*const RSA_PSS_SUPPORTED_ALGOR; 1]>()
                as libc::c_ulong)
                .wrapping_div(
                    ::core::mem::size_of::<*const RSA_PSS_SUPPORTED_ALGOR>()
                        as libc::c_ulong,
                ),
            &mut mgf1,
        ) != 0
        && CBS_get_asn1(
            &mut seq,
            &mut hash_seq,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) != 0 && CBS_len(&mut seq) == 0 as libc::c_int as size_t
        && CBS_get_asn1(&mut hash_seq, &mut hash_oid, 0x6 as libc::c_uint) != 0
        && is_absent_or_null(&mut hash_seq) != 0
        && parse_oid(
            &mut hash_oid,
            rsa_pss_hash_functions.as_ptr(),
            (::core::mem::size_of::<[*const RSA_PSS_SUPPORTED_ALGOR; 5]>()
                as libc::c_ulong)
                .wrapping_div(
                    ::core::mem::size_of::<*const RSA_PSS_SUPPORTED_ALGOR>()
                        as libc::c_ulong,
                ),
            &mut hash_algor,
        ) != 0
    {
        *mga = RSA_MGA_IDENTIFIER_new();
        if !(*mga).is_null() {
            (**mga).mask_gen = mgf1;
            (**mga).one_way_hash = hash_algor;
            return 1 as libc::c_int;
        }
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        102 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
            as *const u8 as *const libc::c_char,
        147 as libc::c_int as libc::c_uint,
    );
    RSA_ALGOR_IDENTIFIER_free(mgf1);
    RSA_ALGOR_IDENTIFIER_free(hash_algor);
    return 0 as libc::c_int;
}
unsafe extern "C" fn get_context_specific_value(
    mut seq: *mut CBS,
    mut out: *mut CBS,
    mut index: libc::c_int,
) -> libc::c_int {
    let mut tag_value: libc::c_uint = (0x80 as libc::c_uint) << 24 as libc::c_int
        | (0x20 as libc::c_uint) << 24 as libc::c_int | index as libc::c_uint;
    let mut seq_cp: CBS = {
        let mut init = cbs_st {
            data: (*seq).data,
            len: (*seq).len,
        };
        init
    };
    if CBS_get_asn1(seq, out, tag_value) != 0 {
        return 1 as libc::c_int
    } else {
        (*seq).data = seq_cp.data;
        (*seq).len = seq_cp.len;
        return 0 as libc::c_int;
    };
}
unsafe extern "C" fn decode_pss_hash(
    mut seq: *mut CBS,
    mut hash_algor: *mut *mut RSA_ALGOR_IDENTIFIER,
) -> libc::c_int {
    let mut cs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if get_context_specific_value(seq, &mut cs, 0 as libc::c_int) == 0 {
        return 1 as libc::c_int;
    }
    return decode_one_way_hash(&mut cs, hash_algor);
}
unsafe extern "C" fn decode_pss_mask_gen(
    mut seq: *mut CBS,
    mut mga: *mut *mut RSA_MGA_IDENTIFIER,
) -> libc::c_int {
    let mut cs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if get_context_specific_value(seq, &mut cs, 1 as libc::c_int) == 0 {
        return 1 as libc::c_int;
    }
    return decode_mask_gen(&mut cs, mga);
}
unsafe extern "C" fn create_RSA_INTEGER(value: int64_t) -> *mut RSA_INTEGER {
    let mut rsa_int: *mut RSA_INTEGER = RSA_INTEGER_new();
    if !rsa_int.is_null() {
        (*rsa_int).value = value;
        return rsa_int;
    }
    return 0 as *mut RSA_INTEGER;
}
unsafe extern "C" fn parse_trailer_field(
    mut cbs: *mut CBS,
    mut rsa_int: *mut *mut RSA_INTEGER,
) -> libc::c_int {
    let mut value: int64_t = 0 as libc::c_int as int64_t;
    if CBS_get_asn1_int64(cbs, &mut value) != 0
        && CBS_len(cbs) == 0 as libc::c_int as size_t
    {
        if value != 1 as libc::c_int as int64_t {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                502 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                207 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        *rsa_int = create_RSA_INTEGER(value);
        return (*rsa_int != 0 as *mut libc::c_void as *mut RSA_INTEGER) as libc::c_int;
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        102 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
            as *const u8 as *const libc::c_char,
        213 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn parse_salt_length(
    mut cbs: *mut CBS,
    mut rsa_int: *mut *mut RSA_INTEGER,
) -> libc::c_int {
    let mut value: int64_t = 0 as libc::c_int as int64_t;
    if CBS_get_asn1_int64(cbs, &mut value) != 0
        && CBS_len(cbs) == 0 as libc::c_int as size_t
    {
        if value < 0 as libc::c_int as int64_t {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                501 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                222 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        *rsa_int = create_RSA_INTEGER(value);
        return (*rsa_int != 0 as *mut libc::c_void as *mut RSA_INTEGER) as libc::c_int;
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        102 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
            as *const u8 as *const libc::c_char,
        228 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn decode_pss_salt_len(
    mut seq: *mut CBS,
    mut salt_len: *mut *mut RSA_INTEGER,
) -> libc::c_int {
    let mut cs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if get_context_specific_value(seq, &mut cs, 2 as libc::c_int) == 0 {
        return 1 as libc::c_int;
    }
    return parse_salt_length(&mut cs, salt_len);
}
unsafe extern "C" fn decode_pss_trailer_field(
    mut seq: *mut CBS,
    mut trailer_field: *mut *mut RSA_INTEGER,
) -> libc::c_int {
    let mut cs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if get_context_specific_value(seq, &mut cs, 3 as libc::c_int) == 0 {
        return 1 as libc::c_int;
    }
    return parse_trailer_field(&mut cs, trailer_field);
}
#[no_mangle]
pub unsafe extern "C" fn RSASSA_PSS_parse_params(
    mut params: *mut CBS,
    mut pss_params: *mut *mut RSASSA_PSS_PARAMS,
) -> libc::c_int {
    if CBS_len(params) == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    let mut hash_algor: *mut RSA_ALGOR_IDENTIFIER = 0 as *mut RSA_ALGOR_IDENTIFIER;
    let mut mask_gen_algor: *mut RSA_MGA_IDENTIFIER = 0 as *mut RSA_MGA_IDENTIFIER;
    let mut salt_len: *mut RSA_INTEGER = 0 as *mut RSA_INTEGER;
    let mut trailer_field: *mut RSA_INTEGER = 0 as *mut RSA_INTEGER;
    let mut seq: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        params,
        &mut seq,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) != 0 && CBS_len(params) == 0 as libc::c_int as size_t
        && decode_pss_hash(&mut seq, &mut hash_algor) != 0
        && decode_pss_mask_gen(&mut seq, &mut mask_gen_algor) != 0
        && decode_pss_salt_len(&mut seq, &mut salt_len) != 0
        && decode_pss_trailer_field(&mut seq, &mut trailer_field) != 0
        && CBS_len(&mut seq) == 0 as libc::c_int as size_t
    {
        *pss_params = RSASSA_PSS_PARAMS_new();
        if !(*pss_params).is_null() {
            (**pss_params).hash_algor = hash_algor;
            (**pss_params).mask_gen_algor = mask_gen_algor;
            (**pss_params).salt_len = salt_len;
            (**pss_params).trailer_field = trailer_field;
            return 1 as libc::c_int;
        }
    }
    RSA_ALGOR_IDENTIFIER_free(hash_algor);
    RSA_MGA_IDENTIFIER_free(mask_gen_algor);
    RSA_INTEGER_free(salt_len);
    RSA_INTEGER_free(trailer_field);
    return 0 as libc::c_int;
}
unsafe extern "C" fn pss_parse_nid(
    mut nid: libc::c_int,
    mut out: *mut *mut RSA_ALGOR_IDENTIFIER,
) -> libc::c_int {
    if nid == 64 as libc::c_int {
        *out = 0 as *mut RSA_ALGOR_IDENTIFIER;
        return 1 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i
        < (::core::mem::size_of::<[*const RSA_PSS_SUPPORTED_ALGOR; 5]>()
            as libc::c_ulong)
            .wrapping_div(
                ::core::mem::size_of::<*const RSA_PSS_SUPPORTED_ALGOR>() as libc::c_ulong,
            )
    {
        let mut supported_algor: *const RSA_PSS_SUPPORTED_ALGOR = rsa_pss_hash_functions[i
            as usize];
        if nid == (*supported_algor).nid {
            *out = RSA_ALGOR_IDENTIFIER_new();
            if !(*out).is_null() {
                (**out).nid = (*supported_algor).nid;
                return 1 as libc::c_int;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    ERR_put_error(
        4 as libc::c_int,
        0 as libc::c_int,
        128 as libc::c_int,
        b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
            as *const u8 as *const libc::c_char,
        308 as libc::c_int as libc::c_uint,
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_INTEGER_new() -> *mut RSA_INTEGER {
    let mut ret: *mut RSA_INTEGER = OPENSSL_zalloc(
        ::core::mem::size_of::<RSA_INTEGER>() as libc::c_ulong,
    ) as *mut RSA_INTEGER;
    if ret.is_null() {
        return 0 as *mut RSA_INTEGER;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_ALGOR_IDENTIFIER_new() -> *mut RSA_ALGOR_IDENTIFIER {
    let mut ret: *mut RSA_ALGOR_IDENTIFIER = OPENSSL_zalloc(
        ::core::mem::size_of::<RSA_ALGOR_IDENTIFIER>() as libc::c_ulong,
    ) as *mut RSA_ALGOR_IDENTIFIER;
    if ret.is_null() {
        return 0 as *mut RSA_ALGOR_IDENTIFIER;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_MGA_IDENTIFIER_new() -> *mut RSA_MGA_IDENTIFIER {
    let mut ret: *mut RSA_MGA_IDENTIFIER = OPENSSL_zalloc(
        ::core::mem::size_of::<RSA_MGA_IDENTIFIER>() as libc::c_ulong,
    ) as *mut RSA_MGA_IDENTIFIER;
    if ret.is_null() {
        return 0 as *mut RSA_MGA_IDENTIFIER;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSASSA_PSS_PARAMS_new() -> *mut RSASSA_PSS_PARAMS {
    let mut ret: *mut RSASSA_PSS_PARAMS = OPENSSL_zalloc(
        ::core::mem::size_of::<RSASSA_PSS_PARAMS>() as libc::c_ulong,
    ) as *mut RSASSA_PSS_PARAMS;
    if ret.is_null() {
        return 0 as *mut RSASSA_PSS_PARAMS;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn RSA_INTEGER_free(mut ptr: *mut RSA_INTEGER) {
    OPENSSL_free(ptr as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_ALGOR_IDENTIFIER_free(
    mut algor: *mut RSA_ALGOR_IDENTIFIER,
) {
    OPENSSL_free(algor as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn RSA_MGA_IDENTIFIER_free(mut mga: *mut RSA_MGA_IDENTIFIER) {
    if mga.is_null() {
        return;
    }
    RSA_ALGOR_IDENTIFIER_free((*mga).mask_gen);
    RSA_ALGOR_IDENTIFIER_free((*mga).one_way_hash);
    OPENSSL_free(mga as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn RSASSA_PSS_PARAMS_free(mut params: *mut RSASSA_PSS_PARAMS) {
    if params.is_null() {
        return;
    }
    RSA_ALGOR_IDENTIFIER_free((*params).hash_algor);
    RSA_MGA_IDENTIFIER_free((*params).mask_gen_algor);
    RSA_INTEGER_free((*params).salt_len);
    RSA_INTEGER_free((*params).trailer_field);
    OPENSSL_free(params as *mut libc::c_void);
}
unsafe extern "C" fn pss_hash_create(
    mut sigmd: *const EVP_MD,
    mut out: *mut *mut RSA_ALGOR_IDENTIFIER,
) -> libc::c_int {
    if sigmd.is_null() {
        *out = 0 as *mut RSA_ALGOR_IDENTIFIER;
        return 1 as libc::c_int;
    }
    return pss_parse_nid(EVP_MD_type(sigmd), out);
}
unsafe extern "C" fn pss_mga_create(
    mut mgf1md: *const EVP_MD,
    mut out: *mut *mut RSA_MGA_IDENTIFIER,
) -> libc::c_int {
    if mgf1md.is_null() || EVP_MD_type(mgf1md) == 64 as libc::c_int {
        *out = 0 as *mut RSA_MGA_IDENTIFIER;
        return 1 as libc::c_int;
    }
    let mut mga: *mut RSA_MGA_IDENTIFIER = RSA_MGA_IDENTIFIER_new();
    if mga.is_null() {
        return 0 as libc::c_int;
    }
    if pss_parse_nid(EVP_MD_type(mgf1md), &mut (*mga).one_way_hash) != 0 {
        *out = mga;
        return 1 as libc::c_int;
    }
    RSA_MGA_IDENTIFIER_free(mga);
    return 0 as libc::c_int;
}
unsafe extern "C" fn pss_saltlen_create(
    mut saltlen: libc::c_int,
    mut out: *mut *mut RSA_INTEGER,
) -> libc::c_int {
    if saltlen < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if saltlen == 20 as libc::c_int {
        return 1 as libc::c_int;
    }
    *out = RSA_INTEGER_new();
    if !(*out).is_null() {
        (**out).value = saltlen as int64_t;
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSASSA_PSS_PARAMS_create(
    mut sigmd: *const EVP_MD,
    mut mgf1md: *const EVP_MD,
    mut saltlen: libc::c_int,
    mut out: *mut *mut RSASSA_PSS_PARAMS,
) -> libc::c_int {
    if sigmd.is_null() && mgf1md.is_null() && saltlen == -(2 as libc::c_int) {
        return 1 as libc::c_int;
    }
    let mut pss: *mut RSASSA_PSS_PARAMS = RSASSA_PSS_PARAMS_new();
    if pss.is_null() {
        return 0 as libc::c_int;
    }
    if pss_hash_create(sigmd, &mut (*pss).hash_algor) == 0
        || pss_mga_create(mgf1md, &mut (*pss).mask_gen_algor) == 0
        || pss_saltlen_create(saltlen, &mut (*pss).salt_len) == 0
    {
        RSASSA_PSS_PARAMS_free(pss);
        return 0 as libc::c_int;
    }
    *out = pss;
    return 1 as libc::c_int;
}
unsafe extern "C" fn nid_to_EVP_MD(nid: libc::c_int) -> *const EVP_MD {
    match nid {
        64 => return EVP_sha1(),
        675 => return EVP_sha224(),
        672 => return EVP_sha256(),
        673 => return EVP_sha384(),
        674 => return EVP_sha512(),
        _ => {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                128 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                456 as libc::c_int as libc::c_uint,
            );
            return 0 as *const EVP_MD;
        }
    };
}
unsafe extern "C" fn hash_algor_to_EVP_MD(
    mut hash_algor: *mut RSA_ALGOR_IDENTIFIER,
    mut md: *mut *const EVP_MD,
) -> libc::c_int {
    if !hash_algor.is_null() {
        *md = nid_to_EVP_MD((*hash_algor).nid);
    } else {
        *md = EVP_sha1();
    }
    return (*md != 0 as *mut libc::c_void as *const EVP_MD) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn RSASSA_PSS_PARAMS_get(
    mut pss: *const RSASSA_PSS_PARAMS,
    mut md: *mut *const EVP_MD,
    mut mgf1md: *mut *const EVP_MD,
    mut saltlen: *mut libc::c_int,
) -> libc::c_int {
    if pss.is_null() || md.is_null() || mgf1md.is_null() || saltlen.is_null() {
        return 0 as libc::c_int;
    }
    if hash_algor_to_EVP_MD((*pss).hash_algor, md) == 0 {
        return 0 as libc::c_int;
    }
    let mut mga_hash: *mut RSA_ALGOR_IDENTIFIER = 0 as *mut RSA_ALGOR_IDENTIFIER;
    if !((*pss).mask_gen_algor).is_null() {
        mga_hash = (*(*pss).mask_gen_algor).one_way_hash;
    }
    if hash_algor_to_EVP_MD(mga_hash, mgf1md) == 0 {
        return 0 as libc::c_int;
    }
    if !((*pss).salt_len).is_null() {
        if (*(*pss).salt_len).value < 0 as libc::c_int as int64_t {
            ERR_put_error(
                4 as libc::c_int,
                0 as libc::c_int,
                501 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
                    as *const u8 as *const libc::c_char,
                491 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        *saltlen = (*(*pss).salt_len).value as libc::c_int;
    } else {
        *saltlen = 20 as libc::c_int;
    }
    if !((*pss).trailer_field).is_null()
        && (*(*pss).trailer_field).value != 1 as libc::c_int as int64_t
    {
        ERR_put_error(
            4 as libc::c_int,
            0 as libc::c_int,
            502 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/rsa_extra/rsassa_pss_asn1.c\0"
                as *const u8 as *const libc::c_char,
            500 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
