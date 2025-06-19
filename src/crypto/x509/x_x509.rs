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
    pub type ASN1_VALUE_st;
    pub type stack_st_GENERAL_NAME;
    pub type stack_st_X509_NAME_ENTRY;
    pub type stack_st_GENERAL_SUBTREE;
    pub type evp_pkey_st;
    pub type stack_st_ASN1_OBJECT;
    pub type stack_st_X509_EXTENSION;
    pub type crypto_buffer_st;
    pub type stack_st_DIST_POINT;
    pub type stack_st_void;
    pub type stack_st_CRYPTO_EX_DATA_FUNCS;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn ASN1_item_new(it: *const ASN1_ITEM) -> *mut ASN1_VALUE;
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn ASN1_item_d2i(
        out: *mut *mut ASN1_VALUE,
        inp: *mut *const libc::c_uchar,
        len: libc::c_long,
        it: *const ASN1_ITEM,
    ) -> *mut ASN1_VALUE;
    fn ASN1_item_i2d(
        val: *mut ASN1_VALUE,
        outp: *mut *mut libc::c_uchar,
        it: *const ASN1_ITEM,
    ) -> libc::c_int;
    fn ASN1_item_dup(it: *const ASN1_ITEM, x: *mut libc::c_void) -> *mut libc::c_void;
    fn ASN1_STRING_set(
        str: *mut ASN1_STRING,
        data: *const libc::c_void,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn ASN1_OCTET_STRING_free(str: *mut ASN1_OCTET_STRING);
    static ASN1_BIT_STRING_it: ASN1_ITEM;
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn ASN1_INTEGER_get(a: *const ASN1_INTEGER) -> libc::c_long;
    fn asn1_encoding_clear(enc: *mut ASN1_ENCODING);
    static X509_NAME_it: ASN1_ITEM;
    static X509_PUBKEY_it: ASN1_ITEM;
    static X509_EXTENSION_it: ASN1_ITEM;
    fn GENERAL_NAMES_free(gens: *mut GENERAL_NAMES);
    static X509_ALGOR_it: ASN1_ITEM;
    fn X509_ALGOR_dup(alg: *const X509_ALGOR) -> *mut X509_ALGOR;
    fn X509_ALGOR_free(alg: *mut X509_ALGOR);
    fn AUTHORITY_KEYID_free(akid: *mut AUTHORITY_KEYID);
    fn CRL_DIST_POINTS_free(crldp: *mut CRL_DIST_POINTS);
    fn NAME_CONSTRAINTS_free(ncons: *mut NAME_CONSTRAINTS);
    static X509_VAL_it: ASN1_ITEM;
    fn i2d_X509_CERT_AUX(
        a: *const X509_CERT_AUX,
        out: *mut *mut libc::c_uchar,
    ) -> libc::c_int;
    fn X509_CERT_AUX_free(a: *mut X509_CERT_AUX);
    fn d2i_X509_CERT_AUX(
        a: *mut *mut X509_CERT_AUX,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut X509_CERT_AUX;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn OBJ_obj2nid(obj: *const ASN1_OBJECT) -> libc::c_int;
    fn CRYPTO_BUFFER_free(buf: *mut CRYPTO_BUFFER);
    fn CRYPTO_BUFFER_up_ref(buf: *mut CRYPTO_BUFFER) -> libc::c_int;
    fn CRYPTO_BUFFER_data(buf: *const CRYPTO_BUFFER) -> *const uint8_t;
    fn CRYPTO_BUFFER_len(buf: *const CRYPTO_BUFFER) -> size_t;
    fn CRYPTO_refcount_inc(count: *mut CRYPTO_refcount_t);
    fn CRYPTO_MUTEX_init(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_MUTEX_cleanup(lock: *mut CRYPTO_MUTEX);
    fn CRYPTO_get_ex_new_index(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        out_index: *mut libc::c_int,
        argl: libc::c_long,
        argp: *mut libc::c_void,
        free_func: Option::<CRYPTO_EX_free>,
    ) -> libc::c_int;
    fn CRYPTO_set_ex_data(
        ad: *mut CRYPTO_EX_DATA,
        index: libc::c_int,
        val: *mut libc::c_void,
    ) -> libc::c_int;
    fn CRYPTO_get_ex_data(
        ad: *const CRYPTO_EX_DATA,
        index: libc::c_int,
    ) -> *mut libc::c_void;
    fn CRYPTO_new_ex_data(ad: *mut CRYPTO_EX_DATA);
    fn CRYPTO_free_ex_data(
        ex_data_class: *mut CRYPTO_EX_DATA_CLASS,
        obj: *mut libc::c_void,
        ad: *mut CRYPTO_EX_DATA,
    );
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type ptrdiff_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_rwlock_arch_t {
    pub __readers: libc::c_uint,
    pub __writers: libc::c_uint,
    pub __wrphase_futex: libc::c_uint,
    pub __writers_futex: libc::c_uint,
    pub __pad3: libc::c_uint,
    pub __pad4: libc::c_uint,
    pub __cur_writer: libc::c_int,
    pub __shared: libc::c_int,
    pub __rwelision: libc::c_schar,
    pub __pad1: [libc::c_uchar; 7],
    pub __pad2: libc::c_ulong,
    pub __flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_rwlock_t {
    pub __data: __pthread_rwlock_arch_t,
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
pub type ossl_ssize_t = ptrdiff_t;
pub type ASN1_BOOLEAN = libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_ITEM_st {
    pub itype: libc::c_char,
    pub utype: libc::c_int,
    pub templates: *const ASN1_TEMPLATE,
    pub tcount: libc::c_long,
    pub funcs: *const libc::c_void,
    pub size: libc::c_long,
    pub sname: *const libc::c_char,
}
pub type ASN1_TEMPLATE = ASN1_TEMPLATE_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_TEMPLATE_st {
    pub flags: uint32_t,
    pub tag: libc::c_int,
    pub offset: libc::c_ulong,
    pub field_name: *const libc::c_char,
    pub item: *const ASN1_ITEM_EXP,
}
pub type ASN1_ITEM_EXP = ASN1_ITEM;
pub type ASN1_ITEM = ASN1_ITEM_st;
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
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_BIT_STRING = asn1_string_st;
pub type ASN1_BMPSTRING = asn1_string_st;
pub type ASN1_ENUMERATED = asn1_string_st;
pub type ASN1_GENERALIZEDTIME = asn1_string_st;
pub type ASN1_GENERALSTRING = asn1_string_st;
pub type ASN1_IA5STRING = asn1_string_st;
pub type ASN1_INTEGER = asn1_string_st;
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type ASN1_PRINTABLESTRING = asn1_string_st;
pub type ASN1_STRING = asn1_string_st;
pub type ASN1_T61STRING = asn1_string_st;
pub type ASN1_TIME = asn1_string_st;
pub type ASN1_UNIVERSALSTRING = asn1_string_st;
pub type ASN1_UTCTIME = asn1_string_st;
pub type ASN1_UTF8STRING = asn1_string_st;
pub type ASN1_VISIBLESTRING = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_type_st {
    pub type_0: libc::c_int,
    pub value: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub ptr: *mut libc::c_char,
    pub boolean: ASN1_BOOLEAN,
    pub asn1_string: *mut ASN1_STRING,
    pub object: *mut ASN1_OBJECT,
    pub integer: *mut ASN1_INTEGER,
    pub enumerated: *mut ASN1_ENUMERATED,
    pub bit_string: *mut ASN1_BIT_STRING,
    pub octet_string: *mut ASN1_OCTET_STRING,
    pub printablestring: *mut ASN1_PRINTABLESTRING,
    pub t61string: *mut ASN1_T61STRING,
    pub ia5string: *mut ASN1_IA5STRING,
    pub generalstring: *mut ASN1_GENERALSTRING,
    pub bmpstring: *mut ASN1_BMPSTRING,
    pub universalstring: *mut ASN1_UNIVERSALSTRING,
    pub utctime: *mut ASN1_UTCTIME,
    pub generalizedtime: *mut ASN1_GENERALIZEDTIME,
    pub visiblestring: *mut ASN1_VISIBLESTRING,
    pub utf8string: *mut ASN1_UTF8STRING,
    pub set: *mut ASN1_STRING,
    pub sequence: *mut ASN1_STRING,
    pub asn1_value: *mut ASN1_VALUE,
}
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type ASN1_TYPE = asn1_type_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct AUTHORITY_KEYID_st {
    pub keyid: *mut ASN1_OCTET_STRING,
    pub issuer: *mut GENERAL_NAMES,
    pub serial: *mut ASN1_INTEGER,
}
pub type GENERAL_NAMES = stack_st_GENERAL_NAME;
pub type AUTHORITY_KEYID = AUTHORITY_KEYID_st;
pub type X509_NAME = X509_name_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_name_st {
    pub entries: *mut stack_st_X509_NAME_ENTRY,
    pub modified: libc::c_int,
    pub bytes: *mut BUF_MEM,
    pub canon_enc: *mut libc::c_uchar,
    pub canon_enclen: libc::c_int,
}
pub type BUF_MEM = buf_mem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct NAME_CONSTRAINTS_st {
    pub permittedSubtrees: *mut stack_st_GENERAL_SUBTREE,
    pub excludedSubtrees: *mut stack_st_GENERAL_SUBTREE,
}
pub type NAME_CONSTRAINTS = NAME_CONSTRAINTS_st;
pub type X509_PUBKEY = X509_pubkey_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_pubkey_st {
    pub algor: *mut X509_ALGOR,
    pub public_key: *mut ASN1_BIT_STRING,
    pub pkey: *mut EVP_PKEY,
}
pub type EVP_PKEY = evp_pkey_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type ASN1_ENCODING = ASN1_ENCODING_st;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ASN1_ENCODING_st {
    pub enc: *mut libc::c_uchar,
    pub len: libc::c_long,
    #[bitfield(name = "alias_only", ty = "libc::c_uint", bits = "0..=0")]
    #[bitfield(name = "alias_only_on_next_parse", ty = "libc::c_uint", bits = "1..=1")]
    pub alias_only_alias_only_on_next_parse: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
pub type X509 = x509_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_st {
    pub cert_info: *mut X509_CINF,
    pub sig_alg: *mut X509_ALGOR,
    pub signature: *mut ASN1_BIT_STRING,
    pub sig_info: X509_SIG_INFO,
    pub references: CRYPTO_refcount_t,
    pub ex_data: CRYPTO_EX_DATA,
    pub ex_pathlen: libc::c_long,
    pub ex_flags: uint32_t,
    pub ex_kusage: uint32_t,
    pub ex_xkusage: uint32_t,
    pub ex_nscert: uint32_t,
    pub skid: *mut ASN1_OCTET_STRING,
    pub akid: *mut AUTHORITY_KEYID,
    pub crldp: *mut stack_st_DIST_POINT,
    pub altname: *mut stack_st_GENERAL_NAME,
    pub nc: *mut NAME_CONSTRAINTS,
    pub cert_hash: [libc::c_uchar; 32],
    pub aux: *mut X509_CERT_AUX,
    pub buf: *mut CRYPTO_BUFFER,
    pub lock: CRYPTO_MUTEX,
}
pub type CRYPTO_MUTEX = crypto_mutex_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union crypto_mutex_st {
    pub alignment: libc::c_double,
    pub padding: [uint8_t; 56],
}
pub type CRYPTO_BUFFER = crypto_buffer_st;
pub type X509_CERT_AUX = x509_cert_aux_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_cert_aux_st {
    pub trust: *mut stack_st_ASN1_OBJECT,
    pub reject: *mut stack_st_ASN1_OBJECT,
    pub alias: *mut ASN1_UTF8STRING,
    pub keyid: *mut ASN1_OCTET_STRING,
}
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type X509_SIG_INFO = x509_sig_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x509_sig_info_st {
    pub digest_nid: libc::c_int,
    pub pubkey_nid: libc::c_int,
    pub sec_bits: libc::c_int,
    pub flags: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_CINF {
    pub version: *mut ASN1_INTEGER,
    pub serialNumber: *mut ASN1_INTEGER,
    pub signature: *mut X509_ALGOR,
    pub issuer: *mut X509_NAME,
    pub validity: *mut X509_VAL,
    pub subject: *mut X509_NAME,
    pub key: *mut X509_PUBKEY,
    pub issuerUID: *mut ASN1_BIT_STRING,
    pub subjectUID: *mut ASN1_BIT_STRING,
    pub extensions: *mut stack_st_X509_EXTENSION,
    pub enc: ASN1_ENCODING,
}
pub type X509_VAL = X509_val_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_val_st {
    pub notBefore: *mut ASN1_TIME,
    pub notAfter: *mut ASN1_TIME,
}
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    *mut CRYPTO_EX_DATA,
    *const CRYPTO_EX_DATA,
    *mut *mut libc::c_void,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> libc::c_int;
pub type CRYPTO_EX_unused = libc::c_int;
pub type ASN1_aux_cb = unsafe extern "C" fn(
    libc::c_int,
    *mut *mut ASN1_VALUE,
    *const ASN1_ITEM,
    *mut libc::c_void,
) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ASN1_AUX_st {
    pub app_data: *mut libc::c_void,
    pub flags: uint32_t,
    pub ref_offset: libc::c_int,
    pub asn1_cb: Option::<ASN1_aux_cb>,
    pub enc_offset: libc::c_int,
}
pub type ASN1_AUX = ASN1_AUX_st;
pub type CRL_DIST_POINTS = stack_st_DIST_POINT;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_EX_DATA_CLASS {
    pub lock: CRYPTO_STATIC_MUTEX,
    pub meth: *mut stack_st_CRYPTO_EX_DATA_FUNCS,
    pub num_reserved: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPTO_STATIC_MUTEX {
    pub lock: pthread_rwlock_t,
}
pub const PTHREAD_RWLOCK_DEFAULT_NP: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP: C2RustUnnamed_0 = 2;
pub const PTHREAD_RWLOCK_PREFER_WRITER_NP: C2RustUnnamed_0 = 1;
pub const PTHREAD_RWLOCK_PREFER_READER_NP: C2RustUnnamed_0 = 0;
static mut g_ex_data_class: CRYPTO_EX_DATA_CLASS = {
    let mut init = CRYPTO_EX_DATA_CLASS {
        lock: {
            let mut init = CRYPTO_STATIC_MUTEX {
                lock: pthread_rwlock_t {
                    __data: {
                        let mut init = __pthread_rwlock_arch_t {
                            __readers: 0 as libc::c_int as libc::c_uint,
                            __writers: 0 as libc::c_int as libc::c_uint,
                            __wrphase_futex: 0 as libc::c_int as libc::c_uint,
                            __writers_futex: 0 as libc::c_int as libc::c_uint,
                            __pad3: 0 as libc::c_int as libc::c_uint,
                            __pad4: 0 as libc::c_int as libc::c_uint,
                            __cur_writer: 0 as libc::c_int,
                            __shared: 0 as libc::c_int,
                            __rwelision: 0 as libc::c_int as libc::c_schar,
                            __pad1: [
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                                0 as libc::c_int as libc::c_uchar,
                            ],
                            __pad2: 0 as libc::c_int as libc::c_ulong,
                            __flags: PTHREAD_RWLOCK_DEFAULT_NP as libc::c_int
                                as libc::c_uint,
                        };
                        init
                    },
                },
            };
            init
        },
        meth: 0 as *const stack_st_CRYPTO_EX_DATA_FUNCS
            as *mut stack_st_CRYPTO_EX_DATA_FUNCS,
        num_reserved: 0 as libc::c_int as uint8_t,
    };
    init
};
static mut X509_CINF_aux: ASN1_AUX = {
    let mut init = ASN1_AUX_st {
        app_data: 0 as *const libc::c_void as *mut libc::c_void,
        flags: 2 as libc::c_int as uint32_t,
        ref_offset: 0 as libc::c_int,
        asn1_cb: None,
        enc_offset: 80 as libc::c_ulong as libc::c_int,
    };
    init
};
static mut X509_CINF_seq_tt: [ASN1_TEMPLATE; 10] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"version\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"serialNumber\0" as *const u8 as *const libc::c_char,
                item: &ASN1_INTEGER_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"signature\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"issuer\0" as *const u8 as *const libc::c_char,
                item: &X509_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 32 as libc::c_ulong,
                field_name: b"validity\0" as *const u8 as *const libc::c_char,
                item: &X509_VAL_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 40 as libc::c_ulong,
                field_name: b"subject\0" as *const u8 as *const libc::c_char,
                item: &X509_NAME_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 48 as libc::c_ulong,
                field_name: b"key\0" as *const u8 as *const libc::c_char,
                item: &X509_PUBKEY_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 1 as libc::c_int,
                offset: 56 as libc::c_ulong,
                field_name: b"issuerUID\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 2 as libc::c_int,
                offset: 64 as libc::c_ulong,
                field_name: b"subjectUID\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x2 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x2 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 3 as libc::c_int,
                offset: 72 as libc::c_ulong,
                field_name: b"extensions\0" as *const u8 as *const libc::c_char,
                item: &X509_EXTENSION_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut X509_CINF_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_CINF(
    mut a: *mut X509_CINF,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_CINF_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CINF_free(mut a: *mut X509_CINF) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_CINF_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_CINF_new() -> *mut X509_CINF {
    return ASN1_item_new(&X509_CINF_it) as *mut X509_CINF;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_CINF(
    mut a: *mut *mut X509_CINF,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509_CINF {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_CINF_it)
        as *mut X509_CINF;
}
unsafe extern "C" fn x509_cb(
    mut operation: libc::c_int,
    mut pval: *mut *mut ASN1_VALUE,
    mut it: *const ASN1_ITEM,
    mut exarg: *mut libc::c_void,
) -> libc::c_int {
    let mut ret: *mut X509 = *pval as *mut X509;
    match operation {
        1 => {
            (*ret).ex_flags = 0 as libc::c_int as uint32_t;
            (*ret).ex_pathlen = -(1 as libc::c_int) as libc::c_long;
            (*ret).skid = 0 as *mut ASN1_OCTET_STRING;
            (*ret).akid = 0 as *mut AUTHORITY_KEYID;
            (*ret).aux = 0 as *mut X509_CERT_AUX;
            (*ret).crldp = 0 as *mut stack_st_DIST_POINT;
            (*ret).buf = 0 as *mut CRYPTO_BUFFER;
            CRYPTO_new_ex_data(&mut (*ret).ex_data);
            CRYPTO_MUTEX_init(&mut (*ret).lock);
        }
        4 => {
            CRYPTO_BUFFER_free((*ret).buf);
            (*ret).buf = 0 as *mut CRYPTO_BUFFER;
        }
        5 => {
            let mut version: libc::c_long = 0 as libc::c_int as libc::c_long;
            if !((*(*ret).cert_info).version).is_null() {
                version = ASN1_INTEGER_get((*(*ret).cert_info).version);
                if version < 0 as libc::c_int as libc::c_long
                    || version > 2 as libc::c_int as libc::c_long
                {
                    ERR_put_error(
                        11 as libc::c_int,
                        0 as libc::c_int,
                        140 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0"
                            as *const u8 as *const libc::c_char,
                        122 as libc::c_int as libc::c_uint,
                    );
                    return 0 as libc::c_int;
                }
            }
            if version == 0 as libc::c_int as libc::c_long
                && (!((*(*ret).cert_info).issuerUID).is_null()
                    || !((*(*ret).cert_info).subjectUID).is_null())
            {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    139 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    130 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
            if version != 2 as libc::c_int as libc::c_long
                && !((*(*ret).cert_info).extensions).is_null()
            {
                ERR_put_error(
                    11 as libc::c_int,
                    0 as libc::c_int,
                    139 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    136 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
        }
        3 => {
            CRYPTO_MUTEX_cleanup(&mut (*ret).lock);
            CRYPTO_free_ex_data(
                &mut g_ex_data_class,
                ret as *mut libc::c_void,
                &mut (*ret).ex_data,
            );
            X509_CERT_AUX_free((*ret).aux);
            ASN1_OCTET_STRING_free((*ret).skid);
            AUTHORITY_KEYID_free((*ret).akid);
            CRL_DIST_POINTS_free((*ret).crldp);
            GENERAL_NAMES_free((*ret).altname);
            NAME_CONSTRAINTS_free((*ret).nc);
            CRYPTO_BUFFER_free((*ret).buf);
        }
        _ => {}
    }
    return 1 as libc::c_int;
}
static mut X509_aux: ASN1_AUX = unsafe {
    {
        let mut init = ASN1_AUX_st {
            app_data: 0 as *const libc::c_void as *mut libc::c_void,
            flags: 1 as libc::c_int as uint32_t,
            ref_offset: 40 as libc::c_ulong as libc::c_int,
            asn1_cb: Some(
                x509_cb
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *mut *mut ASN1_VALUE,
                        *const ASN1_ITEM,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            enc_offset: 0 as libc::c_int,
        };
        init
    }
};
static mut X509_seq_tt: [ASN1_TEMPLATE; 3] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 0 as libc::c_ulong,
                field_name: b"cert_info\0" as *const u8 as *const libc::c_char,
                item: &X509_CINF_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 8 as libc::c_ulong,
                field_name: b"sig_alg\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"signature\0" as *const u8 as *const libc::c_char,
                item: &ASN1_BIT_STRING_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut X509_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_free(mut a: *mut X509) {
    ASN1_item_free(a as *mut ASN1_VALUE, &X509_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509(
    mut a: *mut X509,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &X509_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509(
    mut a: *mut *mut X509,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut X509 {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &X509_it) as *mut X509;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_new() -> *mut X509 {
    return ASN1_item_new(&X509_it) as *mut X509;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_dup(mut x: *mut X509) -> *mut X509 {
    return ASN1_item_dup(&X509_it, x as *mut libc::c_void) as *mut X509;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_parse_from_buffer(
    mut buf: *mut CRYPTO_BUFFER,
) -> *mut X509 {
    if CRYPTO_BUFFER_len(buf) > 9223372036854775807 as libc::c_long as size_t {
        ERR_put_error(
            16 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0" as *const u8
                as *const libc::c_char,
            171 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut X509;
    }
    let mut x509: *mut X509 = X509_new();
    if x509.is_null() {
        return 0 as *mut X509;
    }
    ((*(*x509).cert_info).enc)
        .set_alias_only_on_next_parse(1 as libc::c_int as libc::c_uint);
    let mut inp: *const uint8_t = CRYPTO_BUFFER_data(buf);
    let mut x509p: *mut X509 = x509;
    let mut ret: *mut X509 = d2i_X509(
        &mut x509p,
        &mut inp,
        CRYPTO_BUFFER_len(buf) as libc::c_long,
    );
    if ret.is_null()
        || inp.offset_from(CRYPTO_BUFFER_data(buf)) as libc::c_long
            != CRYPTO_BUFFER_len(buf) as ptrdiff_t
    {
        X509_free(x509p);
        return 0 as *mut X509;
    }
    if x509p == x509 {} else {
        __assert_fail(
            b"x509p == x509\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0" as *const u8
                as *const libc::c_char,
            190 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 46],
                &[libc::c_char; 46],
            >(b"X509 *X509_parse_from_buffer(CRYPTO_BUFFER *)\0"))
                .as_ptr(),
        );
    }
    'c_16701: {
        if x509p == x509 {} else {
            __assert_fail(
                b"x509p == x509\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0" as *const u8
                    as *const libc::c_char,
                190 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 46],
                    &[libc::c_char; 46],
                >(b"X509 *X509_parse_from_buffer(CRYPTO_BUFFER *)\0"))
                    .as_ptr(),
            );
        }
    };
    if ret == x509 {} else {
        __assert_fail(
            b"ret == x509\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0" as *const u8
                as *const libc::c_char,
            191 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 46],
                &[libc::c_char; 46],
            >(b"X509 *X509_parse_from_buffer(CRYPTO_BUFFER *)\0"))
                .as_ptr(),
        );
    }
    'c_16659: {
        if ret == x509 {} else {
            __assert_fail(
                b"ret == x509\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0" as *const u8
                    as *const libc::c_char,
                191 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 46],
                    &[libc::c_char; 46],
                >(b"X509 *X509_parse_from_buffer(CRYPTO_BUFFER *)\0"))
                    .as_ptr(),
            );
        }
    };
    CRYPTO_BUFFER_up_ref(buf);
    (*ret).buf = buf;
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_up_ref(mut x: *mut X509) -> libc::c_int {
    if x.is_null() {
        return 0 as libc::c_int;
    }
    CRYPTO_refcount_inc(&mut (*x).references);
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get_ex_new_index(
    mut argl: libc::c_long,
    mut argp: *mut libc::c_void,
    mut unused: *mut CRYPTO_EX_unused,
    mut dup_unused: Option::<CRYPTO_EX_dup>,
    mut free_func: Option::<CRYPTO_EX_free>,
) -> libc::c_int {
    let mut index: libc::c_int = 0;
    if CRYPTO_get_ex_new_index(&mut g_ex_data_class, &mut index, argl, argp, free_func)
        == 0
    {
        return -(1 as libc::c_int);
    }
    return index;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set_ex_data(
    mut r: *mut X509,
    mut idx: libc::c_int,
    mut arg: *mut libc::c_void,
) -> libc::c_int {
    return CRYPTO_set_ex_data(&mut (*r).ex_data, idx, arg);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get_ex_data(
    mut r: *mut X509,
    mut idx: libc::c_int,
) -> *mut libc::c_void {
    return CRYPTO_get_ex_data(&mut (*r).ex_data, idx);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_X509_AUX(
    mut a: *mut *mut X509,
    mut pp: *mut *const libc::c_uchar,
    mut length: libc::c_long,
) -> *mut X509 {
    let mut q: *const libc::c_uchar = *pp;
    let mut ret: *mut X509 = 0 as *mut X509;
    let mut freeret: libc::c_int = 0 as libc::c_int;
    if a.is_null() || (*a).is_null() {
        freeret = 1 as libc::c_int;
    }
    ret = d2i_X509(a, &mut q, length);
    if ret.is_null() {
        return 0 as *mut X509;
    }
    length -= q.offset_from(*pp) as libc::c_long;
    if length > 0 as libc::c_int as libc::c_long
        && (d2i_X509_CERT_AUX(&mut (*ret).aux, &mut q, length)).is_null()
    {
        if freeret != 0 {
            X509_free(ret);
            if !a.is_null() {
                *a = 0 as *mut X509;
            }
        }
        return 0 as *mut X509;
    } else {
        *pp = q;
        return ret;
    };
}
unsafe extern "C" fn i2d_x509_aux_internal(
    mut a: *mut X509,
    mut pp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    let mut length: libc::c_int = 0;
    let mut tmplen: libc::c_int = 0;
    let mut start: *mut libc::c_uchar = if !pp.is_null() {
        *pp
    } else {
        0 as *mut libc::c_uchar
    };
    if pp.is_null() || !(*pp).is_null() {} else {
        __assert_fail(
            b"pp == NULL || *pp != NULL\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0" as *const u8
                as *const libc::c_char,
            270 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 52],
                &[libc::c_char; 52],
            >(b"int i2d_x509_aux_internal(X509 *, unsigned char **)\0"))
                .as_ptr(),
        );
    }
    'c_17914: {
        if pp.is_null() || !(*pp).is_null() {} else {
            __assert_fail(
                b"pp == NULL || *pp != NULL\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/x509/x_x509.c\0" as *const u8
                    as *const libc::c_char,
                270 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 52],
                    &[libc::c_char; 52],
                >(b"int i2d_x509_aux_internal(X509 *, unsigned char **)\0"))
                    .as_ptr(),
            );
        }
    };
    length = i2d_X509(a, pp);
    if length <= 0 as libc::c_int || a.is_null() {
        return length;
    }
    if !((*a).aux).is_null() {
        tmplen = i2d_X509_CERT_AUX((*a).aux, pp);
        if tmplen < 0 as libc::c_int {
            if !start.is_null() {
                *pp = start;
            }
            return tmplen;
        }
        length += tmplen;
    }
    return length;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_AUX(
    mut a: *mut X509,
    mut pp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    let mut length: libc::c_int = 0;
    let mut tmp: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    if pp.is_null() || !(*pp).is_null() {
        return i2d_x509_aux_internal(a, pp);
    }
    length = i2d_x509_aux_internal(a, 0 as *mut *mut libc::c_uchar);
    if length <= 0 as libc::c_int {
        return length;
    }
    tmp = OPENSSL_malloc(length as size_t) as *mut libc::c_uchar;
    *pp = tmp;
    if tmp.is_null() {
        return -(1 as libc::c_int);
    }
    length = i2d_x509_aux_internal(a, &mut tmp);
    if length <= 0 as libc::c_int {
        OPENSSL_free(*pp as *mut libc::c_void);
        *pp = 0 as *mut libc::c_uchar;
    }
    return length;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_re_X509_tbs(
    mut x509: *mut X509,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    asn1_encoding_clear(&mut (*(*x509).cert_info).enc);
    return i2d_X509_CINF((*x509).cert_info, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_X509_tbs(
    mut x509: *mut X509,
    mut outp: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return i2d_X509_CINF((*x509).cert_info, outp);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set1_signature_algo(
    mut x509: *mut X509,
    mut algo: *const X509_ALGOR,
) -> libc::c_int {
    let mut copy1: *mut X509_ALGOR = X509_ALGOR_dup(algo);
    let mut copy2: *mut X509_ALGOR = X509_ALGOR_dup(algo);
    if copy1.is_null() || copy2.is_null() {
        X509_ALGOR_free(copy1);
        X509_ALGOR_free(copy2);
        return 0 as libc::c_int;
    }
    X509_ALGOR_free((*x509).sig_alg);
    (*x509).sig_alg = copy1;
    X509_ALGOR_free((*(*x509).cert_info).signature);
    (*(*x509).cert_info).signature = copy2;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_set1_signature_value(
    mut x509: *mut X509,
    mut sig: *const uint8_t,
    mut sig_len: size_t,
) -> libc::c_int {
    if ASN1_STRING_set(
        (*x509).signature,
        sig as *const libc::c_void,
        sig_len as ossl_ssize_t,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    (*(*x509).signature).flags
        &= !(0x8 as libc::c_int | 0x7 as libc::c_int) as libc::c_long;
    (*(*x509).signature).flags |= 0x8 as libc::c_int as libc::c_long;
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get0_signature(
    mut psig: *mut *const ASN1_BIT_STRING,
    mut palg: *mut *const X509_ALGOR,
    mut x: *const X509,
) {
    if !psig.is_null() {
        *psig = (*x).signature;
    }
    if !palg.is_null() {
        *palg = (*x).sig_alg;
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn X509_get_signature_nid(mut x: *const X509) -> libc::c_int {
    return OBJ_obj2nid((*(*x).sig_alg).algorithm);
}
unsafe extern "C" fn run_static_initializers() {
    X509_CINF_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_CINF_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 10]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &X509_CINF_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<X509_CINF>() as libc::c_ulong as libc::c_long,
            sname: b"X509_CINF\0" as *const u8 as *const libc::c_char,
        };
        init
    };
    X509_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: X509_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 3]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: &X509_aux as *const ASN1_AUX as *const libc::c_void,
            size: ::core::mem::size_of::<X509>() as libc::c_ulong as libc::c_long,
            sname: b"X509\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
