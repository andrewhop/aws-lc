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
    pub type asn1_object_st;
    pub type ASN1_VALUE_st;
    pub type evp_cipher_st;
    pub type evp_pkey_st;
    pub type x509_st;
    pub type X509_sig_st;
    pub type stack_st_void;
    pub type env_md_st;
    pub type stack_st_X509;
    pub type stack_st_X509_ATTRIBUTE;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type stack_st;
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
    static ASN1_OCTET_STRING_it: ASN1_ITEM;
    static ASN1_INTEGER_it: ASN1_ITEM;
    fn X509_free(x509: *mut X509);
    fn d2i_X509(
        out: *mut *mut X509,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509;
    fn i2d_X509(x509: *mut X509, outp: *mut *mut uint8_t) -> libc::c_int;
    fn X509_check_private_key(x509: *const X509, pkey: *const EVP_PKEY) -> libc::c_int;
    fn X509_alias_set1(
        x509: *mut X509,
        name: *const uint8_t,
        len: ossl_ssize_t,
    ) -> libc::c_int;
    fn X509_alias_get0(x509: *const X509, out_len: *mut libc::c_int) -> *const uint8_t;
    static X509_ALGOR_it: ASN1_ITEM;
    static X509_ATTRIBUTE_it: ASN1_ITEM;
    fn X509_SIG_free(key: *mut X509_SIG);
    fn d2i_X509_SIG(
        out: *mut *mut X509_SIG,
        inp: *mut *const uint8_t,
        len: libc::c_long,
    ) -> *mut X509_SIG;
    fn i2d_X509_SIG(sig: *const X509_SIG, outp: *mut *mut uint8_t) -> libc::c_int;
    fn X509_digest(
        x509: *const X509,
        md: *const EVP_MD,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> libc::c_int;
    fn EVP_CIPHER_CTX_init(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_cleanup(ctx: *mut EVP_CIPHER_CTX) -> libc::c_int;
    fn EVP_CipherUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
        in_0: *const uint8_t,
        in_len: libc::c_int,
    ) -> libc::c_int;
    fn EVP_CipherFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut uint8_t,
        out_len: *mut libc::c_int,
    ) -> libc::c_int;
    fn EVP_CIPHER_CTX_block_size(ctx: *const EVP_CIPHER_CTX) -> libc::c_uint;
    fn BIO_free(bio: *mut BIO) -> libc::c_int;
    fn BIO_read(bio: *mut BIO, data: *mut libc::c_void, len: libc::c_int) -> libc::c_int;
    fn BIO_write_all(
        bio: *mut BIO,
        data: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn BIO_new_fp(stream: *mut FILE, close_flag: libc::c_int) -> *mut BIO;
    fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_num(sk: *const OPENSSL_STACK) -> size_t;
    fn OPENSSL_sk_value(sk: *const OPENSSL_STACK, i: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_free(sk: *mut OPENSSL_STACK);
    fn OPENSSL_sk_pop_free_ex(
        sk: *mut OPENSSL_STACK,
        call_free_func: OPENSSL_sk_call_free_func,
        free_func: OPENSSL_sk_free_func,
    );
    fn OPENSSL_sk_delete(sk: *mut OPENSSL_STACK, where_0: size_t) -> *mut libc::c_void;
    fn OPENSSL_sk_push(sk: *mut OPENSSL_STACK, p: *mut libc::c_void) -> size_t;
    fn OPENSSL_sk_pop(sk: *mut OPENSSL_STACK) -> *mut libc::c_void;
    fn BUF_MEM_new() -> *mut BUF_MEM;
    fn BUF_MEM_free(buf: *mut BUF_MEM);
    fn BUF_MEM_grow(buf: *mut BUF_MEM, len: size_t) -> size_t;
    fn CBS_init(cbs: *mut CBS, data: *const uint8_t, len: size_t);
    fn CBS_data(cbs: *const CBS) -> *const uint8_t;
    fn CBS_len(cbs: *const CBS) -> size_t;
    fn CBS_mem_equal(cbs: *const CBS, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBS_get_asn1(
        cbs: *mut CBS,
        out: *mut CBS,
        tag_value: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBS_get_asn1_uint64(cbs: *mut CBS, out: *mut uint64_t) -> libc::c_int;
    fn CBB_init(cbb: *mut CBB, initial_capacity: size_t) -> libc::c_int;
    fn CBB_cleanup(cbb: *mut CBB);
    fn CBB_finish(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        out_len: *mut size_t,
    ) -> libc::c_int;
    fn CBB_flush(cbb: *mut CBB) -> libc::c_int;
    fn CBB_data(cbb: *const CBB) -> *const uint8_t;
    fn CBB_len(cbb: *const CBB) -> size_t;
    fn CBB_add_asn1(
        cbb: *mut CBB,
        out_contents: *mut CBB,
        tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn CBB_add_bytes(cbb: *mut CBB, data: *const uint8_t, len: size_t) -> libc::c_int;
    fn CBB_add_space(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CBB_reserve(
        cbb: *mut CBB,
        out_data: *mut *mut uint8_t,
        len: size_t,
    ) -> libc::c_int;
    fn CBB_did_write(cbb: *mut CBB, len: size_t) -> libc::c_int;
    fn CBB_add_asn1_uint64(cbb: *mut CBB, value: uint64_t) -> libc::c_int;
    fn CBB_flush_asn1_set_of(cbb: *mut CBB) -> libc::c_int;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_MD_size(md: *const EVP_MD) -> size_t;
    fn EVP_parse_digest_algorithm(cbs: *mut CBS) -> *const EVP_MD;
    fn EVP_marshal_digest_algorithm(cbb: *mut CBB, md: *const EVP_MD) -> libc::c_int;
    fn HMAC(
        evp_md: *const EVP_MD,
        key: *const libc::c_void,
        key_len: size_t,
        data: *const uint8_t,
        data_len: size_t,
        out: *mut uint8_t,
        out_len: *mut libc::c_uint,
    ) -> *mut uint8_t;
    fn pkcs8_pbe_decrypt(
        out: *mut *mut uint8_t,
        out_len: *mut size_t,
        algorithm: *mut CBS,
        pass: *const libc::c_char,
        pass_len: size_t,
        in_0: *const uint8_t,
        in_len: size_t,
    ) -> libc::c_int;
    fn pkcs12_key_gen(
        pass: *const libc::c_char,
        pass_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
        id: uint8_t,
        iterations: uint32_t,
        out_len: size_t,
        out: *mut uint8_t,
        md: *const EVP_MD,
    ) -> libc::c_int;
    fn pkcs12_pbe_encrypt_init(
        out: *mut CBB,
        ctx: *mut EVP_CIPHER_CTX,
        alg: libc::c_int,
        iterations: uint32_t,
        pass: *const libc::c_char,
        pass_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
    ) -> libc::c_int;
    fn RAND_bytes(buf: *mut uint8_t, len: size_t) -> libc::c_int;
    fn OPENSSL_malloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_zalloc(size: size_t) -> *mut libc::c_void;
    fn OPENSSL_free(ptr: *mut libc::c_void);
    fn OPENSSL_cleanse(ptr: *mut libc::c_void, len: size_t);
    fn OPENSSL_memdup(data: *const libc::c_void, size: size_t) -> *mut libc::c_void;
    fn ERR_clear_error();
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_parse_private_key(cbs: *mut CBS) -> *mut EVP_PKEY;
    fn EVP_marshal_private_key(cbb: *mut CBB, key: *const EVP_PKEY) -> libc::c_int;
    fn PKCS8_marshal_encrypted_private_key(
        out: *mut CBB,
        pbe_nid: libc::c_int,
        cipher: *const EVP_CIPHER,
        pass: *const libc::c_char,
        pass_len: size_t,
        salt: *const uint8_t,
        salt_len: size_t,
        iterations: libc::c_int,
        pkey: *const EVP_PKEY,
    ) -> libc::c_int;
    fn PKCS8_parse_encrypted_private_key(
        cbs: *mut CBS,
        pass: *const libc::c_char,
        pass_len: size_t,
    ) -> *mut EVP_PKEY;
    fn CBS_asn1_ber_to_der(
        in_0: *mut CBS,
        out: *mut CBS,
        out_storage: *mut *mut uint8_t,
    ) -> libc::c_int;
    fn CBS_get_asn1_implicit_string(
        in_0: *mut CBS,
        out: *mut CBS,
        out_storage: *mut *mut uint8_t,
        outer_tag: CBS_ASN1_TAG,
        inner_tag: CBS_ASN1_TAG,
    ) -> libc::c_int;
    fn cbs_get_utf8(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn cbs_get_ucs2_be(cbs: *mut CBS, out: *mut uint32_t) -> libc::c_int;
    fn cbb_add_utf8(cbb: *mut CBB, u: uint32_t) -> libc::c_int;
    fn cbb_add_ucs2_be(cbb: *mut CBB, u: uint32_t) -> libc::c_int;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type ptrdiff_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type ossl_ssize_t = ptrdiff_t;
pub type CBS_ASN1_TAG = uint32_t;
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
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_PKEY = evp_pkey_st;
pub type X509 = x509_st;
pub type X509_SIG = X509_sig_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_method_st {
    pub type_0: libc::c_int,
    pub name: *const libc::c_char,
    pub bwrite: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bread: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub bputs: Option::<
        unsafe extern "C" fn(*mut BIO, *const libc::c_char) -> libc::c_int,
    >,
    pub bgets: Option::<
        unsafe extern "C" fn(*mut BIO, *mut libc::c_char, libc::c_int) -> libc::c_int,
    >,
    pub ctrl: Option::<
        unsafe extern "C" fn(
            *mut BIO,
            libc::c_int,
            libc::c_long,
            *mut libc::c_void,
        ) -> libc::c_long,
    >,
    pub create: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub destroy: Option::<unsafe extern "C" fn(*mut BIO) -> libc::c_int>,
    pub callback_ctrl: Option::<
        unsafe extern "C" fn(*mut BIO, libc::c_int, bio_info_cb) -> libc::c_long,
    >,
}
pub type bio_info_cb = Option::<
    unsafe extern "C" fn(*mut BIO, libc::c_int, libc::c_int) -> libc::c_long,
>;
pub type BIO = bio_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bio_st {
    pub method: *const BIO_METHOD,
    pub ex_data: CRYPTO_EX_DATA,
    pub callback_ex: BIO_callback_fn_ex,
    pub callback: BIO_callback_fn,
    pub cb_arg: *mut libc::c_char,
    pub init: libc::c_int,
    pub shutdown: libc::c_int,
    pub flags: libc::c_int,
    pub retry_reason: libc::c_int,
    pub num: libc::c_int,
    pub references: CRYPTO_refcount_t,
    pub ptr: *mut libc::c_void,
    pub next_bio: *mut BIO,
    pub num_read: uint64_t,
    pub num_write: uint64_t,
}
pub type CRYPTO_refcount_t = uint32_t;
pub type BIO_callback_fn = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        libc::c_long,
        libc::c_long,
    ) -> libc::c_long,
>;
pub type BIO_callback_fn_ex = Option::<
    unsafe extern "C" fn(
        *mut BIO,
        libc::c_int,
        *const libc::c_char,
        size_t,
        libc::c_int,
        libc::c_long,
        libc::c_int,
        *mut size_t,
    ) -> libc::c_long,
>;
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type BIO_METHOD = bio_method_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut libc::c_char,
    pub max: size_t,
}
pub type BUF_MEM = buf_mem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cbb_st {
    pub child: *mut CBB,
    pub is_child: libc::c_char,
    pub u: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
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
pub type EVP_MD = env_md_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_ctx_st {
    pub cipher: *const EVP_CIPHER,
    pub app_data: *mut libc::c_void,
    pub cipher_data: *mut libc::c_void,
    pub key_len: libc::c_uint,
    pub encrypt: libc::c_int,
    pub flags: uint32_t,
    pub oiv: [uint8_t; 16],
    pub iv: [uint8_t; 16],
    pub buf: [uint8_t; 32],
    pub buf_len: libc::c_int,
    pub num: libc::c_uint,
    pub final_used: libc::c_int,
    pub final_0: [uint8_t; 32],
    pub poisoned: libc::c_int,
}
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs12_st {
    pub ber_bytes: *mut uint8_t,
    pub ber_len: size_t,
}
pub type PKCS12 = pkcs12_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs8_priv_key_info_st {
    pub version: *mut ASN1_INTEGER,
    pub pkeyalg: *mut X509_ALGOR,
    pub pkey: *mut ASN1_OCTET_STRING,
    pub attributes: *mut stack_st_X509_ATTRIBUTE,
}
pub type PKCS8_PRIV_KEY_INFO = pkcs8_priv_key_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type OPENSSL_sk_free_func = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type OPENSSL_sk_call_free_func = Option::<
    unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
>;
pub type OPENSSL_STACK = stack_st;
pub type sk_X509_free_func = Option::<unsafe extern "C" fn(*mut X509) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs12_context {
    pub out_key: *mut *mut EVP_PKEY,
    pub out_certs: *mut stack_st_X509,
    pub password: *const libc::c_char,
    pub password_len: size_t,
}
#[inline]
unsafe extern "C" fn sk_X509_call_free_func(
    mut free_func: OPENSSL_sk_free_func,
    mut ptr: *mut libc::c_void,
) {
    (::core::mem::transmute::<OPENSSL_sk_free_func, sk_X509_free_func>(free_func))
        .expect("non-null function pointer")(ptr as *mut X509);
}
#[inline]
unsafe extern "C" fn sk_X509_new_null() -> *mut stack_st_X509 {
    return OPENSSL_sk_new_null() as *mut stack_st_X509;
}
#[inline]
unsafe extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> size_t {
    return OPENSSL_sk_num(sk as *const OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_value(
    mut sk: *const stack_st_X509,
    mut i: size_t,
) -> *mut X509 {
    return OPENSSL_sk_value(sk as *const OPENSSL_STACK, i) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_free(mut sk: *mut stack_st_X509) {
    OPENSSL_sk_free(sk as *mut OPENSSL_STACK);
}
#[inline]
unsafe extern "C" fn sk_X509_pop_free(
    mut sk: *mut stack_st_X509,
    mut free_func: sk_X509_free_func,
) {
    OPENSSL_sk_pop_free_ex(
        sk as *mut OPENSSL_STACK,
        Some(
            sk_X509_call_free_func
                as unsafe extern "C" fn(OPENSSL_sk_free_func, *mut libc::c_void) -> (),
        ),
        ::core::mem::transmute::<sk_X509_free_func, OPENSSL_sk_free_func>(free_func),
    );
}
#[inline]
unsafe extern "C" fn sk_X509_delete(
    mut sk: *mut stack_st_X509,
    mut where_0: size_t,
) -> *mut X509 {
    return OPENSSL_sk_delete(sk as *mut OPENSSL_STACK, where_0) as *mut X509;
}
#[inline]
unsafe extern "C" fn sk_X509_push(
    mut sk: *mut stack_st_X509,
    mut p: *mut X509,
) -> size_t {
    return OPENSSL_sk_push(sk as *mut OPENSSL_STACK, p as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn sk_X509_pop(mut sk: *mut stack_st_X509) -> *mut X509 {
    return OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) as *mut X509;
}
#[inline]
unsafe extern "C" fn OPENSSL_memchr(
    mut s: *const libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as size_t {
        return 0 as *mut libc::c_void;
    }
    return memchr(s, c, n);
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkcs12_iterations_acceptable(
    mut iterations: uint64_t,
) -> libc::c_int {
    static mut kIterationsLimit: uint64_t = (100 as libc::c_int * 1000000 as libc::c_int)
        as uint64_t;
    if kIterationsLimit <= 4294967295 as libc::c_uint as uint64_t {} else {
        __assert_fail(
            b"kIterationsLimit <= UINT32_MAX\0" as *const u8 as *const libc::c_char,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            90 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<
                &[u8; 43],
                &[libc::c_char; 43],
            >(b"int pkcs12_iterations_acceptable(uint64_t)\0"))
                .as_ptr(),
        );
    }
    'c_28726: {
        if kIterationsLimit <= 4294967295 as libc::c_uint as uint64_t {} else {
            __assert_fail(
                b"kIterationsLimit <= UINT32_MAX\0" as *const u8 as *const libc::c_char,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                90 as libc::c_int as libc::c_uint,
                (*::core::mem::transmute::<
                    &[u8; 43],
                    &[libc::c_char; 43],
                >(b"int pkcs12_iterations_acceptable(uint64_t)\0"))
                    .as_ptr(),
            );
        }
    };
    return ((0 as libc::c_int as uint64_t) < iterations
        && iterations <= kIterationsLimit) as libc::c_int;
}
static mut PKCS8_PRIV_KEY_INFO_seq_tt: [ASN1_TEMPLATE; 4] = unsafe {
    [
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
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
                field_name: b"pkeyalg\0" as *const u8 as *const libc::c_char,
                item: &X509_ALGOR_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: 0 as libc::c_int as uint32_t,
                tag: 0 as libc::c_int,
                offset: 16 as libc::c_ulong,
                field_name: b"pkey\0" as *const u8 as *const libc::c_char,
                item: &ASN1_OCTET_STRING_it as *const ASN1_ITEM,
            };
            init
        },
        {
            let mut init = ASN1_TEMPLATE_st {
                flags: ((0x1 as libc::c_int) << 3 as libc::c_int
                    | (0x2 as libc::c_int) << 6 as libc::c_int
                    | (0x1 as libc::c_int) << 1 as libc::c_int | 0x1 as libc::c_int)
                    as uint32_t,
                tag: 0 as libc::c_int,
                offset: 24 as libc::c_ulong,
                field_name: b"attributes\0" as *const u8 as *const libc::c_char,
                item: &X509_ATTRIBUTE_it as *const ASN1_ITEM,
            };
            init
        },
    ]
};
#[unsafe(no_mangle)]
pub static mut PKCS8_PRIV_KEY_INFO_it: ASN1_ITEM = ASN1_ITEM_st {
    itype: 0,
    utype: 0,
    templates: 0 as *const ASN1_TEMPLATE,
    tcount: 0,
    funcs: 0 as *const libc::c_void,
    size: 0,
    sname: 0 as *const libc::c_char,
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS8_PRIV_KEY_INFO_free(mut a: *mut PKCS8_PRIV_KEY_INFO) {
    ASN1_item_free(a as *mut ASN1_VALUE, &PKCS8_PRIV_KEY_INFO_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS8_PRIV_KEY_INFO(
    mut a: *const PKCS8_PRIV_KEY_INFO,
    mut out: *mut *mut libc::c_uchar,
) -> libc::c_int {
    return ASN1_item_i2d(a as *mut ASN1_VALUE, out, &PKCS8_PRIV_KEY_INFO_it);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS8_PRIV_KEY_INFO_new() -> *mut PKCS8_PRIV_KEY_INFO {
    return ASN1_item_new(&PKCS8_PRIV_KEY_INFO_it) as *mut PKCS8_PRIV_KEY_INFO;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS8_PRIV_KEY_INFO(
    mut a: *mut *mut PKCS8_PRIV_KEY_INFO,
    mut in_0: *mut *const libc::c_uchar,
    mut len: libc::c_long,
) -> *mut PKCS8_PRIV_KEY_INFO {
    return ASN1_item_d2i(a as *mut *mut ASN1_VALUE, in_0, len, &PKCS8_PRIV_KEY_INFO_it)
        as *mut PKCS8_PRIV_KEY_INFO;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKCS82PKEY(
    mut p8: *const PKCS8_PRIV_KEY_INFO,
) -> *mut EVP_PKEY {
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    let mut der_len: libc::c_int = i2d_PKCS8_PRIV_KEY_INFO(p8, &mut der);
    if der_len < 0 as libc::c_int {
        return 0 as *mut EVP_PKEY;
    }
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    CBS_init(&mut cbs, der, der_len as size_t);
    let mut ret: *mut EVP_PKEY = EVP_parse_private_key(&mut cbs);
    if ret.is_null() || CBS_len(&mut cbs) != 0 as libc::c_int as size_t {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            104 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            114 as libc::c_int as libc::c_uint,
        );
        EVP_PKEY_free(ret);
        OPENSSL_free(der as *mut libc::c_void);
        return 0 as *mut EVP_PKEY;
    }
    OPENSSL_free(der as *mut libc::c_void);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EVP_PKEY2PKCS8(
    mut pkey: *const EVP_PKEY,
) -> *mut PKCS8_PRIV_KEY_INFO {
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let mut p8: *mut PKCS8_PRIV_KEY_INFO = 0 as *mut PKCS8_PRIV_KEY_INFO;
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    let mut der_len: size_t = 0;
    if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || EVP_marshal_private_key(&mut cbb, pkey) == 0
        || CBB_finish(&mut cbb, &mut der, &mut der_len) == 0
        || der_len > 9223372036854775807 as libc::c_long as size_t
    {
        CBB_cleanup(&mut cbb);
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            105 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            133 as libc::c_int as libc::c_uint,
        );
    } else {
        p = der;
        p8 = d2i_PKCS8_PRIV_KEY_INFO(
            0 as *mut *mut PKCS8_PRIV_KEY_INFO,
            &mut p,
            der_len as libc::c_long,
        );
        if p8.is_null() || p != der.offset(der_len as isize) as *const uint8_t {
            PKCS8_PRIV_KEY_INFO_free(p8);
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                104 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                141 as libc::c_int as libc::c_uint,
            );
        } else {
            OPENSSL_free(der as *mut libc::c_void);
            return p8;
        }
    }
    OPENSSL_free(der as *mut libc::c_void);
    return 0 as *mut PKCS8_PRIV_KEY_INFO;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS8_decrypt(
    mut pkcs8: *mut X509_SIG,
    mut pass: *const libc::c_char,
    mut pass_len_in: libc::c_int,
) -> *mut PKCS8_PRIV_KEY_INFO {
    let mut cbs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut pass_len: size_t = 0;
    if pass_len_in == -(1 as libc::c_int) && !pass.is_null() {
        pass_len = strlen(pass);
    } else {
        pass_len = pass_len_in as size_t;
    }
    let mut ret: *mut PKCS8_PRIV_KEY_INFO = 0 as *mut PKCS8_PRIV_KEY_INFO;
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut in_0: *mut uint8_t = 0 as *mut uint8_t;
    let mut in_len: libc::c_int = i2d_X509_SIG(pkcs8, &mut in_0);
    if !(in_len < 0 as libc::c_int) {
        cbs = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        CBS_init(&mut cbs, in_0, in_len as size_t);
        pkey = PKCS8_parse_encrypted_private_key(&mut cbs, pass, pass_len);
        if !(pkey.is_null() || CBS_len(&mut cbs) != 0 as libc::c_int as size_t) {
            ret = EVP_PKEY2PKCS8(pkey);
        }
    }
    OPENSSL_free(in_0 as *mut libc::c_void);
    EVP_PKEY_free(pkey);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS8_encrypt(
    mut pbe_nid: libc::c_int,
    mut cipher: *const EVP_CIPHER,
    mut pass: *const libc::c_char,
    mut pass_len_in: libc::c_int,
    mut salt: *const uint8_t,
    mut salt_len: size_t,
    mut iterations: libc::c_int,
    mut p8inf: *mut PKCS8_PRIV_KEY_INFO,
) -> *mut X509_SIG {
    let mut ptr: *const uint8_t = 0 as *const uint8_t;
    let mut pass_len: size_t = 0;
    if pass_len_in < 0 as libc::c_int && !pass.is_null() {
        pass_len = strlen(pass);
    } else {
        pass_len = pass_len_in as size_t;
    }
    let mut pkey: *mut EVP_PKEY = EVP_PKCS82PKEY(p8inf);
    if pkey.is_null() {
        return 0 as *mut X509_SIG;
    }
    let mut ret: *mut X509_SIG = 0 as *mut X509_SIG;
    let mut der: *mut uint8_t = 0 as *mut uint8_t;
    let mut der_len: size_t = 0;
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if CBB_init(&mut cbb, 128 as libc::c_int as size_t) == 0
        || PKCS8_marshal_encrypted_private_key(
            &mut cbb,
            pbe_nid,
            cipher,
            pass,
            pass_len,
            salt,
            salt_len,
            iterations,
            pkey,
        ) == 0 || CBB_finish(&mut cbb, &mut der, &mut der_len) == 0
    {
        CBB_cleanup(&mut cbb);
    } else {
        ptr = der;
        ret = d2i_X509_SIG(0 as *mut *mut X509_SIG, &mut ptr, der_len as libc::c_long);
        if ret.is_null() || ptr != der.offset(der_len as isize) as *const uint8_t {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                4 as libc::c_int | 64 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                220 as libc::c_int as libc::c_uint,
            );
            X509_SIG_free(ret);
            ret = 0 as *mut X509_SIG;
        }
    }
    OPENSSL_free(der as *mut libc::c_void);
    EVP_PKEY_free(pkey);
    return ret;
}
unsafe extern "C" fn PKCS12_handle_sequence(
    mut sequence: *mut CBS,
    mut ctx: *mut pkcs12_context,
    mut handle_element: Option::<
        unsafe extern "C" fn(*mut CBS, *mut pkcs12_context) -> libc::c_int,
    >,
) -> libc::c_int {
    let mut current_block: u64;
    let mut storage: *mut uint8_t = 0 as *mut uint8_t;
    let mut in_0: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    if CBS_asn1_ber_to_der(sequence, &mut in_0, &mut storage) == 0 {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            252 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut child: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(
        &mut in_0,
        &mut child,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_len(&mut in_0) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            259 as libc::c_int as libc::c_uint,
        );
    } else {
        loop {
            if !(CBS_len(&mut child) > 0 as libc::c_int as size_t) {
                current_block = 7746791466490516765;
                break;
            }
            let mut element: CBS = cbs_st {
                data: 0 as *const uint8_t,
                len: 0,
            };
            if CBS_get_asn1(
                &mut child,
                &mut element,
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0
            {
                ERR_put_error(
                    19 as libc::c_int,
                    0 as libc::c_int,
                    100 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    266 as libc::c_int as libc::c_uint,
                );
                current_block = 16043195130373502782;
                break;
            } else if handle_element
                .expect("non-null function pointer")(&mut element, ctx) == 0
            {
                current_block = 16043195130373502782;
                break;
            }
        }
        match current_block {
            16043195130373502782 => {}
            _ => {
                ret = 1 as libc::c_int;
            }
        }
    }
    OPENSSL_free(storage as *mut libc::c_void);
    return ret;
}
static mut kKeyBag: [uint8_t; 11] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
];
static mut kPKCS8ShroudedKeyBag: [uint8_t; 11] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
];
static mut kCertBag: [uint8_t; 11] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
];
static mut kFriendlyName: [uint8_t; 9] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
];
static mut kLocalKeyID: [uint8_t; 9] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
];
static mut kX509Certificate: [uint8_t; 10] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
];
unsafe extern "C" fn parse_bag_attributes(
    mut attrs: *mut CBS,
    mut out_friendly_name: *mut *mut uint8_t,
    mut out_friendly_name_len: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    *out_friendly_name = 0 as *mut uint8_t;
    *out_friendly_name_len = 0 as libc::c_int as size_t;
    's_7: loop {
        if !(CBS_len(attrs) != 0 as libc::c_int as size_t) {
            current_block = 4956146061682418353;
            break;
        }
        let mut attr: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut oid: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut values: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(
            attrs,
            &mut attr,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut attr, &mut oid, 0x6 as libc::c_uint) == 0
            || CBS_get_asn1(
                &mut attr,
                &mut values,
                0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0 || CBS_len(&mut attr) != 0 as libc::c_int as size_t
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                322 as libc::c_int as libc::c_uint,
            );
            current_block = 5313521349081233647;
            break;
        } else {
            if !(CBS_mem_equal(
                &mut oid,
                kFriendlyName.as_ptr(),
                ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
            ) != 0)
            {
                continue;
            }
            let mut value: CBS = cbs_st {
                data: 0 as *const uint8_t,
                len: 0,
            };
            if !(*out_friendly_name).is_null()
                || CBS_get_asn1(&mut values, &mut value, 0x1e as libc::c_uint) == 0
                || CBS_len(&mut values) != 0 as libc::c_int as size_t
                || CBS_len(&mut value) == 0 as libc::c_int as size_t
            {
                ERR_put_error(
                    19 as libc::c_int,
                    0 as libc::c_int,
                    100 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    332 as libc::c_int as libc::c_uint,
                );
                current_block = 5313521349081233647;
                break;
            } else {
                let mut cbb: CBB = cbb_st {
                    child: 0 as *mut CBB,
                    is_child: 0,
                    u: C2RustUnnamed_0 {
                        base: cbb_buffer_st {
                            buf: 0 as *mut uint8_t,
                            len: 0,
                            cap: 0,
                            can_resize_error: [0; 1],
                            c2rust_padding: [0; 7],
                        },
                    },
                };
                if CBB_init(&mut cbb, CBS_len(&mut value)) == 0 {
                    current_block = 5313521349081233647;
                    break;
                }
                while CBS_len(&mut value) != 0 as libc::c_int as size_t {
                    let mut c: uint32_t = 0;
                    if !(cbs_get_ucs2_be(&mut value, &mut c) == 0
                        || cbb_add_utf8(&mut cbb, c) == 0)
                    {
                        continue;
                    }
                    ERR_put_error(
                        19 as libc::c_int,
                        0 as libc::c_int,
                        131 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                            as *const u8 as *const libc::c_char,
                        344 as libc::c_int as libc::c_uint,
                    );
                    CBB_cleanup(&mut cbb);
                    current_block = 5313521349081233647;
                    break 's_7;
                }
                if !(CBB_finish(&mut cbb, out_friendly_name, out_friendly_name_len) == 0)
                {
                    continue;
                }
                CBB_cleanup(&mut cbb);
                current_block = 5313521349081233647;
                break;
            }
        }
    }
    match current_block {
        4956146061682418353 => return 1 as libc::c_int,
        _ => {
            OPENSSL_free(*out_friendly_name as *mut libc::c_void);
            *out_friendly_name = 0 as *mut uint8_t;
            *out_friendly_name_len = 0 as libc::c_int as size_t;
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn PKCS12_handle_safe_bag(
    mut safe_bag: *mut CBS,
    mut ctx: *mut pkcs12_context,
) -> libc::c_int {
    let mut bag_id: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut wrapped_value: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut bag_attrs: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    if CBS_get_asn1(safe_bag, &mut bag_id, 0x6 as libc::c_uint) == 0
        || CBS_get_asn1(
            safe_bag,
            &mut wrapped_value,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | (0x20 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            372 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    if CBS_len(safe_bag) == 0 as libc::c_int as size_t {
        CBS_init(&mut bag_attrs, 0 as *const uint8_t, 0 as libc::c_int as size_t);
    } else if CBS_get_asn1(
        safe_bag,
        &mut bag_attrs,
        0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_len(safe_bag) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            379 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let is_key_bag: libc::c_int = CBS_mem_equal(
        &mut bag_id,
        kKeyBag.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 11]>() as libc::c_ulong,
    );
    let is_shrouded_key_bag: libc::c_int = CBS_mem_equal(
        &mut bag_id,
        kPKCS8ShroudedKeyBag.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 11]>() as libc::c_ulong,
    );
    if is_key_bag != 0 || is_shrouded_key_bag != 0 {
        if !(*(*ctx).out_key).is_null() {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                113 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                389 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        let mut pkey: *mut EVP_PKEY = if is_key_bag != 0 {
            EVP_parse_private_key(&mut wrapped_value)
        } else {
            PKCS8_parse_encrypted_private_key(
                &mut wrapped_value,
                (*ctx).password,
                (*ctx).password_len,
            )
        };
        if pkey.is_null() {
            return 0 as libc::c_int;
        }
        if CBS_len(&mut wrapped_value) != 0 as libc::c_int as size_t {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                402 as libc::c_int as libc::c_uint,
            );
            EVP_PKEY_free(pkey);
            return 0 as libc::c_int;
        }
        *(*ctx).out_key = pkey;
        return 1 as libc::c_int;
    }
    if CBS_mem_equal(
        &mut bag_id,
        kCertBag.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 11]>() as libc::c_ulong,
    ) != 0
    {
        let mut cert_bag: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut cert_type: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut wrapped_cert: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut cert: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(
            &mut wrapped_value,
            &mut cert_bag,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBS_get_asn1(&mut cert_bag, &mut cert_type, 0x6 as libc::c_uint) == 0
            || CBS_get_asn1(
                &mut cert_bag,
                &mut wrapped_cert,
                (0x80 as libc::c_uint) << 24 as libc::c_int
                    | (0x20 as libc::c_uint) << 24 as libc::c_int
                    | 0 as libc::c_int as libc::c_uint,
            ) == 0
            || CBS_get_asn1(&mut wrapped_cert, &mut cert, 0x4 as libc::c_uint) == 0
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                419 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if CBS_mem_equal(
            &mut cert_type,
            kX509Certificate.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        ) == 0
        {
            return 1 as libc::c_int;
        }
        if CBS_len(&mut cert) > 9223372036854775807 as libc::c_long as size_t {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                430 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        let mut inp: *const uint8_t = CBS_data(&mut cert);
        let mut x509: *mut X509 = d2i_X509(
            0 as *mut *mut X509,
            &mut inp,
            CBS_len(&mut cert) as libc::c_long,
        );
        if x509.is_null() {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                437 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        if inp != (CBS_data(&mut cert)).offset(CBS_len(&mut cert) as isize) {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                442 as libc::c_int as libc::c_uint,
            );
            X509_free(x509);
            return 0 as libc::c_int;
        }
        let mut friendly_name: *mut uint8_t = 0 as *mut uint8_t;
        let mut friendly_name_len: size_t = 0;
        if parse_bag_attributes(
            &mut bag_attrs,
            &mut friendly_name,
            &mut friendly_name_len,
        ) == 0
        {
            X509_free(x509);
            return 0 as libc::c_int;
        }
        let mut ok: libc::c_int = (friendly_name_len == 0 as libc::c_int as size_t
            || X509_alias_set1(x509, friendly_name, friendly_name_len as ossl_ssize_t)
                != 0) as libc::c_int;
        OPENSSL_free(friendly_name as *mut libc::c_void);
        if ok == 0 || 0 as libc::c_int as size_t == sk_X509_push((*ctx).out_certs, x509)
        {
            X509_free(x509);
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    return 1 as libc::c_int;
}
static mut kPKCS7Data: [uint8_t; 9] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
];
static mut kPKCS7EncryptedData: [uint8_t; 9] = [
    0x2a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x48 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
];
unsafe extern "C" fn PKCS12_handle_content_info(
    mut content_info: *mut CBS,
    mut ctx: *mut pkcs12_context,
) -> libc::c_int {
    let mut content_type: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut wrapped_contents: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut contents: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut storage: *mut uint8_t = 0 as *mut uint8_t;
    if CBS_get_asn1(content_info, &mut content_type, 0x6 as libc::c_uint) == 0
        || CBS_get_asn1(
            content_info,
            &mut wrapped_contents,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | (0x20 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0 || CBS_len(content_info) != 0 as libc::c_int as size_t
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            489 as libc::c_int as libc::c_uint,
        );
    } else if CBS_mem_equal(
        &mut content_type,
        kPKCS7EncryptedData.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
    ) != 0
    {
        let mut version_bytes: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut eci: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut contents_type: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut ai: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut encrypted_contents: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut out: *mut uint8_t = 0 as *mut uint8_t;
        let mut out_len: size_t = 0;
        if CBS_get_asn1(
            &mut wrapped_contents,
            &mut contents,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
            || CBS_get_asn1(&mut contents, &mut version_bytes, 0x2 as libc::c_uint) == 0
            || CBS_get_asn1(
                &mut contents,
                &mut eci,
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0
            || CBS_get_asn1(&mut eci, &mut contents_type, 0x6 as libc::c_uint) == 0
            || CBS_get_asn1(
                &mut eci,
                &mut ai,
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0
            || CBS_get_asn1_implicit_string(
                &mut eci,
                &mut encrypted_contents,
                &mut storage,
                (0x80 as libc::c_uint) << 24 as libc::c_int
                    | 0 as libc::c_int as libc::c_uint,
                0x4 as libc::c_uint,
            ) == 0
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                516 as libc::c_int as libc::c_uint,
            );
        } else if CBS_mem_equal(
            &mut contents_type,
            kPKCS7Data.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                521 as libc::c_int as libc::c_uint,
            );
        } else if !(pkcs8_pbe_decrypt(
            &mut out,
            &mut out_len,
            &mut ai,
            (*ctx).password,
            (*ctx).password_len,
            CBS_data(&mut encrypted_contents),
            CBS_len(&mut encrypted_contents),
        ) == 0)
        {
            let mut safe_contents: CBS = cbs_st {
                data: 0 as *const uint8_t,
                len: 0,
            };
            CBS_init(&mut safe_contents, out, out_len);
            ret = PKCS12_handle_sequence(
                &mut safe_contents,
                ctx,
                Some(
                    PKCS12_handle_safe_bag
                        as unsafe extern "C" fn(
                            *mut CBS,
                            *mut pkcs12_context,
                        ) -> libc::c_int,
                ),
            );
            OPENSSL_free(out as *mut libc::c_void);
        }
    } else if CBS_mem_equal(
        &mut content_type,
        kPKCS7Data.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
    ) != 0
    {
        let mut octet_string_contents: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(
            &mut wrapped_contents,
            &mut octet_string_contents,
            0x4 as libc::c_uint,
        ) == 0
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                540 as libc::c_int as libc::c_uint,
            );
        } else {
            ret = PKCS12_handle_sequence(
                &mut octet_string_contents,
                ctx,
                Some(
                    PKCS12_handle_safe_bag
                        as unsafe extern "C" fn(
                            *mut CBS,
                            *mut pkcs12_context,
                        ) -> libc::c_int,
                ),
            );
        }
    } else {
        ret = 1 as libc::c_int;
    }
    OPENSSL_free(storage as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn pkcs12_check_mac(
    mut out_mac_ok: *mut libc::c_int,
    mut password: *const libc::c_char,
    mut password_len: size_t,
    mut salt: *const CBS,
    mut iterations: uint32_t,
    mut md: *const EVP_MD,
    mut authsafes: *const CBS,
    mut expected_mac: *const CBS,
) -> libc::c_int {
    let mut hmac: [uint8_t; 64] = [0; 64];
    let mut hmac_len: libc::c_uint = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut hmac_key: [uint8_t; 64] = [0; 64];
    if !(pkcs12_key_gen(
        password,
        password_len,
        CBS_data(salt),
        CBS_len(salt),
        3 as libc::c_int as uint8_t,
        iterations,
        EVP_MD_size(md),
        hmac_key.as_mut_ptr(),
        md,
    ) == 0)
    {
        hmac = [0; 64];
        hmac_len = 0;
        if !(HMAC(
            md,
            hmac_key.as_mut_ptr() as *const libc::c_void,
            EVP_MD_size(md),
            CBS_data(authsafes),
            CBS_len(authsafes),
            hmac.as_mut_ptr(),
            &mut hmac_len,
        ))
            .is_null()
        {
            *out_mac_ok = CBS_mem_equal(
                expected_mac,
                hmac.as_mut_ptr(),
                hmac_len as size_t,
            );
            ret = 1 as libc::c_int;
        }
    }
    OPENSSL_cleanse(
        hmac_key.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS12_get_key_and_certs(
    mut out_key: *mut *mut EVP_PKEY,
    mut out_certs: *mut stack_st_X509,
    mut ber_in: *mut CBS,
    mut password: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut storage: *mut uint8_t = 0 as *mut uint8_t;
    let mut in_0: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut pfx: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut mac_data: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut authsafe: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut content_type: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut wrapped_authsafes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut authsafes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut version: uint64_t = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctx: pkcs12_context = pkcs12_context {
        out_key: 0 as *mut *mut EVP_PKEY,
        out_certs: 0 as *mut stack_st_X509,
        password: 0 as *const libc::c_char,
        password_len: 0,
    };
    let original_out_certs_len: size_t = sk_X509_num(out_certs);
    if CBS_asn1_ber_to_der(ber_in, &mut in_0, &mut storage) == 0 {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            598 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    *out_key = 0 as *mut EVP_PKEY;
    OPENSSL_memset(
        &mut ctx as *mut pkcs12_context as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<pkcs12_context>() as libc::c_ulong,
    );
    if CBS_get_asn1(
        &mut in_0,
        &mut pfx,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBS_len(&mut in_0) != 0 as libc::c_int as size_t
        || CBS_get_asn1_uint64(&mut pfx, &mut version) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            610 as libc::c_int as libc::c_uint,
        );
    } else if version < 3 as libc::c_int as uint64_t {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            101 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            615 as libc::c_int as libc::c_uint,
        );
    } else if CBS_get_asn1(
        &mut pfx,
        &mut authsafe,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            620 as libc::c_int as libc::c_uint,
        );
    } else if CBS_len(&mut pfx) == 0 as libc::c_int as size_t {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            112 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            625 as libc::c_int as libc::c_uint,
        );
    } else if CBS_get_asn1(
        &mut pfx,
        &mut mac_data,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            630 as libc::c_int as libc::c_uint,
        );
    } else if CBS_get_asn1(&mut authsafe, &mut content_type, 0x6 as libc::c_uint) == 0
        || CBS_get_asn1(
            &mut authsafe,
            &mut wrapped_authsafes,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | (0x20 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            639 as libc::c_int as libc::c_uint,
        );
    } else if CBS_mem_equal(
        &mut content_type,
        kPKCS7Data.as_ptr(),
        ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
    ) == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            114 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            646 as libc::c_int as libc::c_uint,
        );
    } else if CBS_get_asn1(&mut wrapped_authsafes, &mut authsafes, 0x4 as libc::c_uint)
        == 0
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            100 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            651 as libc::c_int as libc::c_uint,
        );
    } else {
        ctx.out_key = out_key;
        ctx.out_certs = out_certs;
        ctx.password = password;
        ctx
            .password_len = if !password.is_null() {
            strlen(password)
        } else {
            0 as libc::c_int as libc::c_ulong
        };
        let mut mac: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut salt: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        let mut expected_mac: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        if CBS_get_asn1(
            &mut mac_data,
            &mut mac,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                100 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                664 as libc::c_int as libc::c_uint,
            );
        } else {
            let mut md: *const EVP_MD = EVP_parse_digest_algorithm(&mut mac);
            if !md.is_null() {
                if CBS_get_asn1(&mut mac, &mut expected_mac, 0x4 as libc::c_uint) == 0
                    || CBS_get_asn1(&mut mac_data, &mut salt, 0x4 as libc::c_uint) == 0
                {
                    ERR_put_error(
                        19 as libc::c_int,
                        0 as libc::c_int,
                        100 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                            as *const u8 as *const libc::c_char,
                        675 as libc::c_int as libc::c_uint,
                    );
                } else {
                    let mut iterations: uint32_t = 1 as libc::c_int as uint32_t;
                    if CBS_len(&mut mac_data) > 0 as libc::c_int as size_t {
                        let mut iterations_u64: uint64_t = 0;
                        if CBS_get_asn1_uint64(&mut mac_data, &mut iterations_u64) == 0
                            || pkcs12_iterations_acceptable(iterations_u64) == 0
                        {
                            ERR_put_error(
                                19 as libc::c_int,
                                0 as libc::c_int,
                                100 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                                    as *const u8 as *const libc::c_char,
                                685 as libc::c_int as libc::c_uint,
                            );
                            current_block = 8040827944253617475;
                        } else {
                            iterations = iterations_u64 as uint32_t;
                            current_block = 7828949454673616476;
                        }
                    } else {
                        current_block = 7828949454673616476;
                    }
                    match current_block {
                        8040827944253617475 => {}
                        _ => {
                            let mut mac_ok: libc::c_int = 0;
                            if !(pkcs12_check_mac(
                                &mut mac_ok,
                                ctx.password,
                                ctx.password_len,
                                &mut salt,
                                iterations,
                                md,
                                &mut authsafes,
                                &mut expected_mac,
                            ) == 0)
                            {
                                if mac_ok == 0
                                    && ctx.password_len == 0 as libc::c_int as size_t
                                {
                                    ctx
                                        .password = if !(ctx.password).is_null() {
                                        0 as *const libc::c_char
                                    } else {
                                        b"\0" as *const u8 as *const libc::c_char
                                    };
                                    if pkcs12_check_mac(
                                        &mut mac_ok,
                                        ctx.password,
                                        ctx.password_len,
                                        &mut salt,
                                        iterations,
                                        md,
                                        &mut authsafes,
                                        &mut expected_mac,
                                    ) == 0
                                    {
                                        current_block = 8040827944253617475;
                                    } else {
                                        current_block = 7427571413727699167;
                                    }
                                } else {
                                    current_block = 7427571413727699167;
                                }
                                match current_block {
                                    8040827944253617475 => {}
                                    _ => {
                                        if mac_ok == 0 {
                                            ERR_put_error(
                                                19 as libc::c_int,
                                                0 as libc::c_int,
                                                108 as libc::c_int,
                                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                                                    as *const u8 as *const libc::c_char,
                                                709 as libc::c_int as libc::c_uint,
                                            );
                                        } else if !(PKCS12_handle_sequence(
                                            &mut authsafes,
                                            &mut ctx,
                                            Some(
                                                PKCS12_handle_content_info
                                                    as unsafe extern "C" fn(
                                                        *mut CBS,
                                                        *mut pkcs12_context,
                                                    ) -> libc::c_int,
                                            ),
                                        ) == 0)
                                        {
                                            ret = 1 as libc::c_int;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    OPENSSL_free(storage as *mut libc::c_void);
    if ret == 0 {
        EVP_PKEY_free(*out_key);
        *out_key = 0 as *mut EVP_PKEY;
        while sk_X509_num(out_certs) > original_out_certs_len {
            let mut x509: *mut X509 = sk_X509_pop(out_certs);
            X509_free(x509);
        }
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS12_PBE_add() {}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS12(
    mut out_p12: *mut *mut PKCS12,
    mut ber_bytes: *mut *const uint8_t,
    mut ber_len: size_t,
) -> *mut PKCS12 {
    let mut p12: *mut PKCS12 = PKCS12_new();
    if p12.is_null() {
        return 0 as *mut PKCS12;
    }
    (*p12)
        .ber_bytes = OPENSSL_memdup(*ber_bytes as *const libc::c_void, ber_len)
        as *mut uint8_t;
    if ((*p12).ber_bytes).is_null() {
        OPENSSL_free(p12 as *mut libc::c_void);
        return 0 as *mut PKCS12;
    }
    (*p12).ber_len = ber_len;
    *ber_bytes = (*ber_bytes).offset(ber_len as isize);
    if !out_p12.is_null() {
        PKCS12_free(*out_p12);
        *out_p12 = p12;
    }
    return p12;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS12_bio(
    mut bio: *mut BIO,
    mut out_p12: *mut *mut PKCS12,
) -> *mut PKCS12 {
    let mut current_block: u64;
    let mut used: size_t = 0 as libc::c_int as size_t;
    let mut buf: *mut BUF_MEM = 0 as *mut BUF_MEM;
    let mut dummy: *const uint8_t = 0 as *const uint8_t;
    static mut kMaxSize: size_t = (256 as libc::c_int * 1024 as libc::c_int) as size_t;
    let mut ret: *mut PKCS12 = 0 as *mut PKCS12;
    buf = BUF_MEM_new();
    if buf.is_null() {
        return 0 as *mut PKCS12;
    }
    if BUF_MEM_grow(buf, 8192 as libc::c_int as size_t) == 0 as libc::c_int as size_t {
        current_block = 10145681324771214450;
    } else {
        current_block = 10879442775620481940;
    }
    loop {
        match current_block {
            10145681324771214450 => {
                BUF_MEM_free(buf);
                break;
            }
            _ => {
                let mut max_read: size_t = ((*buf).length).wrapping_sub(used);
                let mut n: libc::c_int = BIO_read(
                    bio,
                    &mut *((*buf).data).offset(used as isize) as *mut libc::c_char
                        as *mut libc::c_void,
                    if max_read > 2147483647 as libc::c_int as size_t {
                        2147483647 as libc::c_int
                    } else {
                        max_read as libc::c_int
                    },
                );
                if n < 0 as libc::c_int {
                    if used == 0 as libc::c_int as size_t {
                        current_block = 10145681324771214450;
                        continue;
                    }
                    n = 0 as libc::c_int;
                }
                if n == 0 as libc::c_int {
                    dummy = (*buf).data as *mut uint8_t;
                    ret = d2i_PKCS12(out_p12, &mut dummy, used);
                    current_block = 10145681324771214450;
                } else {
                    used = used.wrapping_add(n as size_t);
                    if used < (*buf).length {
                        current_block = 10879442775620481940;
                        continue;
                    }
                    if (*buf).length > kMaxSize
                        || BUF_MEM_grow(buf, (*buf).length * 2 as libc::c_int as size_t)
                            == 0 as libc::c_int as size_t
                    {
                        current_block = 10145681324771214450;
                    } else {
                        current_block = 10879442775620481940;
                    }
                }
            }
        }
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn d2i_PKCS12_fp(
    mut fp: *mut FILE,
    mut out_p12: *mut *mut PKCS12,
) -> *mut PKCS12 {
    let mut bio: *mut BIO = 0 as *mut BIO;
    let mut ret: *mut PKCS12 = 0 as *mut PKCS12;
    bio = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as *mut PKCS12;
    }
    ret = d2i_PKCS12_bio(bio, out_p12);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS12(
    mut p12: *const PKCS12,
    mut out: *mut *mut uint8_t,
) -> libc::c_int {
    if (*p12).ber_len > 2147483647 as libc::c_int as size_t {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            5 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            833 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    if out.is_null() {
        return (*p12).ber_len as libc::c_int;
    }
    if (*out).is_null() {
        *out = OPENSSL_memdup((*p12).ber_bytes as *const libc::c_void, (*p12).ber_len)
            as *mut uint8_t;
        if (*out).is_null() {
            return -(1 as libc::c_int);
        }
    } else {
        OPENSSL_memcpy(
            *out as *mut libc::c_void,
            (*p12).ber_bytes as *const libc::c_void,
            (*p12).ber_len,
        );
        *out = (*out).offset((*p12).ber_len as isize);
    }
    return (*p12).ber_len as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS12_bio(
    mut bio: *mut BIO,
    mut p12: *const PKCS12,
) -> libc::c_int {
    return BIO_write_all(bio, (*p12).ber_bytes as *const libc::c_void, (*p12).ber_len);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i2d_PKCS12_fp(
    mut fp: *mut FILE,
    mut p12: *const PKCS12,
) -> libc::c_int {
    let mut bio: *mut BIO = BIO_new_fp(fp, 0 as libc::c_int);
    if bio.is_null() {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = i2d_PKCS12_bio(bio, p12);
    BIO_free(bio);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS12_parse(
    mut p12: *const PKCS12,
    mut password: *const libc::c_char,
    mut out_pkey: *mut *mut EVP_PKEY,
    mut out_cert: *mut *mut X509,
    mut out_ca_certs: *mut *mut stack_st_X509,
) -> libc::c_int {
    let mut ber_bytes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut ca_certs: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut ca_certs_alloced: libc::c_char = 0 as libc::c_int as libc::c_char;
    if !out_ca_certs.is_null() && !(*out_ca_certs).is_null() {
        ca_certs = *out_ca_certs;
    }
    if ca_certs.is_null() {
        ca_certs = sk_X509_new_null();
        if ca_certs.is_null() {
            return 0 as libc::c_int;
        }
        ca_certs_alloced = 1 as libc::c_int as libc::c_char;
    }
    CBS_init(&mut ber_bytes, (*p12).ber_bytes, (*p12).ber_len);
    if PKCS12_get_key_and_certs(out_pkey, ca_certs, &mut ber_bytes, password) == 0 {
        if ca_certs_alloced != 0 {
            sk_X509_free(ca_certs);
        }
        return 0 as libc::c_int;
    }
    *out_cert = 0 as *mut X509;
    let mut num_certs: size_t = sk_X509_num(ca_certs);
    if !(*out_pkey).is_null() && num_certs > 0 as libc::c_int as size_t {
        let mut i: size_t = num_certs.wrapping_sub(1 as libc::c_int as size_t);
        while i < num_certs {
            let mut cert: *mut X509 = sk_X509_value(ca_certs, i);
            if X509_check_private_key(cert, *out_pkey) != 0 {
                *out_cert = cert;
                sk_X509_delete(ca_certs, i);
                break;
            } else {
                ERR_clear_error();
                i = i.wrapping_sub(1);
                i;
            }
        }
    }
    if !out_ca_certs.is_null() {
        *out_ca_certs = ca_certs;
    } else {
        sk_X509_pop_free(
            ca_certs,
            Some(X509_free as unsafe extern "C" fn(*mut X509) -> ()),
        );
    }
    return 1 as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS12_verify_mac(
    mut p12: *const PKCS12,
    mut password: *const libc::c_char,
    mut password_len: libc::c_int,
) -> libc::c_int {
    if password.is_null() {
        if password_len != 0 as libc::c_int {
            return 0 as libc::c_int;
        }
    } else if password_len != -(1 as libc::c_int)
        && (*password.offset(password_len as isize) as libc::c_int != 0 as libc::c_int
            || !(OPENSSL_memchr(
                password as *const libc::c_void,
                0 as libc::c_int,
                password_len as size_t,
            ))
                .is_null())
    {
        return 0 as libc::c_int
    }
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut cert: *mut X509 = 0 as *mut X509;
    if PKCS12_parse(p12, password, &mut pkey, &mut cert, 0 as *mut *mut stack_st_X509)
        == 0
    {
        ERR_clear_error();
        return 0 as libc::c_int;
    }
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return 1 as libc::c_int;
}
unsafe extern "C" fn add_bag_attributes(
    mut bag: *mut CBB,
    mut name: *const libc::c_char,
    mut name_len: size_t,
    mut key_id: *const uint8_t,
    mut key_id_len: size_t,
) -> libc::c_int {
    if name.is_null() && key_id_len == 0 as libc::c_int as size_t {
        return 1 as libc::c_int;
    }
    let mut attrs: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut attr: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
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
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut values: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut value: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
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
        bag,
        &mut attrs,
        0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    if name_len != 0 as libc::c_int as size_t {
        if CBB_add_asn1(
            &mut attrs,
            &mut attr,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut attr, &mut oid, 0x6 as libc::c_uint) == 0
            || CBB_add_bytes(
                &mut oid,
                kFriendlyName.as_ptr(),
                ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
            ) == 0
            || CBB_add_asn1(
                &mut attr,
                &mut values,
                0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0 || CBB_add_asn1(&mut values, &mut value, 0x1e as libc::c_uint) == 0
        {
            return 0 as libc::c_int;
        }
        let mut name_cbs: CBS = cbs_st {
            data: 0 as *const uint8_t,
            len: 0,
        };
        CBS_init(&mut name_cbs, name as *const uint8_t, name_len);
        while CBS_len(&mut name_cbs) != 0 as libc::c_int as size_t {
            let mut c: uint32_t = 0;
            if cbs_get_utf8(&mut name_cbs, &mut c) == 0
                || cbb_add_ucs2_be(&mut value, c) == 0
            {
                ERR_put_error(
                    19 as libc::c_int,
                    0 as libc::c_int,
                    131 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                        as *const u8 as *const libc::c_char,
                    972 as libc::c_int as libc::c_uint,
                );
                return 0 as libc::c_int;
            }
        }
    }
    if key_id_len != 0 as libc::c_int as size_t {
        if CBB_add_asn1(
            &mut attrs,
            &mut attr,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut attr, &mut oid, 0x6 as libc::c_uint) == 0
            || CBB_add_bytes(
                &mut oid,
                kLocalKeyID.as_ptr(),
                ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
            ) == 0
            || CBB_add_asn1(
                &mut attr,
                &mut values,
                0x11 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0 || CBB_add_asn1(&mut values, &mut value, 0x4 as libc::c_uint) == 0
            || CBB_add_bytes(&mut value, key_id, key_id_len) == 0
        {
            return 0 as libc::c_int;
        }
    }
    return (CBB_flush_asn1_set_of(&mut attrs) != 0 && CBB_flush(bag) != 0)
        as libc::c_int;
}
unsafe extern "C" fn add_cert_bag(
    mut cbb: *mut CBB,
    mut cert: *mut X509,
    mut name: *const libc::c_char,
    mut key_id: *const uint8_t,
    mut key_id_len: size_t,
) -> libc::c_int {
    let mut bag: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut bag_oid: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut bag_contents: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut cert_bag: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut cert_type: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut wrapped_cert: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut cert_value: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
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
        &mut bag,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1(&mut bag, &mut bag_oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut bag_oid,
            kCertBag.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 11]>() as libc::c_ulong,
        ) == 0
        || CBB_add_asn1(
            &mut bag,
            &mut bag_contents,
            (0x20 as libc::c_uint) << 24 as libc::c_int
                | (0x80 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
        || CBB_add_asn1(
            &mut bag_contents,
            &mut cert_bag,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1(&mut cert_bag, &mut cert_type, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut cert_type,
            kX509Certificate.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 10]>() as libc::c_ulong,
        ) == 0
        || CBB_add_asn1(
            &mut cert_bag,
            &mut wrapped_cert,
            (0x20 as libc::c_uint) << 24 as libc::c_int
                | (0x80 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
        || CBB_add_asn1(&mut wrapped_cert, &mut cert_value, 0x4 as libc::c_uint) == 0
    {
        return 0 as libc::c_int;
    }
    let mut buf: *mut uint8_t = 0 as *mut uint8_t;
    let mut len: libc::c_int = i2d_X509(cert, 0 as *mut *mut uint8_t);
    let mut int_name_len: libc::c_int = 0 as libc::c_int;
    let mut cert_name: *const libc::c_char = X509_alias_get0(cert, &mut int_name_len)
        as *const libc::c_char;
    let mut name_len: size_t = int_name_len as size_t;
    if !name.is_null() {
        if name_len != 0 as libc::c_int as size_t {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                133 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                1018 as libc::c_int as libc::c_uint,
            );
            return 0 as libc::c_int;
        }
        name_len = strlen(name);
    } else {
        name = cert_name;
    }
    if len < 0 as libc::c_int
        || CBB_add_space(&mut cert_value, &mut buf, len as size_t) == 0
        || i2d_X509(cert, &mut buf) < 0 as libc::c_int
        || add_bag_attributes(&mut bag, name, name_len, key_id, key_id_len) == 0
        || CBB_flush(cbb) == 0
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn add_cert_safe_contents(
    mut cbb: *mut CBB,
    mut cert: *mut X509,
    mut chain: *const stack_st_X509,
    mut name: *const libc::c_char,
    mut key_id: *const uint8_t,
    mut key_id_len: size_t,
) -> libc::c_int {
    let mut safe_contents: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
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
        &mut safe_contents,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0
        || !cert.is_null()
            && add_cert_bag(&mut safe_contents, cert, name, key_id, key_id_len) == 0
    {
        return 0 as libc::c_int;
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < sk_X509_num(chain) {
        if add_cert_bag(
            &mut safe_contents,
            sk_X509_value(chain, i),
            0 as *const libc::c_char,
            0 as *const uint8_t,
            0 as libc::c_int as size_t,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return CBB_flush(cbb);
}
unsafe extern "C" fn add_encrypted_data(
    mut out: *mut CBB,
    mut pbe_nid: libc::c_int,
    mut password: *const libc::c_char,
    mut password_len: size_t,
    mut iterations: uint32_t,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) -> libc::c_int {
    let mut max_out: size_t = 0;
    let mut ptr: *mut uint8_t = 0 as *mut uint8_t;
    let mut n1: libc::c_int = 0;
    let mut n2: libc::c_int = 0;
    let mut salt: [uint8_t; 16] = [0; 16];
    if RAND_bytes(
        salt.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
    ) == 0
    {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctx: EVP_CIPHER_CTX = evp_cipher_ctx_st {
        cipher: 0 as *const EVP_CIPHER,
        app_data: 0 as *mut libc::c_void,
        cipher_data: 0 as *mut libc::c_void,
        key_len: 0,
        encrypt: 0,
        flags: 0,
        oiv: [0; 16],
        iv: [0; 16],
        buf: [0; 32],
        buf_len: 0,
        num: 0,
        final_used: 0,
        final_0: [0; 32],
        poisoned: 0,
    };
    EVP_CIPHER_CTX_init(&mut ctx);
    let mut content_info: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut type_0: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut wrapper: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut encrypted_data: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut encrypted_content_info: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut inner_type: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut encrypted_content: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if !(CBB_add_asn1(
        out,
        &mut content_info,
        0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
    ) == 0 || CBB_add_asn1(&mut content_info, &mut type_0, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut type_0,
            kPKCS7EncryptedData.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        || CBB_add_asn1(
            &mut content_info,
            &mut wrapper,
            (0x20 as libc::c_uint) << 24 as libc::c_int
                | (0x80 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
        || CBB_add_asn1(
            &mut wrapper,
            &mut encrypted_data,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || CBB_add_asn1_uint64(&mut encrypted_data, 0 as libc::c_int as uint64_t) == 0
        || CBB_add_asn1(
            &mut encrypted_data,
            &mut encrypted_content_info,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || CBB_add_asn1(
            &mut encrypted_content_info,
            &mut inner_type,
            0x6 as libc::c_uint,
        ) == 0
        || CBB_add_bytes(
            &mut inner_type,
            kPKCS7Data.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        || pkcs12_pbe_encrypt_init(
            &mut encrypted_content_info,
            &mut ctx,
            pbe_nid,
            iterations,
            password,
            password_len,
            salt.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
        ) == 0
        || CBB_add_asn1(
            &mut encrypted_content_info,
            &mut encrypted_content,
            (0x80 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0)
    {
        max_out = in_len.wrapping_add(EVP_CIPHER_CTX_block_size(&mut ctx) as size_t);
        if max_out < in_len {
            ERR_put_error(
                19 as libc::c_int,
                0 as libc::c_int,
                118 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                    as *const u8 as *const libc::c_char,
                1096 as libc::c_int as libc::c_uint,
            );
        } else {
            ptr = 0 as *mut uint8_t;
            n1 = 0;
            n2 = 0;
            if !(CBB_reserve(&mut encrypted_content, &mut ptr, max_out) == 0
                || EVP_CipherUpdate(&mut ctx, ptr, &mut n1, in_0, in_len as libc::c_int)
                    == 0
                || EVP_CipherFinal_ex(&mut ctx, ptr.offset(n1 as isize), &mut n2) == 0
                || CBB_did_write(&mut encrypted_content, (n1 + n2) as size_t) == 0
                || CBB_flush(out) == 0)
            {
                ret = 1 as libc::c_int;
            }
        }
    }
    EVP_CIPHER_CTX_cleanup(&mut ctx);
    return ret;
}
unsafe extern "C" fn pkcs12_gen_and_write_mac(
    mut out_pfx: *mut CBB,
    mut auth_safe_data: *const uint8_t,
    mut auth_safe_data_len: size_t,
    mut password: *const libc::c_char,
    mut password_len: size_t,
    mut mac_salt: *mut uint8_t,
    mut salt_len: size_t,
    mut mac_iterations: libc::c_int,
    mut md: *const EVP_MD,
) -> libc::c_int {
    let mut mac_data: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut digest_info: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut mac_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut mac_salt_cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut mac_key: [uint8_t; 64] = [0; 64];
    let mut mac: [uint8_t; 64] = [0; 64];
    let mut mac_len: libc::c_uint = 0;
    if !(pkcs12_key_gen(
        password,
        password_len,
        mac_salt,
        salt_len,
        3 as libc::c_int as uint8_t,
        mac_iterations as uint32_t,
        EVP_MD_size(md),
        mac_key.as_mut_ptr(),
        md,
    ) == 0
        || (HMAC(
            md,
            mac_key.as_mut_ptr() as *const libc::c_void,
            EVP_MD_size(md),
            auth_safe_data,
            auth_safe_data_len,
            mac.as_mut_ptr(),
            &mut mac_len,
        ))
            .is_null())
    {
        mac_data = cbb_st {
            child: 0 as *mut CBB,
            is_child: 0,
            u: C2RustUnnamed_0 {
                base: cbb_buffer_st {
                    buf: 0 as *mut uint8_t,
                    len: 0,
                    cap: 0,
                    can_resize_error: [0; 1],
                    c2rust_padding: [0; 7],
                },
            },
        };
        digest_info = cbb_st {
            child: 0 as *mut CBB,
            is_child: 0,
            u: C2RustUnnamed_0 {
                base: cbb_buffer_st {
                    buf: 0 as *mut uint8_t,
                    len: 0,
                    cap: 0,
                    can_resize_error: [0; 1],
                    c2rust_padding: [0; 7],
                },
            },
        };
        mac_cbb = cbb_st {
            child: 0 as *mut CBB,
            is_child: 0,
            u: C2RustUnnamed_0 {
                base: cbb_buffer_st {
                    buf: 0 as *mut uint8_t,
                    len: 0,
                    cap: 0,
                    can_resize_error: [0; 1],
                    c2rust_padding: [0; 7],
                },
            },
        };
        mac_salt_cbb = cbb_st {
            child: 0 as *mut CBB,
            is_child: 0,
            u: C2RustUnnamed_0 {
                base: cbb_buffer_st {
                    buf: 0 as *mut uint8_t,
                    len: 0,
                    cap: 0,
                    can_resize_error: [0; 1],
                    c2rust_padding: [0; 7],
                },
            },
        };
        if !(CBB_add_asn1(
            out_pfx,
            &mut mac_data,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
            || CBB_add_asn1(
                &mut mac_data,
                &mut digest_info,
                0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
            ) == 0 || EVP_marshal_digest_algorithm(&mut digest_info, md) == 0
            || CBB_add_asn1(&mut digest_info, &mut mac_cbb, 0x4 as libc::c_uint) == 0
            || CBB_add_bytes(&mut mac_cbb, mac.as_mut_ptr(), mac_len as size_t) == 0
            || CBB_add_asn1(&mut mac_data, &mut mac_salt_cbb, 0x4 as libc::c_uint) == 0
            || CBB_add_bytes(&mut mac_salt_cbb, mac_salt, salt_len) == 0
            || CBB_add_asn1_uint64(&mut mac_data, mac_iterations as uint64_t) == 0
            || CBB_flush(out_pfx) == 0)
        {
            ret = 1 as libc::c_int;
        }
    }
    OPENSSL_cleanse(
        mac_key.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 64]>() as libc::c_ulong,
    );
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS12_create(
    mut password: *const libc::c_char,
    mut name: *const libc::c_char,
    mut pkey: *const EVP_PKEY,
    mut cert: *mut X509,
    mut chain: *const stack_st_X509,
    mut key_nid: libc::c_int,
    mut cert_nid: libc::c_int,
    mut iterations: libc::c_int,
    mut mac_iterations: libc::c_int,
    mut key_type: libc::c_int,
) -> *mut PKCS12 {
    let mut mac_md: *const EVP_MD = 0 as *const EVP_MD;
    let mut mac_salt: [uint8_t; 16] = [0; 16];
    let mut current_block: u64;
    if key_nid == 0 as libc::c_int {
        key_nid = 146 as libc::c_int;
    }
    if cert_nid == 0 as libc::c_int {
        cert_nid = 149 as libc::c_int;
    }
    if iterations == 0 as libc::c_int {
        iterations = 2048 as libc::c_int;
    }
    if mac_iterations == 0 as libc::c_int {
        mac_iterations = 1 as libc::c_int;
    }
    if key_type != 0 as libc::c_int || mac_iterations < 0 as libc::c_int
        || pkey.is_null() && cert.is_null()
            && sk_X509_num(chain) == 0 as libc::c_int as size_t
    {
        ERR_put_error(
            19 as libc::c_int,
            0 as libc::c_int,
            132 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            1180 as libc::c_int as libc::c_uint,
        );
        return 0 as *mut PKCS12;
    }
    let mut password_len: size_t = if !password.is_null() {
        strlen(password)
    } else {
        0 as libc::c_int as libc::c_ulong
    };
    let mut key_id: [uint8_t; 64] = [0; 64];
    let mut key_id_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    if !cert.is_null() && !pkey.is_null() {
        if X509_check_private_key(cert, pkey) == 0
            || X509_digest(cert, EVP_sha1(), key_id.as_mut_ptr(), &mut key_id_len) == 0
        {
            return 0 as *mut PKCS12;
        }
    }
    let mut ret: *mut PKCS12 = 0 as *mut PKCS12;
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut pfx: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut auth_safe: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut auth_safe_oid: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut auth_safe_wrapper: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut auth_safe_data: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut content_infos: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    if !(CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
        || CBB_add_asn1(
            &mut cbb,
            &mut pfx,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0 || CBB_add_asn1_uint64(&mut pfx, 3 as libc::c_int as uint64_t) == 0
        || CBB_add_asn1(
            &mut pfx,
            &mut auth_safe,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0
        || CBB_add_asn1(&mut auth_safe, &mut auth_safe_oid, 0x6 as libc::c_uint) == 0
        || CBB_add_bytes(
            &mut auth_safe_oid,
            kPKCS7Data.as_ptr(),
            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
        ) == 0
        || CBB_add_asn1(
            &mut auth_safe,
            &mut auth_safe_wrapper,
            (0x20 as libc::c_uint) << 24 as libc::c_int
                | (0x80 as libc::c_uint) << 24 as libc::c_int
                | 0 as libc::c_int as libc::c_uint,
        ) == 0
        || CBB_add_asn1(&mut auth_safe_wrapper, &mut auth_safe_data, 0x4 as libc::c_uint)
            == 0
        || CBB_add_asn1(
            &mut auth_safe_data,
            &mut content_infos,
            0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
        ) == 0)
    {
        if !cert.is_null() || sk_X509_num(chain) > 0 as libc::c_int as size_t {
            if cert_nid < 0 as libc::c_int {
                let mut content_info: CBB = cbb_st {
                    child: 0 as *mut CBB,
                    is_child: 0,
                    u: C2RustUnnamed_0 {
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
                    u: C2RustUnnamed_0 {
                        base: cbb_buffer_st {
                            buf: 0 as *mut uint8_t,
                            len: 0,
                            cap: 0,
                            can_resize_error: [0; 1],
                            c2rust_padding: [0; 7],
                        },
                    },
                };
                let mut wrapper: CBB = cbb_st {
                    child: 0 as *mut CBB,
                    is_child: 0,
                    u: C2RustUnnamed_0 {
                        base: cbb_buffer_st {
                            buf: 0 as *mut uint8_t,
                            len: 0,
                            cap: 0,
                            can_resize_error: [0; 1],
                            c2rust_padding: [0; 7],
                        },
                    },
                };
                let mut data: CBB = cbb_st {
                    child: 0 as *mut CBB,
                    is_child: 0,
                    u: C2RustUnnamed_0 {
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
                    &mut content_infos,
                    &mut content_info,
                    0x10 as libc::c_uint | (0x20 as libc::c_uint) << 24 as libc::c_int,
                ) == 0
                    || CBB_add_asn1(&mut content_info, &mut oid, 0x6 as libc::c_uint)
                        == 0
                    || CBB_add_bytes(
                        &mut oid,
                        kPKCS7Data.as_ptr(),
                        ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
                    ) == 0
                    || CBB_add_asn1(
                        &mut content_info,
                        &mut wrapper,
                        (0x20 as libc::c_uint) << 24 as libc::c_int
                            | (0x80 as libc::c_uint) << 24 as libc::c_int
                            | 0 as libc::c_int as libc::c_uint,
                    ) == 0
                    || CBB_add_asn1(&mut wrapper, &mut data, 0x4 as libc::c_uint) == 0
                    || add_cert_safe_contents(
                        &mut data,
                        cert,
                        chain,
                        name,
                        key_id.as_mut_ptr(),
                        key_id_len as size_t,
                    ) == 0 || CBB_flush(&mut content_infos) == 0
                {
                    current_block = 17331973277139004205;
                } else {
                    current_block = 14763689060501151050;
                }
            } else {
                let mut plaintext_cbb: CBB = cbb_st {
                    child: 0 as *mut CBB,
                    is_child: 0,
                    u: C2RustUnnamed_0 {
                        base: cbb_buffer_st {
                            buf: 0 as *mut uint8_t,
                            len: 0,
                            cap: 0,
                            can_resize_error: [0; 1],
                            c2rust_padding: [0; 7],
                        },
                    },
                };
                let mut ok: libc::c_int = (CBB_init(
                    &mut plaintext_cbb,
                    0 as libc::c_int as size_t,
                ) != 0
                    && add_cert_safe_contents(
                        &mut plaintext_cbb,
                        cert,
                        chain,
                        name,
                        key_id.as_mut_ptr(),
                        key_id_len as size_t,
                    ) != 0
                    && add_encrypted_data(
                        &mut content_infos,
                        cert_nid,
                        password,
                        password_len,
                        iterations as uint32_t,
                        CBB_data(&mut plaintext_cbb),
                        CBB_len(&mut plaintext_cbb),
                    ) != 0) as libc::c_int;
                CBB_cleanup(&mut plaintext_cbb);
                if ok == 0 {
                    current_block = 17331973277139004205;
                } else {
                    current_block = 14763689060501151050;
                }
            }
        } else {
            current_block = 14763689060501151050;
        }
        match current_block {
            17331973277139004205 => {}
            _ => {
                if !pkey.is_null() {
                    let mut content_info_0: CBB = cbb_st {
                        child: 0 as *mut CBB,
                        is_child: 0,
                        u: C2RustUnnamed_0 {
                            base: cbb_buffer_st {
                                buf: 0 as *mut uint8_t,
                                len: 0,
                                cap: 0,
                                can_resize_error: [0; 1],
                                c2rust_padding: [0; 7],
                            },
                        },
                    };
                    let mut oid_0: CBB = cbb_st {
                        child: 0 as *mut CBB,
                        is_child: 0,
                        u: C2RustUnnamed_0 {
                            base: cbb_buffer_st {
                                buf: 0 as *mut uint8_t,
                                len: 0,
                                cap: 0,
                                can_resize_error: [0; 1],
                                c2rust_padding: [0; 7],
                            },
                        },
                    };
                    let mut wrapper_0: CBB = cbb_st {
                        child: 0 as *mut CBB,
                        is_child: 0,
                        u: C2RustUnnamed_0 {
                            base: cbb_buffer_st {
                                buf: 0 as *mut uint8_t,
                                len: 0,
                                cap: 0,
                                can_resize_error: [0; 1],
                                c2rust_padding: [0; 7],
                            },
                        },
                    };
                    let mut data_0: CBB = cbb_st {
                        child: 0 as *mut CBB,
                        is_child: 0,
                        u: C2RustUnnamed_0 {
                            base: cbb_buffer_st {
                                buf: 0 as *mut uint8_t,
                                len: 0,
                                cap: 0,
                                can_resize_error: [0; 1],
                                c2rust_padding: [0; 7],
                            },
                        },
                    };
                    let mut safe_contents: CBB = cbb_st {
                        child: 0 as *mut CBB,
                        is_child: 0,
                        u: C2RustUnnamed_0 {
                            base: cbb_buffer_st {
                                buf: 0 as *mut uint8_t,
                                len: 0,
                                cap: 0,
                                can_resize_error: [0; 1],
                                c2rust_padding: [0; 7],
                            },
                        },
                    };
                    let mut bag: CBB = cbb_st {
                        child: 0 as *mut CBB,
                        is_child: 0,
                        u: C2RustUnnamed_0 {
                            base: cbb_buffer_st {
                                buf: 0 as *mut uint8_t,
                                len: 0,
                                cap: 0,
                                can_resize_error: [0; 1],
                                c2rust_padding: [0; 7],
                            },
                        },
                    };
                    let mut bag_oid: CBB = cbb_st {
                        child: 0 as *mut CBB,
                        is_child: 0,
                        u: C2RustUnnamed_0 {
                            base: cbb_buffer_st {
                                buf: 0 as *mut uint8_t,
                                len: 0,
                                cap: 0,
                                can_resize_error: [0; 1],
                                c2rust_padding: [0; 7],
                            },
                        },
                    };
                    let mut bag_contents: CBB = cbb_st {
                        child: 0 as *mut CBB,
                        is_child: 0,
                        u: C2RustUnnamed_0 {
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
                        &mut content_infos,
                        &mut content_info_0,
                        0x10 as libc::c_uint
                            | (0x20 as libc::c_uint) << 24 as libc::c_int,
                    ) == 0
                        || CBB_add_asn1(
                            &mut content_info_0,
                            &mut oid_0,
                            0x6 as libc::c_uint,
                        ) == 0
                        || CBB_add_bytes(
                            &mut oid_0,
                            kPKCS7Data.as_ptr(),
                            ::core::mem::size_of::<[uint8_t; 9]>() as libc::c_ulong,
                        ) == 0
                        || CBB_add_asn1(
                            &mut content_info_0,
                            &mut wrapper_0,
                            (0x20 as libc::c_uint) << 24 as libc::c_int
                                | (0x80 as libc::c_uint) << 24 as libc::c_int
                                | 0 as libc::c_int as libc::c_uint,
                        ) == 0
                        || CBB_add_asn1(&mut wrapper_0, &mut data_0, 0x4 as libc::c_uint)
                            == 0
                        || CBB_add_asn1(
                            &mut data_0,
                            &mut safe_contents,
                            0x10 as libc::c_uint
                                | (0x20 as libc::c_uint) << 24 as libc::c_int,
                        ) == 0
                        || CBB_add_asn1(
                            &mut safe_contents,
                            &mut bag,
                            0x10 as libc::c_uint
                                | (0x20 as libc::c_uint) << 24 as libc::c_int,
                        ) == 0
                        || CBB_add_asn1(&mut bag, &mut bag_oid, 0x6 as libc::c_uint) == 0
                    {
                        current_block = 17331973277139004205;
                    } else {
                        if key_nid < 0 as libc::c_int {
                            if CBB_add_bytes(
                                &mut bag_oid,
                                kKeyBag.as_ptr(),
                                ::core::mem::size_of::<[uint8_t; 11]>() as libc::c_ulong,
                            ) == 0
                                || CBB_add_asn1(
                                    &mut bag,
                                    &mut bag_contents,
                                    (0x20 as libc::c_uint) << 24 as libc::c_int
                                        | (0x80 as libc::c_uint) << 24 as libc::c_int
                                        | 0 as libc::c_int as libc::c_uint,
                                ) == 0
                                || EVP_marshal_private_key(&mut bag_contents, pkey) == 0
                            {
                                current_block = 17331973277139004205;
                            } else {
                                current_block = 9520865839495247062;
                            }
                        } else if CBB_add_bytes(
                            &mut bag_oid,
                            kPKCS8ShroudedKeyBag.as_ptr(),
                            ::core::mem::size_of::<[uint8_t; 11]>() as libc::c_ulong,
                        ) == 0
                            || CBB_add_asn1(
                                &mut bag,
                                &mut bag_contents,
                                (0x20 as libc::c_uint) << 24 as libc::c_int
                                    | (0x80 as libc::c_uint) << 24 as libc::c_int
                                    | 0 as libc::c_int as libc::c_uint,
                            ) == 0
                            || PKCS8_marshal_encrypted_private_key(
                                &mut bag_contents,
                                key_nid,
                                0 as *const EVP_CIPHER,
                                password,
                                password_len,
                                0 as *const uint8_t,
                                0 as libc::c_int as size_t,
                                iterations,
                                pkey,
                            ) == 0
                        {
                            current_block = 17331973277139004205;
                        } else {
                            current_block = 9520865839495247062;
                        }
                        match current_block {
                            17331973277139004205 => {}
                            _ => {
                                let mut name_len: size_t = 0 as libc::c_int as size_t;
                                if !name.is_null() {
                                    name_len = strlen(name);
                                }
                                if add_bag_attributes(
                                    &mut bag,
                                    name,
                                    name_len,
                                    key_id.as_mut_ptr(),
                                    key_id_len as size_t,
                                ) == 0 || CBB_flush(&mut content_infos) == 0
                                {
                                    current_block = 17331973277139004205;
                                } else {
                                    current_block = 11743904203796629665;
                                }
                            }
                        }
                    }
                } else {
                    current_block = 11743904203796629665;
                }
                match current_block {
                    17331973277139004205 => {}
                    _ => {
                        mac_md = EVP_sha1();
                        mac_salt = [0; 16];
                        if !(CBB_flush(&mut auth_safe_data) == 0
                            || RAND_bytes(
                                mac_salt.as_mut_ptr(),
                                ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
                            ) == 0
                            || pkcs12_gen_and_write_mac(
                                &mut pfx,
                                CBB_data(&mut auth_safe_data),
                                CBB_len(&mut auth_safe_data),
                                password,
                                password_len,
                                mac_salt.as_mut_ptr(),
                                ::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
                                mac_iterations,
                                mac_md,
                            ) == 0)
                        {
                            ret = PKCS12_new();
                            if ret.is_null()
                                || CBB_finish(
                                    &mut cbb,
                                    &mut (*ret).ber_bytes,
                                    &mut (*ret).ber_len,
                                ) == 0
                            {
                                OPENSSL_free(ret as *mut libc::c_void);
                                ret = 0 as *mut PKCS12;
                            }
                        }
                    }
                }
            }
        }
    }
    CBB_cleanup(&mut cbb);
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS12_new() -> *mut PKCS12 {
    return OPENSSL_zalloc(::core::mem::size_of::<PKCS12>() as libc::c_ulong)
        as *mut PKCS12;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS12_free(mut p12: *mut PKCS12) {
    if p12.is_null() {
        return;
    }
    OPENSSL_free((*p12).ber_bytes as *mut libc::c_void);
    OPENSSL_free(p12 as *mut libc::c_void);
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PKCS12_set_mac(
    mut p12: *mut PKCS12,
    mut password: *const libc::c_char,
    mut password_len: libc::c_int,
    mut salt: *mut libc::c_uchar,
    mut salt_len: libc::c_int,
    mut mac_iterations: libc::c_int,
    mut md: *const EVP_MD,
) -> libc::c_int {
    let mut storage: *mut uint8_t = 0 as *mut uint8_t;
    let mut ber_bytes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut in_0: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut pfx: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut authsafe: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut content_type: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut wrapped_authsafes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut authsafes: CBS = cbs_st {
        data: 0 as *const uint8_t,
        len: 0,
    };
    let mut version: uint64_t = 0;
    let mut orig_authsafe: *const uint8_t = 0 as *const uint8_t;
    let mut orig_authsafe_len: size_t = 0;
    let mut cbb: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut out_pfx: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut out_auth_safe: CBB = cbb_st {
        child: 0 as *mut CBB,
        is_child: 0,
        u: C2RustUnnamed_0 {
            base: cbb_buffer_st {
                buf: 0 as *mut uint8_t,
                len: 0,
                cap: 0,
                can_resize_error: [0; 1],
                c2rust_padding: [0; 7],
            },
        },
    };
    let mut current_block: u64;
    if p12.is_null() {
        ERR_put_error(
            14 as libc::c_int,
            0 as libc::c_int,
            3 as libc::c_int | 64 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0" as *const u8
                as *const libc::c_char,
            1378 as libc::c_int as libc::c_uint,
        );
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = 0 as libc::c_int;
    if mac_iterations == 0 as libc::c_int {
        mac_iterations = 1 as libc::c_int;
    }
    if salt_len == 0 as libc::c_int {
        salt_len = 16 as libc::c_int;
    }
    let mut mac_salt: *mut uint8_t = OPENSSL_malloc(salt_len as size_t) as *mut uint8_t;
    if !mac_salt.is_null() {
        if salt.is_null() {
            if RAND_bytes(mac_salt, salt_len as size_t) == 0 {
                current_block = 13442008601947344467;
            } else {
                current_block = 13056961889198038528;
            }
        } else {
            OPENSSL_memcpy(
                mac_salt as *mut libc::c_void,
                salt as *const libc::c_void,
                salt_len as size_t,
            );
            current_block = 13056961889198038528;
        }
        match current_block {
            13442008601947344467 => {}
            _ => {
                if md.is_null() {
                    md = EVP_sha1();
                }
                storage = 0 as *mut uint8_t;
                ber_bytes = cbs_st {
                    data: 0 as *const uint8_t,
                    len: 0,
                };
                in_0 = cbs_st {
                    data: 0 as *const uint8_t,
                    len: 0,
                };
                pfx = cbs_st {
                    data: 0 as *const uint8_t,
                    len: 0,
                };
                authsafe = cbs_st {
                    data: 0 as *const uint8_t,
                    len: 0,
                };
                content_type = cbs_st {
                    data: 0 as *const uint8_t,
                    len: 0,
                };
                wrapped_authsafes = cbs_st {
                    data: 0 as *const uint8_t,
                    len: 0,
                };
                authsafes = cbs_st {
                    data: 0 as *const uint8_t,
                    len: 0,
                };
                version = 0;
                CBS_init(&mut ber_bytes, (*p12).ber_bytes, (*p12).ber_len);
                if CBS_asn1_ber_to_der(&mut ber_bytes, &mut in_0, &mut storage) == 0 {
                    ERR_put_error(
                        19 as libc::c_int,
                        0 as libc::c_int,
                        100 as libc::c_int,
                        b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                            as *const u8 as *const libc::c_char,
                        1411 as libc::c_int as libc::c_uint,
                    );
                } else {
                    OPENSSL_free(storage as *mut libc::c_void);
                    if CBS_get_asn1(
                        &mut in_0,
                        &mut pfx,
                        0x10 as libc::c_uint
                            | (0x20 as libc::c_uint) << 24 as libc::c_int,
                    ) == 0 || CBS_len(&mut in_0) != 0 as libc::c_int as size_t
                        || CBS_get_asn1_uint64(&mut pfx, &mut version) == 0
                    {
                        ERR_put_error(
                            19 as libc::c_int,
                            0 as libc::c_int,
                            100 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                                as *const u8 as *const libc::c_char,
                            1419 as libc::c_int as libc::c_uint,
                        );
                    } else if version < 3 as libc::c_int as uint64_t {
                        ERR_put_error(
                            19 as libc::c_int,
                            0 as libc::c_int,
                            101 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                                as *const u8 as *const libc::c_char,
                            1423 as libc::c_int as libc::c_uint,
                        );
                    } else if CBS_get_asn1(
                        &mut pfx,
                        &mut authsafe,
                        0x10 as libc::c_uint
                            | (0x20 as libc::c_uint) << 24 as libc::c_int,
                    ) == 0
                    {
                        ERR_put_error(
                            19 as libc::c_int,
                            0 as libc::c_int,
                            100 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                                as *const u8 as *const libc::c_char,
                            1428 as libc::c_int as libc::c_uint,
                        );
                    } else {
                        orig_authsafe = CBS_data(&mut authsafe);
                        orig_authsafe_len = CBS_len(&mut authsafe);
                        if CBS_get_asn1(
                            &mut authsafe,
                            &mut content_type,
                            0x6 as libc::c_uint,
                        ) == 0
                            || CBS_get_asn1(
                                &mut authsafe,
                                &mut wrapped_authsafes,
                                (0x80 as libc::c_uint) << 24 as libc::c_int
                                    | (0x20 as libc::c_uint) << 24 as libc::c_int
                                    | 0 as libc::c_int as libc::c_uint,
                            ) == 0
                            || CBS_get_asn1(
                                &mut wrapped_authsafes,
                                &mut authsafes,
                                0x4 as libc::c_uint,
                            ) == 0
                        {
                            ERR_put_error(
                                19 as libc::c_int,
                                0 as libc::c_int,
                                100 as libc::c_int,
                                b"/home/ubuntu/workspace/oss/aws-lc/crypto/pkcs8/pkcs8_x509.c\0"
                                    as *const u8 as *const libc::c_char,
                                1440 as libc::c_int as libc::c_uint,
                            );
                        } else {
                            cbb = cbb_st {
                                child: 0 as *mut CBB,
                                is_child: 0,
                                u: C2RustUnnamed_0 {
                                    base: cbb_buffer_st {
                                        buf: 0 as *mut uint8_t,
                                        len: 0,
                                        cap: 0,
                                        can_resize_error: [0; 1],
                                        c2rust_padding: [0; 7],
                                    },
                                },
                            };
                            out_pfx = cbb_st {
                                child: 0 as *mut CBB,
                                is_child: 0,
                                u: C2RustUnnamed_0 {
                                    base: cbb_buffer_st {
                                        buf: 0 as *mut uint8_t,
                                        len: 0,
                                        cap: 0,
                                        can_resize_error: [0; 1],
                                        c2rust_padding: [0; 7],
                                    },
                                },
                            };
                            out_auth_safe = cbb_st {
                                child: 0 as *mut CBB,
                                is_child: 0,
                                u: C2RustUnnamed_0 {
                                    base: cbb_buffer_st {
                                        buf: 0 as *mut uint8_t,
                                        len: 0,
                                        cap: 0,
                                        can_resize_error: [0; 1],
                                        c2rust_padding: [0; 7],
                                    },
                                },
                            };
                            if CBB_init(&mut cbb, 0 as libc::c_int as size_t) == 0
                                || CBB_add_asn1(
                                    &mut cbb,
                                    &mut out_pfx,
                                    0x10 as libc::c_uint
                                        | (0x20 as libc::c_uint) << 24 as libc::c_int,
                                ) == 0 || CBB_add_asn1_uint64(&mut out_pfx, version) == 0
                                || CBB_add_asn1(
                                    &mut out_pfx,
                                    &mut out_auth_safe,
                                    0x10 as libc::c_uint
                                        | (0x20 as libc::c_uint) << 24 as libc::c_int,
                                ) == 0
                                || CBB_add_bytes(
                                    &mut out_auth_safe,
                                    orig_authsafe,
                                    orig_authsafe_len,
                                ) == 0
                                || pkcs12_gen_and_write_mac(
                                    &mut out_pfx,
                                    CBS_data(&mut authsafes),
                                    CBS_len(&mut authsafes),
                                    password,
                                    password_len as size_t,
                                    mac_salt,
                                    salt_len as size_t,
                                    mac_iterations,
                                    md,
                                ) == 0
                            {
                                CBB_cleanup(&mut cbb);
                            } else {
                                OPENSSL_free((*p12).ber_bytes as *mut libc::c_void);
                                if CBB_finish(
                                    &mut cbb,
                                    &mut (*p12).ber_bytes,
                                    &mut (*p12).ber_len,
                                ) == 0
                                    || PKCS12_verify_mac(p12, password, password_len) == 0
                                {
                                    CBB_cleanup(&mut cbb);
                                } else {
                                    ret = 1 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    OPENSSL_free(mac_salt as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn run_static_initializers() {
    PKCS8_PRIV_KEY_INFO_it = {
        let mut init = ASN1_ITEM_st {
            itype: 0x1 as libc::c_int as libc::c_char,
            utype: 16 as libc::c_int,
            templates: PKCS8_PRIV_KEY_INFO_seq_tt.as_ptr(),
            tcount: (::core::mem::size_of::<[ASN1_TEMPLATE; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<ASN1_TEMPLATE>() as libc::c_ulong)
                as libc::c_long,
            funcs: 0 as *const libc::c_void,
            size: ::core::mem::size_of::<PKCS8_PRIV_KEY_INFO>() as libc::c_ulong
                as libc::c_long,
            sname: b"PKCS8_PRIV_KEY_INFO\0" as *const u8 as *const libc::c_char,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
