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
    pub type stack_st_void;
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_ctrl(
        bio: *mut BIO,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut FILE,
    ) -> *mut libc::c_char;
    fn fread(
        _: *mut libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn fwrite(
        _: *const libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn fseek(
        __stream: *mut FILE,
        __off: libc::c_long,
        __whence: libc::c_int,
    ) -> libc::c_int;
    fn ftell(__stream: *mut FILE) -> libc::c_long;
    fn feof(__stream: *mut FILE) -> libc::c_int;
    fn ferror(__stream: *mut FILE) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    fn ERR_put_error(
        library: libc::c_int,
        unused: libc::c_int,
        reason: libc::c_int,
        file: *const libc::c_char,
        line: libc::c_uint,
    );
    fn ERR_add_error_data(count: libc::c_uint, _: ...);
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_new_file(
    mut filename: *const libc::c_char,
    mut mode: *const libc::c_char,
) -> *mut BIO {
    let mut ret: *mut BIO = 0 as *mut BIO;
    let mut file: *mut FILE = 0 as *mut FILE;
    file = fopen(filename, mode);
    if file.is_null() {
        ERR_put_error(
            2 as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/file.c\0" as *const u8
                as *const libc::c_char,
            110 as libc::c_int as libc::c_uint,
        );
        ERR_add_error_data(
            5 as libc::c_int as libc::c_uint,
            b"fopen('\0" as *const u8 as *const libc::c_char,
            filename,
            b"','\0" as *const u8 as *const libc::c_char,
            mode,
            b"')\0" as *const u8 as *const libc::c_char,
        );
        if *__errno_location() == 2 as libc::c_int {
            ERR_put_error(
                17 as libc::c_int,
                0 as libc::c_int,
                110 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/file.c\0" as *const u8
                    as *const libc::c_char,
                114 as libc::c_int as libc::c_uint,
            );
        } else {
            ERR_put_error(
                17 as libc::c_int,
                0 as libc::c_int,
                112 as libc::c_int,
                b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/file.c\0" as *const u8
                    as *const libc::c_char,
                116 as libc::c_int as libc::c_uint,
            );
        }
        return 0 as *mut BIO;
    }
    ret = BIO_new_fp(file, 1 as libc::c_int);
    if ret.is_null() {
        fclose(file);
        return 0 as *mut BIO;
    }
    return ret;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_new_fp(
    mut stream: *mut FILE,
    mut close_flag: libc::c_int,
) -> *mut BIO {
    let mut ret: *mut BIO = BIO_new(BIO_s_file());
    if ret.is_null() {
        return 0 as *mut BIO;
    }
    BIO_set_fp(ret, stream, close_flag);
    return ret;
}
unsafe extern "C" fn file_free(mut bio: *mut BIO) -> libc::c_int {
    if (*bio).shutdown == 0 {
        return 1 as libc::c_int;
    }
    if (*bio).init != 0 && !((*bio).ptr).is_null() {
        fclose((*bio).ptr as *mut FILE);
        (*bio).ptr = 0 as *mut libc::c_void;
    }
    (*bio).init = 0 as libc::c_int;
    return 1 as libc::c_int;
}
unsafe extern "C" fn file_read(
    mut b: *mut BIO,
    mut out: *mut libc::c_char,
    mut outl: libc::c_int,
) -> libc::c_int {
    if (*b).init == 0 {
        return 0 as libc::c_int;
    }
    let mut ret: size_t = fread(
        out as *mut libc::c_void,
        1 as libc::c_int as libc::c_ulong,
        outl as libc::c_ulong,
        (*b).ptr as *mut FILE,
    );
    if ret == 0 as libc::c_int as size_t && ferror((*b).ptr as *mut FILE) != 0 {
        ERR_put_error(
            2 as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/file.c\0" as *const u8
                as *const libc::c_char,
            162 as libc::c_int as libc::c_uint,
        );
        ERR_put_error(
            17 as libc::c_int,
            0 as libc::c_int,
            2 as libc::c_int,
            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/file.c\0" as *const u8
                as *const libc::c_char,
            163 as libc::c_int as libc::c_uint,
        );
        return -(1 as libc::c_int);
    }
    return ret as libc::c_int;
}
unsafe extern "C" fn file_write(
    mut b: *mut BIO,
    mut in_0: *const libc::c_char,
    mut inl: libc::c_int,
) -> libc::c_int {
    if (*b).init == 0 {
        return 0 as libc::c_int;
    }
    let mut ret: libc::c_int = fwrite(
        in_0 as *const libc::c_void,
        inl as libc::c_ulong,
        1 as libc::c_int as libc::c_ulong,
        (*b).ptr as *mut FILE,
    ) as libc::c_int;
    if ret > 0 as libc::c_int {
        ret = inl;
    }
    return ret;
}
unsafe extern "C" fn file_ctrl(
    mut b: *mut BIO,
    mut cmd: libc::c_int,
    mut num: libc::c_long,
    mut ptr: *mut libc::c_void,
) -> libc::c_long {
    let mut ret: libc::c_long = 1 as libc::c_int as libc::c_long;
    let mut fp: *mut FILE = (*b).ptr as *mut FILE;
    let mut fpp: *mut *mut FILE = 0 as *mut *mut FILE;
    let mut mode: *const libc::c_char = 0 as *const libc::c_char;
    let mut current_block_40: u64;
    match cmd {
        1 => {
            num = 0 as libc::c_int as libc::c_long;
            current_block_40 = 5496900563656886382;
        }
        128 => {
            current_block_40 = 5496900563656886382;
        }
        2 => {
            ret = feof(fp) as libc::c_long;
            current_block_40 = 15004371738079956865;
        }
        133 | 3 => {
            ret = ftell(fp);
            current_block_40 = 15004371738079956865;
        }
        106 => {
            file_free(b);
            (*b).shutdown = num as libc::c_int & 1 as libc::c_int;
            (*b).ptr = ptr;
            (*b).init = 1 as libc::c_int;
            current_block_40 = 15004371738079956865;
        }
        108 => {
            file_free(b);
            (*b).shutdown = num as libc::c_int & 1 as libc::c_int;
            mode = 0 as *const libc::c_char;
            if num & 0x8 as libc::c_int as libc::c_long != 0 {
                if num & 0x2 as libc::c_int as libc::c_long != 0 {
                    mode = b"ab+\0" as *const u8 as *const libc::c_char;
                } else {
                    mode = b"ab\0" as *const u8 as *const libc::c_char;
                }
                current_block_40 = 13550086250199790493;
            } else if num & 0x2 as libc::c_int as libc::c_long != 0
                && num & 0x4 as libc::c_int as libc::c_long != 0
            {
                mode = b"rb+\0" as *const u8 as *const libc::c_char;
                current_block_40 = 13550086250199790493;
            } else if num & 0x4 as libc::c_int as libc::c_long != 0 {
                mode = b"wb\0" as *const u8 as *const libc::c_char;
                current_block_40 = 13550086250199790493;
            } else if num & 0x2 as libc::c_int as libc::c_long != 0 {
                mode = b"rb\0" as *const u8 as *const libc::c_char;
                current_block_40 = 13550086250199790493;
            } else {
                ERR_put_error(
                    17 as libc::c_int,
                    0 as libc::c_int,
                    100 as libc::c_int,
                    b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/file.c\0" as *const u8
                        as *const libc::c_char,
                    236 as libc::c_int as libc::c_uint,
                );
                ret = 0 as libc::c_int as libc::c_long;
                current_block_40 = 15004371738079956865;
            }
            match current_block_40 {
                15004371738079956865 => {}
                _ => {
                    fp = fopen(ptr as *const libc::c_char, mode);
                    if fp.is_null() {
                        ERR_put_error(
                            2 as libc::c_int,
                            0 as libc::c_int,
                            0 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/file.c\0"
                                as *const u8 as *const libc::c_char,
                            242 as libc::c_int as libc::c_uint,
                        );
                        ERR_add_error_data(
                            5 as libc::c_int as libc::c_uint,
                            b"fopen('\0" as *const u8 as *const libc::c_char,
                            ptr,
                            b"','\0" as *const u8 as *const libc::c_char,
                            mode,
                            b"')\0" as *const u8 as *const libc::c_char,
                        );
                        ERR_put_error(
                            17 as libc::c_int,
                            0 as libc::c_int,
                            2 as libc::c_int,
                            b"/home/ubuntu/workspace/oss/aws-lc/crypto/bio/file.c\0"
                                as *const u8 as *const libc::c_char,
                            244 as libc::c_int as libc::c_uint,
                        );
                        ret = 0 as libc::c_int as libc::c_long;
                    } else {
                        (*b).ptr = fp as *mut libc::c_void;
                        (*b).init = 1 as libc::c_int;
                    }
                    current_block_40 = 15004371738079956865;
                }
            }
        }
        107 => {
            if !ptr.is_null() {
                fpp = ptr as *mut *mut FILE;
                *fpp = (*b).ptr as *mut FILE;
            }
            current_block_40 = 15004371738079956865;
        }
        8 => {
            ret = (*b).shutdown as libc::c_long;
            current_block_40 = 15004371738079956865;
        }
        9 => {
            (*b).shutdown = num as libc::c_int;
            current_block_40 = 15004371738079956865;
        }
        11 => {
            ret = (0 as libc::c_int == fflush((*b).ptr as *mut FILE)) as libc::c_int
                as libc::c_long;
            current_block_40 = 15004371738079956865;
        }
        13 | 10 | _ => {
            ret = 0 as libc::c_int as libc::c_long;
            current_block_40 = 15004371738079956865;
        }
    }
    match current_block_40 {
        5496900563656886382 => {
            ret = fseek(fp, num, 0 as libc::c_int) as libc::c_long;
        }
        _ => {}
    }
    return ret;
}
unsafe extern "C" fn file_gets(
    mut bp: *mut BIO,
    mut buf: *mut libc::c_char,
    mut size: libc::c_int,
) -> libc::c_int {
    if size == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if (fgets(buf, size, (*bp).ptr as *mut FILE)).is_null() {
        *buf.offset(0 as libc::c_int as isize) = 0 as libc::c_int as libc::c_char;
        return 0 as libc::c_int;
    }
    return strlen(buf) as libc::c_int;
}
static mut methods_filep: BIO_METHOD = unsafe {
    {
        let mut init = bio_method_st {
            type_0: 2 as libc::c_int | 0x400 as libc::c_int,
            name: b"FILE pointer\0" as *const u8 as *const libc::c_char,
            bwrite: Some(
                file_write
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *const libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bread: Some(
                file_read
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            bputs: None,
            bgets: Some(
                file_gets
                    as unsafe extern "C" fn(
                        *mut BIO,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            ctrl: Some(
                file_ctrl
                    as unsafe extern "C" fn(
                        *mut BIO,
                        libc::c_int,
                        libc::c_long,
                        *mut libc::c_void,
                    ) -> libc::c_long,
            ),
            create: None,
            destroy: Some(file_free as unsafe extern "C" fn(*mut BIO) -> libc::c_int),
            callback_ctrl: None,
        };
        init
    }
};
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_s_file() -> *const BIO_METHOD {
    return &methods_filep;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_get_fp(
    mut bio: *mut BIO,
    mut out_file: *mut *mut FILE,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        107 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        out_file as *mut libc::c_char as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_set_fp(
    mut bio: *mut BIO,
    mut file: *mut FILE,
    mut flags: libc::c_int,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        106 as libc::c_int,
        flags as libc::c_long,
        file as *mut libc::c_char as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_read_filename(
    mut bio: *mut BIO,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        108 as libc::c_int,
        (1 as libc::c_int | 0x2 as libc::c_int) as libc::c_long,
        filename as *mut libc::c_char as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_write_filename(
    mut bio: *mut BIO,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        108 as libc::c_int,
        (1 as libc::c_int | 0x4 as libc::c_int) as libc::c_long,
        filename as *mut libc::c_char as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_append_filename(
    mut bio: *mut BIO,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        108 as libc::c_int,
        (1 as libc::c_int | 0x8 as libc::c_int) as libc::c_long,
        filename as *mut libc::c_char as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_rw_filename(
    mut bio: *mut BIO,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    return BIO_ctrl(
        bio,
        108 as libc::c_int,
        (1 as libc::c_int | 0x2 as libc::c_int | 0x4 as libc::c_int) as libc::c_long,
        filename as *mut libc::c_char as *mut libc::c_void,
    ) as libc::c_int;
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_tell(mut bio: *mut BIO) -> libc::c_long {
    return BIO_ctrl(
        bio,
        133 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    );
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_seek(
    mut bio: *mut BIO,
    mut offset: libc::c_long,
) -> libc::c_long {
    return BIO_ctrl(bio, 128 as libc::c_int, offset, 0 as *mut libc::c_void);
}
