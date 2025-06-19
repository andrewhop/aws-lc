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
    pub type x509_lookup_st;
    pub type x509_lookup_method_st;
    pub type x509_store_st;
    fn X509_STORE_add_lookup(
        store: *mut X509_STORE,
        method: *const X509_LOOKUP_METHOD,
    ) -> *mut X509_LOOKUP;
    fn X509_LOOKUP_hash_dir() -> *const X509_LOOKUP_METHOD;
    fn X509_LOOKUP_file() -> *const X509_LOOKUP_METHOD;
    fn X509_LOOKUP_load_file(
        lookup: *mut X509_LOOKUP,
        file: *const libc::c_char,
        type_0: libc::c_int,
    ) -> libc::c_int;
    fn X509_LOOKUP_add_dir(
        lookup: *mut X509_LOOKUP,
        path: *const libc::c_char,
        type_0: libc::c_int,
    ) -> libc::c_int;
    fn ERR_clear_error();
}
pub type X509_LOOKUP = x509_lookup_st;
pub type X509_LOOKUP_METHOD = x509_lookup_method_st;
pub type X509_STORE = x509_store_st;
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_default_paths(
    mut ctx: *mut X509_STORE,
) -> libc::c_int {
    let mut lookup: *mut X509_LOOKUP = 0 as *mut X509_LOOKUP;
    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());
    if lookup.is_null() {
        return 0 as libc::c_int;
    }
    X509_LOOKUP_load_file(lookup, 0 as *const libc::c_char, 3 as libc::c_int);
    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
    if lookup.is_null() {
        return 0 as libc::c_int;
    }
    X509_LOOKUP_add_dir(lookup, 0 as *const libc::c_char, 3 as libc::c_int);
    ERR_clear_error();
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_load_locations(
    mut ctx: *mut X509_STORE,
    mut file: *const libc::c_char,
    mut path: *const libc::c_char,
) -> libc::c_int {
    let mut lookup: *mut X509_LOOKUP = 0 as *mut X509_LOOKUP;
    if !file.is_null() {
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());
        if lookup.is_null() {
            return 0 as libc::c_int;
        }
        if X509_LOOKUP_load_file(lookup, file, 1 as libc::c_int) != 1 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    if !path.is_null() {
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
        if lookup.is_null() {
            return 0 as libc::c_int;
        }
        if X509_LOOKUP_add_dir(lookup, path, 1 as libc::c_int) != 1 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    if path.is_null() && file.is_null() {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
