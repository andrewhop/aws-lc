#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
extern "C" {
    fn pqcrystals_kyber512_ref_keypair_derand(
        pk: *mut uint8_t,
        sk: *mut uint8_t,
        coins: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber512_ref_keypair(
        pk: *mut uint8_t,
        sk: *mut uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber512_ref_enc_derand(
        ct: *mut uint8_t,
        ss: *mut uint8_t,
        pk: *const uint8_t,
        coins: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber512_ref_enc(
        ct: *mut uint8_t,
        ss: *mut uint8_t,
        pk: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber512_ref_dec(
        ss: *mut uint8_t,
        ct: *const uint8_t,
        sk: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber768_ref_keypair_derand(
        pk: *mut uint8_t,
        sk: *mut uint8_t,
        coins: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber768_ref_keypair(
        pk: *mut uint8_t,
        sk: *mut uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber768_ref_enc_derand(
        ct: *mut uint8_t,
        ss: *mut uint8_t,
        pk: *const uint8_t,
        coins: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber768_ref_enc(
        ct: *mut uint8_t,
        ss: *mut uint8_t,
        pk: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber768_ref_dec(
        ss: *mut uint8_t,
        ct: *const uint8_t,
        sk: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber1024_ref_keypair_derand(
        pk: *mut uint8_t,
        sk: *mut uint8_t,
        coins: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber1024_ref_keypair(
        pk: *mut uint8_t,
        sk: *mut uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber1024_ref_enc_derand(
        ct: *mut uint8_t,
        ss: *mut uint8_t,
        pk: *const uint8_t,
        coins: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber1024_ref_enc(
        ct: *mut uint8_t,
        ss: *mut uint8_t,
        pk: *const uint8_t,
    ) -> libc::c_int;
    fn pqcrystals_kyber1024_ref_dec(
        ss: *mut uint8_t,
        ct: *const uint8_t,
        sk: *const uint8_t,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KEM {
    pub nid: libc::c_int,
    pub oid: *const uint8_t,
    pub oid_len: uint8_t,
    pub comment: *const libc::c_char,
    pub public_key_len: size_t,
    pub secret_key_len: size_t,
    pub ciphertext_len: size_t,
    pub shared_secret_len: size_t,
    pub keygen_seed_len: size_t,
    pub encaps_seed_len: size_t,
    pub method: *const KEM_METHOD,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KEM_METHOD {
    pub keygen_deterministic: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub keygen: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
        ) -> libc::c_int,
    >,
    pub encaps_deterministic: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub encaps: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
    pub decaps: Option::<
        unsafe extern "C" fn(
            *mut uint8_t,
            *mut size_t,
            *const uint8_t,
            *const uint8_t,
        ) -> libc::c_int,
    >,
}
unsafe extern "C" fn kyber512r3_keygen_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber512_ref_keypair_derand(public_key, secret_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber512r3_keygen(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    return (pqcrystals_kyber512_ref_keypair(public_key, secret_key) == 0 as libc::c_int)
        as libc::c_int;
}
unsafe extern "C" fn kyber512r3_encaps_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber512_ref_enc_derand(
        ciphertext,
        shared_secret,
        public_key,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber512r3_encaps(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber512_ref_enc(ciphertext, shared_secret, public_key)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber512r3_decaps(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber512_ref_dec(shared_secret, ciphertext, secret_key)
        == 0 as libc::c_int) as libc::c_int;
}
static mut kem_kyber512r3_method: KEM_METHOD = unsafe {
    {
        let mut init = KEM_METHOD {
            keygen_deterministic: Some(
                kyber512r3_keygen_deterministic
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            keygen: Some(
                kyber512r3_keygen
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            encaps_deterministic: Some(
                kyber512r3_encaps_deterministic
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            encaps: Some(
                kyber512r3_encaps
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            decaps: Some(
                kyber512r3_decaps
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
unsafe extern "C" fn kyber768r3_keygen_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber768_ref_keypair_derand(public_key, secret_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber768r3_keygen(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    return (pqcrystals_kyber768_ref_keypair(public_key, secret_key) == 0 as libc::c_int)
        as libc::c_int;
}
unsafe extern "C" fn kyber768r3_encaps_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber768_ref_enc_derand(
        ciphertext,
        shared_secret,
        public_key,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber768r3_encaps(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber768r3_decaps(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key)
        == 0 as libc::c_int) as libc::c_int;
}
static mut kem_kyber768r3_method: KEM_METHOD = unsafe {
    {
        let mut init = KEM_METHOD {
            keygen_deterministic: Some(
                kyber768r3_keygen_deterministic
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            keygen: Some(
                kyber768r3_keygen
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            encaps_deterministic: Some(
                kyber768r3_encaps_deterministic
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            encaps: Some(
                kyber768r3_encaps
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            decaps: Some(
                kyber768r3_decaps
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
unsafe extern "C" fn kyber1024r3_keygen_deterministic(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber1024_ref_keypair_derand(public_key, secret_key, seed)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber1024r3_keygen(
    mut public_key: *mut uint8_t,
    mut public_len: *mut size_t,
    mut secret_key: *mut uint8_t,
    mut secret_len: *mut size_t,
) -> libc::c_int {
    return (pqcrystals_kyber1024_ref_keypair(public_key, secret_key) == 0 as libc::c_int)
        as libc::c_int;
}
unsafe extern "C" fn kyber1024r3_encaps_deterministic(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
    mut seed: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber1024_ref_enc_derand(
        ciphertext,
        shared_secret,
        public_key,
        seed,
    ) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber1024r3_encaps(
    mut ciphertext: *mut uint8_t,
    mut ciphertext_len: *mut size_t,
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut public_key: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber1024_ref_enc(ciphertext, shared_secret, public_key)
        == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn kyber1024r3_decaps(
    mut shared_secret: *mut uint8_t,
    mut shared_secret_len: *mut size_t,
    mut ciphertext: *const uint8_t,
    mut secret_key: *const uint8_t,
) -> libc::c_int {
    return (pqcrystals_kyber1024_ref_dec(shared_secret, ciphertext, secret_key)
        == 0 as libc::c_int) as libc::c_int;
}
static mut kem_kyber1024r3_method: KEM_METHOD = unsafe {
    {
        let mut init = KEM_METHOD {
            keygen_deterministic: Some(
                kyber1024r3_keygen_deterministic
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            keygen: Some(
                kyber1024r3_keygen
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                    ) -> libc::c_int,
            ),
            encaps_deterministic: Some(
                kyber1024r3_encaps_deterministic
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            encaps: Some(
                kyber1024r3_encaps
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
            decaps: Some(
                kyber1024r3_decaps
                    as unsafe extern "C" fn(
                        *mut uint8_t,
                        *mut size_t,
                        *const uint8_t,
                        *const uint8_t,
                    ) -> libc::c_int,
            ),
        };
        init
    }
};
static mut kOIDKyber512r3: [uint8_t; 4] = [
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
];
static mut kOIDKyber768r3: [uint8_t; 4] = [
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
];
static mut kOIDKyber1024r3: [uint8_t; 4] = [
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
];
static mut legacy_kem_kyber512_r3: KEM = unsafe {
    {
        let mut init = KEM {
            nid: 972 as libc::c_int,
            oid: kOIDKyber512r3.as_ptr(),
            oid_len: ::core::mem::size_of::<[uint8_t; 4]>() as libc::c_ulong as uint8_t,
            comment: b"Kyber512 Round-3\0" as *const u8 as *const libc::c_char,
            public_key_len: 800 as libc::c_int as size_t,
            secret_key_len: 1632 as libc::c_int as size_t,
            ciphertext_len: 768 as libc::c_int as size_t,
            shared_secret_len: 32 as libc::c_int as size_t,
            keygen_seed_len: 64 as libc::c_int as size_t,
            encaps_seed_len: 32 as libc::c_int as size_t,
            method: &kem_kyber512r3_method as *const KEM_METHOD,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn get_legacy_kem_kyber512_r3() -> *const KEM {
    return &legacy_kem_kyber512_r3;
}
static mut legacy_kem_kyber768_r3: KEM = unsafe {
    {
        let mut init = KEM {
            nid: 973 as libc::c_int,
            oid: kOIDKyber768r3.as_ptr(),
            oid_len: ::core::mem::size_of::<[uint8_t; 4]>() as libc::c_ulong as uint8_t,
            comment: b"Kyber768 Round-3\0" as *const u8 as *const libc::c_char,
            public_key_len: 1184 as libc::c_int as size_t,
            secret_key_len: 2400 as libc::c_int as size_t,
            ciphertext_len: 1088 as libc::c_int as size_t,
            shared_secret_len: 32 as libc::c_int as size_t,
            keygen_seed_len: 64 as libc::c_int as size_t,
            encaps_seed_len: 32 as libc::c_int as size_t,
            method: &kem_kyber768r3_method as *const KEM_METHOD,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn get_legacy_kem_kyber768_r3() -> *const KEM {
    return &legacy_kem_kyber768_r3;
}
static mut legacy_kem_kyber1024_r3: KEM = unsafe {
    {
        let mut init = KEM {
            nid: 974 as libc::c_int,
            oid: kOIDKyber1024r3.as_ptr(),
            oid_len: ::core::mem::size_of::<[uint8_t; 4]>() as libc::c_ulong as uint8_t,
            comment: b"Kyber1024 Round-3\0" as *const u8 as *const libc::c_char,
            public_key_len: 1568 as libc::c_int as size_t,
            secret_key_len: 3168 as libc::c_int as size_t,
            ciphertext_len: 1568 as libc::c_int as size_t,
            shared_secret_len: 32 as libc::c_int as size_t,
            keygen_seed_len: 64 as libc::c_int as size_t,
            encaps_seed_len: 32 as libc::c_int as size_t,
            method: &kem_kyber1024r3_method as *const KEM_METHOD,
        };
        init
    }
};
#[no_mangle]
pub unsafe extern "C" fn get_legacy_kem_kyber1024_r3() -> *const KEM {
    return &legacy_kem_kyber1024_r3;
}
