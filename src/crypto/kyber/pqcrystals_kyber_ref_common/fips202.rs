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
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct keccak_state {
    pub s: [uint64_t; 25],
    pub pos: libc::c_uint,
}
unsafe extern "C" fn load64(mut x: *const uint8_t) -> uint64_t {
    let mut i: libc::c_uint = 0;
    let mut r: uint64_t = 0 as libc::c_int as uint64_t;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 8 as libc::c_int as libc::c_uint {
        r
            |= (*x.offset(i as isize) as uint64_t)
                << (8 as libc::c_int as libc::c_uint).wrapping_mul(i);
        i = i.wrapping_add(1);
        i;
    }
    return r;
}
unsafe extern "C" fn store64(mut x: *mut uint8_t, mut u: uint64_t) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 8 as libc::c_int as libc::c_uint {
        *x
            .offset(
                i as isize,
            ) = (u >> (8 as libc::c_int as libc::c_uint).wrapping_mul(i)) as uint8_t;
        i = i.wrapping_add(1);
        i;
    }
}
static mut KeccakF_RoundConstants: [uint64_t; 24] = [
    0x1 as libc::c_ulonglong as uint64_t,
    0x8082 as libc::c_ulonglong as uint64_t,
    0x800000000000808a as libc::c_ulonglong as uint64_t,
    0x8000000080008000 as libc::c_ulonglong as uint64_t,
    0x808b as libc::c_ulonglong as uint64_t,
    0x80000001 as libc::c_ulonglong as uint64_t,
    0x8000000080008081 as libc::c_ulonglong as uint64_t,
    0x8000000000008009 as libc::c_ulonglong as uint64_t,
    0x8a as libc::c_ulonglong as uint64_t,
    0x88 as libc::c_ulonglong as uint64_t,
    0x80008009 as libc::c_ulonglong as uint64_t,
    0x8000000a as libc::c_ulonglong as uint64_t,
    0x8000808b as libc::c_ulonglong as uint64_t,
    0x800000000000008b as libc::c_ulonglong as uint64_t,
    0x8000000000008089 as libc::c_ulonglong as uint64_t,
    0x8000000000008003 as libc::c_ulonglong as uint64_t,
    0x8000000000008002 as libc::c_ulonglong as uint64_t,
    0x8000000000000080 as libc::c_ulonglong as uint64_t,
    0x800a as libc::c_ulonglong as uint64_t,
    0x800000008000000a as libc::c_ulonglong as uint64_t,
    0x8000000080008081 as libc::c_ulonglong as uint64_t,
    0x8000000000008080 as libc::c_ulonglong as uint64_t,
    0x80000001 as libc::c_ulonglong as uint64_t,
    0x8000000080008008 as libc::c_ulonglong as uint64_t,
];
unsafe extern "C" fn KeccakF1600_StatePermute(mut state: *mut uint64_t) {
    let mut round: libc::c_int = 0;
    let mut Aba: uint64_t = 0;
    let mut Abe: uint64_t = 0;
    let mut Abi: uint64_t = 0;
    let mut Abo: uint64_t = 0;
    let mut Abu: uint64_t = 0;
    let mut Aga: uint64_t = 0;
    let mut Age: uint64_t = 0;
    let mut Agi: uint64_t = 0;
    let mut Ago: uint64_t = 0;
    let mut Agu: uint64_t = 0;
    let mut Aka: uint64_t = 0;
    let mut Ake: uint64_t = 0;
    let mut Aki: uint64_t = 0;
    let mut Ako: uint64_t = 0;
    let mut Aku: uint64_t = 0;
    let mut Ama: uint64_t = 0;
    let mut Ame: uint64_t = 0;
    let mut Ami: uint64_t = 0;
    let mut Amo: uint64_t = 0;
    let mut Amu: uint64_t = 0;
    let mut Asa: uint64_t = 0;
    let mut Ase: uint64_t = 0;
    let mut Asi: uint64_t = 0;
    let mut Aso: uint64_t = 0;
    let mut Asu: uint64_t = 0;
    let mut BCa: uint64_t = 0;
    let mut BCe: uint64_t = 0;
    let mut BCi: uint64_t = 0;
    let mut BCo: uint64_t = 0;
    let mut BCu: uint64_t = 0;
    let mut Da: uint64_t = 0;
    let mut De: uint64_t = 0;
    let mut Di: uint64_t = 0;
    let mut Do: uint64_t = 0;
    let mut Du: uint64_t = 0;
    let mut Eba: uint64_t = 0;
    let mut Ebe: uint64_t = 0;
    let mut Ebi: uint64_t = 0;
    let mut Ebo: uint64_t = 0;
    let mut Ebu: uint64_t = 0;
    let mut Ega: uint64_t = 0;
    let mut Ege: uint64_t = 0;
    let mut Egi: uint64_t = 0;
    let mut Ego: uint64_t = 0;
    let mut Egu: uint64_t = 0;
    let mut Eka: uint64_t = 0;
    let mut Eke: uint64_t = 0;
    let mut Eki: uint64_t = 0;
    let mut Eko: uint64_t = 0;
    let mut Eku: uint64_t = 0;
    let mut Ema: uint64_t = 0;
    let mut Eme: uint64_t = 0;
    let mut Emi: uint64_t = 0;
    let mut Emo: uint64_t = 0;
    let mut Emu: uint64_t = 0;
    let mut Esa: uint64_t = 0;
    let mut Ese: uint64_t = 0;
    let mut Esi: uint64_t = 0;
    let mut Eso: uint64_t = 0;
    let mut Esu: uint64_t = 0;
    Aba = *state.offset(0 as libc::c_int as isize);
    Abe = *state.offset(1 as libc::c_int as isize);
    Abi = *state.offset(2 as libc::c_int as isize);
    Abo = *state.offset(3 as libc::c_int as isize);
    Abu = *state.offset(4 as libc::c_int as isize);
    Aga = *state.offset(5 as libc::c_int as isize);
    Age = *state.offset(6 as libc::c_int as isize);
    Agi = *state.offset(7 as libc::c_int as isize);
    Ago = *state.offset(8 as libc::c_int as isize);
    Agu = *state.offset(9 as libc::c_int as isize);
    Aka = *state.offset(10 as libc::c_int as isize);
    Ake = *state.offset(11 as libc::c_int as isize);
    Aki = *state.offset(12 as libc::c_int as isize);
    Ako = *state.offset(13 as libc::c_int as isize);
    Aku = *state.offset(14 as libc::c_int as isize);
    Ama = *state.offset(15 as libc::c_int as isize);
    Ame = *state.offset(16 as libc::c_int as isize);
    Ami = *state.offset(17 as libc::c_int as isize);
    Amo = *state.offset(18 as libc::c_int as isize);
    Amu = *state.offset(19 as libc::c_int as isize);
    Asa = *state.offset(20 as libc::c_int as isize);
    Ase = *state.offset(21 as libc::c_int as isize);
    Asi = *state.offset(22 as libc::c_int as isize);
    Aso = *state.offset(23 as libc::c_int as isize);
    Asu = *state.offset(24 as libc::c_int as isize);
    round = 0 as libc::c_int;
    while round < 24 as libc::c_int {
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
        Da = BCu
            ^ (BCe << 1 as libc::c_int ^ BCe >> 64 as libc::c_int - 1 as libc::c_int);
        De = BCa
            ^ (BCi << 1 as libc::c_int ^ BCi >> 64 as libc::c_int - 1 as libc::c_int);
        Di = BCe
            ^ (BCo << 1 as libc::c_int ^ BCo >> 64 as libc::c_int - 1 as libc::c_int);
        Do = BCi
            ^ (BCu << 1 as libc::c_int ^ BCu >> 64 as libc::c_int - 1 as libc::c_int);
        Du = BCo
            ^ (BCa << 1 as libc::c_int ^ BCa >> 64 as libc::c_int - 1 as libc::c_int);
        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = Age << 44 as libc::c_int ^ Age >> 64 as libc::c_int - 44 as libc::c_int;
        Aki ^= Di;
        BCi = Aki << 43 as libc::c_int ^ Aki >> 64 as libc::c_int - 43 as libc::c_int;
        Amo ^= Do;
        BCo = Amo << 21 as libc::c_int ^ Amo >> 64 as libc::c_int - 21 as libc::c_int;
        Asu ^= Du;
        BCu = Asu << 14 as libc::c_int ^ Asu >> 64 as libc::c_int - 14 as libc::c_int;
        Eba = BCa ^ !BCe & BCi;
        Eba ^= KeccakF_RoundConstants[round as usize];
        Ebe = BCe ^ !BCi & BCo;
        Ebi = BCi ^ !BCo & BCu;
        Ebo = BCo ^ !BCu & BCa;
        Ebu = BCu ^ !BCa & BCe;
        Abo ^= Do;
        BCa = Abo << 28 as libc::c_int ^ Abo >> 64 as libc::c_int - 28 as libc::c_int;
        Agu ^= Du;
        BCe = Agu << 20 as libc::c_int ^ Agu >> 64 as libc::c_int - 20 as libc::c_int;
        Aka ^= Da;
        BCi = Aka << 3 as libc::c_int ^ Aka >> 64 as libc::c_int - 3 as libc::c_int;
        Ame ^= De;
        BCo = Ame << 45 as libc::c_int ^ Ame >> 64 as libc::c_int - 45 as libc::c_int;
        Asi ^= Di;
        BCu = Asi << 61 as libc::c_int ^ Asi >> 64 as libc::c_int - 61 as libc::c_int;
        Ega = BCa ^ !BCe & BCi;
        Ege = BCe ^ !BCi & BCo;
        Egi = BCi ^ !BCo & BCu;
        Ego = BCo ^ !BCu & BCa;
        Egu = BCu ^ !BCa & BCe;
        Abe ^= De;
        BCa = Abe << 1 as libc::c_int ^ Abe >> 64 as libc::c_int - 1 as libc::c_int;
        Agi ^= Di;
        BCe = Agi << 6 as libc::c_int ^ Agi >> 64 as libc::c_int - 6 as libc::c_int;
        Ako ^= Do;
        BCi = Ako << 25 as libc::c_int ^ Ako >> 64 as libc::c_int - 25 as libc::c_int;
        Amu ^= Du;
        BCo = Amu << 8 as libc::c_int ^ Amu >> 64 as libc::c_int - 8 as libc::c_int;
        Asa ^= Da;
        BCu = Asa << 18 as libc::c_int ^ Asa >> 64 as libc::c_int - 18 as libc::c_int;
        Eka = BCa ^ !BCe & BCi;
        Eke = BCe ^ !BCi & BCo;
        Eki = BCi ^ !BCo & BCu;
        Eko = BCo ^ !BCu & BCa;
        Eku = BCu ^ !BCa & BCe;
        Abu ^= Du;
        BCa = Abu << 27 as libc::c_int ^ Abu >> 64 as libc::c_int - 27 as libc::c_int;
        Aga ^= Da;
        BCe = Aga << 36 as libc::c_int ^ Aga >> 64 as libc::c_int - 36 as libc::c_int;
        Ake ^= De;
        BCi = Ake << 10 as libc::c_int ^ Ake >> 64 as libc::c_int - 10 as libc::c_int;
        Ami ^= Di;
        BCo = Ami << 15 as libc::c_int ^ Ami >> 64 as libc::c_int - 15 as libc::c_int;
        Aso ^= Do;
        BCu = Aso << 56 as libc::c_int ^ Aso >> 64 as libc::c_int - 56 as libc::c_int;
        Ema = BCa ^ !BCe & BCi;
        Eme = BCe ^ !BCi & BCo;
        Emi = BCi ^ !BCo & BCu;
        Emo = BCo ^ !BCu & BCa;
        Emu = BCu ^ !BCa & BCe;
        Abi ^= Di;
        BCa = Abi << 62 as libc::c_int ^ Abi >> 64 as libc::c_int - 62 as libc::c_int;
        Ago ^= Do;
        BCe = Ago << 55 as libc::c_int ^ Ago >> 64 as libc::c_int - 55 as libc::c_int;
        Aku ^= Du;
        BCi = Aku << 39 as libc::c_int ^ Aku >> 64 as libc::c_int - 39 as libc::c_int;
        Ama ^= Da;
        BCo = Ama << 41 as libc::c_int ^ Ama >> 64 as libc::c_int - 41 as libc::c_int;
        Ase ^= De;
        BCu = Ase << 2 as libc::c_int ^ Ase >> 64 as libc::c_int - 2 as libc::c_int;
        Esa = BCa ^ !BCe & BCi;
        Ese = BCe ^ !BCi & BCo;
        Esi = BCi ^ !BCo & BCu;
        Eso = BCo ^ !BCu & BCa;
        Esu = BCu ^ !BCa & BCe;
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
        Da = BCu
            ^ (BCe << 1 as libc::c_int ^ BCe >> 64 as libc::c_int - 1 as libc::c_int);
        De = BCa
            ^ (BCi << 1 as libc::c_int ^ BCi >> 64 as libc::c_int - 1 as libc::c_int);
        Di = BCe
            ^ (BCo << 1 as libc::c_int ^ BCo >> 64 as libc::c_int - 1 as libc::c_int);
        Do = BCi
            ^ (BCu << 1 as libc::c_int ^ BCu >> 64 as libc::c_int - 1 as libc::c_int);
        Du = BCo
            ^ (BCa << 1 as libc::c_int ^ BCa >> 64 as libc::c_int - 1 as libc::c_int);
        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = Ege << 44 as libc::c_int ^ Ege >> 64 as libc::c_int - 44 as libc::c_int;
        Eki ^= Di;
        BCi = Eki << 43 as libc::c_int ^ Eki >> 64 as libc::c_int - 43 as libc::c_int;
        Emo ^= Do;
        BCo = Emo << 21 as libc::c_int ^ Emo >> 64 as libc::c_int - 21 as libc::c_int;
        Esu ^= Du;
        BCu = Esu << 14 as libc::c_int ^ Esu >> 64 as libc::c_int - 14 as libc::c_int;
        Aba = BCa ^ !BCe & BCi;
        Aba ^= KeccakF_RoundConstants[(round + 1 as libc::c_int) as usize];
        Abe = BCe ^ !BCi & BCo;
        Abi = BCi ^ !BCo & BCu;
        Abo = BCo ^ !BCu & BCa;
        Abu = BCu ^ !BCa & BCe;
        Ebo ^= Do;
        BCa = Ebo << 28 as libc::c_int ^ Ebo >> 64 as libc::c_int - 28 as libc::c_int;
        Egu ^= Du;
        BCe = Egu << 20 as libc::c_int ^ Egu >> 64 as libc::c_int - 20 as libc::c_int;
        Eka ^= Da;
        BCi = Eka << 3 as libc::c_int ^ Eka >> 64 as libc::c_int - 3 as libc::c_int;
        Eme ^= De;
        BCo = Eme << 45 as libc::c_int ^ Eme >> 64 as libc::c_int - 45 as libc::c_int;
        Esi ^= Di;
        BCu = Esi << 61 as libc::c_int ^ Esi >> 64 as libc::c_int - 61 as libc::c_int;
        Aga = BCa ^ !BCe & BCi;
        Age = BCe ^ !BCi & BCo;
        Agi = BCi ^ !BCo & BCu;
        Ago = BCo ^ !BCu & BCa;
        Agu = BCu ^ !BCa & BCe;
        Ebe ^= De;
        BCa = Ebe << 1 as libc::c_int ^ Ebe >> 64 as libc::c_int - 1 as libc::c_int;
        Egi ^= Di;
        BCe = Egi << 6 as libc::c_int ^ Egi >> 64 as libc::c_int - 6 as libc::c_int;
        Eko ^= Do;
        BCi = Eko << 25 as libc::c_int ^ Eko >> 64 as libc::c_int - 25 as libc::c_int;
        Emu ^= Du;
        BCo = Emu << 8 as libc::c_int ^ Emu >> 64 as libc::c_int - 8 as libc::c_int;
        Esa ^= Da;
        BCu = Esa << 18 as libc::c_int ^ Esa >> 64 as libc::c_int - 18 as libc::c_int;
        Aka = BCa ^ !BCe & BCi;
        Ake = BCe ^ !BCi & BCo;
        Aki = BCi ^ !BCo & BCu;
        Ako = BCo ^ !BCu & BCa;
        Aku = BCu ^ !BCa & BCe;
        Ebu ^= Du;
        BCa = Ebu << 27 as libc::c_int ^ Ebu >> 64 as libc::c_int - 27 as libc::c_int;
        Ega ^= Da;
        BCe = Ega << 36 as libc::c_int ^ Ega >> 64 as libc::c_int - 36 as libc::c_int;
        Eke ^= De;
        BCi = Eke << 10 as libc::c_int ^ Eke >> 64 as libc::c_int - 10 as libc::c_int;
        Emi ^= Di;
        BCo = Emi << 15 as libc::c_int ^ Emi >> 64 as libc::c_int - 15 as libc::c_int;
        Eso ^= Do;
        BCu = Eso << 56 as libc::c_int ^ Eso >> 64 as libc::c_int - 56 as libc::c_int;
        Ama = BCa ^ !BCe & BCi;
        Ame = BCe ^ !BCi & BCo;
        Ami = BCi ^ !BCo & BCu;
        Amo = BCo ^ !BCu & BCa;
        Amu = BCu ^ !BCa & BCe;
        Ebi ^= Di;
        BCa = Ebi << 62 as libc::c_int ^ Ebi >> 64 as libc::c_int - 62 as libc::c_int;
        Ego ^= Do;
        BCe = Ego << 55 as libc::c_int ^ Ego >> 64 as libc::c_int - 55 as libc::c_int;
        Eku ^= Du;
        BCi = Eku << 39 as libc::c_int ^ Eku >> 64 as libc::c_int - 39 as libc::c_int;
        Ema ^= Da;
        BCo = Ema << 41 as libc::c_int ^ Ema >> 64 as libc::c_int - 41 as libc::c_int;
        Ese ^= De;
        BCu = Ese << 2 as libc::c_int ^ Ese >> 64 as libc::c_int - 2 as libc::c_int;
        Asa = BCa ^ !BCe & BCi;
        Ase = BCe ^ !BCi & BCo;
        Asi = BCi ^ !BCo & BCu;
        Aso = BCo ^ !BCu & BCa;
        Asu = BCu ^ !BCa & BCe;
        round += 2 as libc::c_int;
    }
    *state.offset(0 as libc::c_int as isize) = Aba;
    *state.offset(1 as libc::c_int as isize) = Abe;
    *state.offset(2 as libc::c_int as isize) = Abi;
    *state.offset(3 as libc::c_int as isize) = Abo;
    *state.offset(4 as libc::c_int as isize) = Abu;
    *state.offset(5 as libc::c_int as isize) = Aga;
    *state.offset(6 as libc::c_int as isize) = Age;
    *state.offset(7 as libc::c_int as isize) = Agi;
    *state.offset(8 as libc::c_int as isize) = Ago;
    *state.offset(9 as libc::c_int as isize) = Agu;
    *state.offset(10 as libc::c_int as isize) = Aka;
    *state.offset(11 as libc::c_int as isize) = Ake;
    *state.offset(12 as libc::c_int as isize) = Aki;
    *state.offset(13 as libc::c_int as isize) = Ako;
    *state.offset(14 as libc::c_int as isize) = Aku;
    *state.offset(15 as libc::c_int as isize) = Ama;
    *state.offset(16 as libc::c_int as isize) = Ame;
    *state.offset(17 as libc::c_int as isize) = Ami;
    *state.offset(18 as libc::c_int as isize) = Amo;
    *state.offset(19 as libc::c_int as isize) = Amu;
    *state.offset(20 as libc::c_int as isize) = Asa;
    *state.offset(21 as libc::c_int as isize) = Ase;
    *state.offset(22 as libc::c_int as isize) = Asi;
    *state.offset(23 as libc::c_int as isize) = Aso;
    *state.offset(24 as libc::c_int as isize) = Asu;
}
unsafe extern "C" fn keccak_init(mut s: *mut uint64_t) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 25 as libc::c_int as libc::c_uint {
        *s.offset(i as isize) = 0 as libc::c_int as uint64_t;
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn keccak_absorb(
    mut s: *mut uint64_t,
    mut pos: libc::c_uint,
    mut r: libc::c_uint,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) -> libc::c_uint {
    let mut i: libc::c_uint = 0;
    while (pos as size_t).wrapping_add(inlen) >= r as size_t {
        i = pos;
        while i < r {
            let fresh0 = in_0;
            in_0 = in_0.offset(1);
            *s.offset(i.wrapping_div(8 as libc::c_int as libc::c_uint) as isize)
                ^= (*fresh0 as uint64_t)
                    << (8 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i.wrapping_rem(8 as libc::c_int as libc::c_uint));
            i = i.wrapping_add(1);
            i;
        }
        inlen = inlen.wrapping_sub(r.wrapping_sub(pos) as size_t);
        KeccakF1600_StatePermute(s);
        pos = 0 as libc::c_int as libc::c_uint;
    }
    i = pos;
    while (i as size_t) < (pos as size_t).wrapping_add(inlen) {
        let fresh1 = in_0;
        in_0 = in_0.offset(1);
        *s.offset(i.wrapping_div(8 as libc::c_int as libc::c_uint) as isize)
            ^= (*fresh1 as uint64_t)
                << (8 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i.wrapping_rem(8 as libc::c_int as libc::c_uint));
        i = i.wrapping_add(1);
        i;
    }
    return i;
}
unsafe extern "C" fn keccak_finalize(
    mut s: *mut uint64_t,
    mut pos: libc::c_uint,
    mut r: libc::c_uint,
    mut p: uint8_t,
) {
    *s.offset(pos.wrapping_div(8 as libc::c_int as libc::c_uint) as isize)
        ^= (p as uint64_t)
            << (8 as libc::c_int as libc::c_uint)
                .wrapping_mul(pos.wrapping_rem(8 as libc::c_int as libc::c_uint));
    let ref mut fresh2 = *s
        .offset(
            r
                .wrapping_div(8 as libc::c_int as libc::c_uint)
                .wrapping_sub(1 as libc::c_int as libc::c_uint) as isize,
        );
    *fresh2 = (*fresh2 as libc::c_ulonglong
        ^ (1 as libc::c_ulonglong) << 63 as libc::c_int) as uint64_t;
}
unsafe extern "C" fn keccak_squeeze(
    mut out: *mut uint8_t,
    mut outlen: size_t,
    mut s: *mut uint64_t,
    mut pos: libc::c_uint,
    mut r: libc::c_uint,
) -> libc::c_uint {
    let mut i: libc::c_uint = 0;
    while outlen != 0 {
        if pos == r {
            KeccakF1600_StatePermute(s);
            pos = 0 as libc::c_int as libc::c_uint;
        }
        i = pos;
        while i < r && (i as size_t) < (pos as size_t).wrapping_add(outlen) {
            let fresh3 = out;
            out = out.offset(1);
            *fresh3 = (*s
                .offset(i.wrapping_div(8 as libc::c_int as libc::c_uint) as isize)
                >> (8 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i.wrapping_rem(8 as libc::c_int as libc::c_uint)))
                as uint8_t;
            i = i.wrapping_add(1);
            i;
        }
        outlen = outlen.wrapping_sub(i.wrapping_sub(pos) as size_t);
        pos = i;
    }
    return pos;
}
unsafe extern "C" fn keccak_absorb_once(
    mut s: *mut uint64_t,
    mut r: libc::c_uint,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
    mut p: uint8_t,
) {
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 25 as libc::c_int as libc::c_uint {
        *s.offset(i as isize) = 0 as libc::c_int as uint64_t;
        i = i.wrapping_add(1);
        i;
    }
    while inlen >= r as size_t {
        i = 0 as libc::c_int as libc::c_uint;
        while i < r.wrapping_div(8 as libc::c_int as libc::c_uint) {
            *s.offset(i as isize)
                ^= load64(
                    in_0
                        .offset(
                            (8 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize,
                        ),
                );
            i = i.wrapping_add(1);
            i;
        }
        in_0 = in_0.offset(r as isize);
        inlen = inlen.wrapping_sub(r as size_t);
        KeccakF1600_StatePermute(s);
    }
    i = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < inlen {
        *s.offset(i.wrapping_div(8 as libc::c_int as libc::c_uint) as isize)
            ^= (*in_0.offset(i as isize) as uint64_t)
                << (8 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i.wrapping_rem(8 as libc::c_int as libc::c_uint));
        i = i.wrapping_add(1);
        i;
    }
    *s.offset(i.wrapping_div(8 as libc::c_int as libc::c_uint) as isize)
        ^= (p as uint64_t)
            << (8 as libc::c_int as libc::c_uint)
                .wrapping_mul(i.wrapping_rem(8 as libc::c_int as libc::c_uint));
    let ref mut fresh4 = *s
        .offset(
            r
                .wrapping_sub(1 as libc::c_int as libc::c_uint)
                .wrapping_div(8 as libc::c_int as libc::c_uint) as isize,
        );
    *fresh4 = (*fresh4 as libc::c_ulonglong
        ^ (1 as libc::c_ulonglong) << 63 as libc::c_int) as uint64_t;
}
unsafe extern "C" fn keccak_squeezeblocks(
    mut out: *mut uint8_t,
    mut nblocks: size_t,
    mut s: *mut uint64_t,
    mut r: libc::c_uint,
) {
    let mut i: libc::c_uint = 0;
    while nblocks != 0 {
        KeccakF1600_StatePermute(s);
        i = 0 as libc::c_int as libc::c_uint;
        while i < r.wrapping_div(8 as libc::c_int as libc::c_uint) {
            store64(
                out.offset((8 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
                *s.offset(i as isize),
            );
            i = i.wrapping_add(1);
            i;
        }
        out = out.offset(r as isize);
        nblocks = nblocks.wrapping_sub(1 as libc::c_int as size_t);
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake128_init(
    mut state: *mut keccak_state,
) {
    keccak_init(((*state).s).as_mut_ptr());
    (*state).pos = 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake128_absorb(
    mut state: *mut keccak_state,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) {
    (*state)
        .pos = keccak_absorb(
        ((*state).s).as_mut_ptr(),
        (*state).pos,
        168 as libc::c_int as libc::c_uint,
        in_0,
        inlen,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake128_finalize(
    mut state: *mut keccak_state,
) {
    keccak_finalize(
        ((*state).s).as_mut_ptr(),
        (*state).pos,
        168 as libc::c_int as libc::c_uint,
        0x1f as libc::c_int as uint8_t,
    );
    (*state).pos = 168 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake128_squeeze(
    mut out: *mut uint8_t,
    mut outlen: size_t,
    mut state: *mut keccak_state,
) {
    (*state)
        .pos = keccak_squeeze(
        out,
        outlen,
        ((*state).s).as_mut_ptr(),
        (*state).pos,
        168 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake128_absorb_once(
    mut state: *mut keccak_state,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) {
    keccak_absorb_once(
        ((*state).s).as_mut_ptr(),
        168 as libc::c_int as libc::c_uint,
        in_0,
        inlen,
        0x1f as libc::c_int as uint8_t,
    );
    (*state).pos = 168 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake128_squeezeblocks(
    mut out: *mut uint8_t,
    mut nblocks: size_t,
    mut state: *mut keccak_state,
) {
    keccak_squeezeblocks(
        out,
        nblocks,
        ((*state).s).as_mut_ptr(),
        168 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake256_init(
    mut state: *mut keccak_state,
) {
    keccak_init(((*state).s).as_mut_ptr());
    (*state).pos = 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake256_absorb(
    mut state: *mut keccak_state,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) {
    (*state)
        .pos = keccak_absorb(
        ((*state).s).as_mut_ptr(),
        (*state).pos,
        136 as libc::c_int as libc::c_uint,
        in_0,
        inlen,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake256_finalize(
    mut state: *mut keccak_state,
) {
    keccak_finalize(
        ((*state).s).as_mut_ptr(),
        (*state).pos,
        136 as libc::c_int as libc::c_uint,
        0x1f as libc::c_int as uint8_t,
    );
    (*state).pos = 136 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake256_squeeze(
    mut out: *mut uint8_t,
    mut outlen: size_t,
    mut state: *mut keccak_state,
) {
    (*state)
        .pos = keccak_squeeze(
        out,
        outlen,
        ((*state).s).as_mut_ptr(),
        (*state).pos,
        136 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake256_absorb_once(
    mut state: *mut keccak_state,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) {
    keccak_absorb_once(
        ((*state).s).as_mut_ptr(),
        136 as libc::c_int as libc::c_uint,
        in_0,
        inlen,
        0x1f as libc::c_int as uint8_t,
    );
    (*state).pos = 136 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake256_squeezeblocks(
    mut out: *mut uint8_t,
    mut nblocks: size_t,
    mut state: *mut keccak_state,
) {
    keccak_squeezeblocks(
        out,
        nblocks,
        ((*state).s).as_mut_ptr(),
        136 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake128(
    mut out: *mut uint8_t,
    mut outlen: size_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) {
    let mut nblocks: size_t = 0;
    let mut state: keccak_state = keccak_state { s: [0; 25], pos: 0 };
    pqcrystals_kyber_fips202_ref_shake128_absorb_once(&mut state, in_0, inlen);
    nblocks = outlen / 168 as libc::c_int as size_t;
    pqcrystals_kyber_fips202_ref_shake128_squeezeblocks(out, nblocks, &mut state);
    outlen = outlen.wrapping_sub(nblocks * 168 as libc::c_int as size_t);
    out = out.offset((nblocks * 168 as libc::c_int as size_t) as isize);
    pqcrystals_kyber_fips202_ref_shake128_squeeze(out, outlen, &mut state);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_shake256(
    mut out: *mut uint8_t,
    mut outlen: size_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) {
    let mut nblocks: size_t = 0;
    let mut state: keccak_state = keccak_state { s: [0; 25], pos: 0 };
    pqcrystals_kyber_fips202_ref_shake256_absorb_once(&mut state, in_0, inlen);
    nblocks = outlen / 136 as libc::c_int as size_t;
    pqcrystals_kyber_fips202_ref_shake256_squeezeblocks(out, nblocks, &mut state);
    outlen = outlen.wrapping_sub(nblocks * 136 as libc::c_int as size_t);
    out = out.offset((nblocks * 136 as libc::c_int as size_t) as isize);
    pqcrystals_kyber_fips202_ref_shake256_squeeze(out, outlen, &mut state);
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_sha3_256(
    mut h: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) {
    let mut i: libc::c_uint = 0;
    let mut s: [uint64_t; 25] = [0; 25];
    keccak_absorb_once(
        s.as_mut_ptr(),
        136 as libc::c_int as libc::c_uint,
        in_0,
        inlen,
        0x6 as libc::c_int as uint8_t,
    );
    KeccakF1600_StatePermute(s.as_mut_ptr());
    i = 0 as libc::c_int as libc::c_uint;
    while i < 4 as libc::c_int as libc::c_uint {
        store64(
            h.offset((8 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            s[i as usize],
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn pqcrystals_kyber_fips202_ref_sha3_512(
    mut h: *mut uint8_t,
    mut in_0: *const uint8_t,
    mut inlen: size_t,
) {
    let mut i: libc::c_uint = 0;
    let mut s: [uint64_t; 25] = [0; 25];
    keccak_absorb_once(
        s.as_mut_ptr(),
        72 as libc::c_int as libc::c_uint,
        in_0,
        inlen,
        0x6 as libc::c_int as uint8_t,
    );
    KeccakF1600_StatePermute(s.as_mut_ptr());
    i = 0 as libc::c_int as libc::c_uint;
    while i < 8 as libc::c_int as libc::c_uint {
        store64(
            h.offset((8 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            s[i as usize],
        );
        i = i.wrapping_add(1);
        i;
    }
}
