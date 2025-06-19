#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ASN1_tag2str(mut tag: libc::c_int) -> *const libc::c_char {
    static mut tag2str: [*const libc::c_char; 31] = [
        b"EOC\0" as *const u8 as *const libc::c_char,
        b"BOOLEAN\0" as *const u8 as *const libc::c_char,
        b"INTEGER\0" as *const u8 as *const libc::c_char,
        b"BIT STRING\0" as *const u8 as *const libc::c_char,
        b"OCTET STRING\0" as *const u8 as *const libc::c_char,
        b"NULL\0" as *const u8 as *const libc::c_char,
        b"OBJECT\0" as *const u8 as *const libc::c_char,
        b"OBJECT DESCRIPTOR\0" as *const u8 as *const libc::c_char,
        b"EXTERNAL\0" as *const u8 as *const libc::c_char,
        b"REAL\0" as *const u8 as *const libc::c_char,
        b"ENUMERATED\0" as *const u8 as *const libc::c_char,
        b"<ASN1 11>\0" as *const u8 as *const libc::c_char,
        b"UTF8STRING\0" as *const u8 as *const libc::c_char,
        b"<ASN1 13>\0" as *const u8 as *const libc::c_char,
        b"<ASN1 14>\0" as *const u8 as *const libc::c_char,
        b"<ASN1 15>\0" as *const u8 as *const libc::c_char,
        b"SEQUENCE\0" as *const u8 as *const libc::c_char,
        b"SET\0" as *const u8 as *const libc::c_char,
        b"NUMERICSTRING\0" as *const u8 as *const libc::c_char,
        b"PRINTABLESTRING\0" as *const u8 as *const libc::c_char,
        b"T61STRING\0" as *const u8 as *const libc::c_char,
        b"VIDEOTEXSTRING\0" as *const u8 as *const libc::c_char,
        b"IA5STRING\0" as *const u8 as *const libc::c_char,
        b"UTCTIME\0" as *const u8 as *const libc::c_char,
        b"GENERALIZEDTIME\0" as *const u8 as *const libc::c_char,
        b"GRAPHICSTRING\0" as *const u8 as *const libc::c_char,
        b"VISIBLESTRING\0" as *const u8 as *const libc::c_char,
        b"GENERALSTRING\0" as *const u8 as *const libc::c_char,
        b"UNIVERSALSTRING\0" as *const u8 as *const libc::c_char,
        b"<ASN1 29>\0" as *const u8 as *const libc::c_char,
        b"BMPSTRING\0" as *const u8 as *const libc::c_char,
    ];
    if tag == 2 as libc::c_int | 0x100 as libc::c_int
        || tag == 10 as libc::c_int | 0x100 as libc::c_int
    {
        tag &= !(0x100 as libc::c_int);
    }
    if tag < 0 as libc::c_int || tag > 30 as libc::c_int {
        return b"(unknown)\0" as *const u8 as *const libc::c_char;
    }
    return tag2str[tag as usize];
}
