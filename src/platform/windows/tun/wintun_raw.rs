#![expect(
    unsafe_code,
    reason = "generated Wintun bindings mirror the C ABI and are isolated behind this include wrapper"
)]
#![expect(
    unsafe_op_in_unsafe_fn,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::ptr_offset_with_cast,
    clippy::upper_case_acronyms,
    clippy::useless_transmute,
    clippy::unnecessary_cast,
    reason = "generated Wintun bindings preserve the upstream C ABI and are regenerated rather than hand-edited"
)]
#[cfg(all(not(docsrs), feature = "bindgen"))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(any(docsrs, not(feature = "bindgen")))]
#[cfg(target_pointer_width = "64")]
include!("bindings_x86_64.rs");

#[cfg(any(docsrs, not(feature = "bindgen")))]
#[cfg(target_pointer_width = "32")]
include!("bindings_i686.rs");
