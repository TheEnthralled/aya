#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, struct_ops},
    maps::Array,
};
#[cfg(not(test))]
extern crate ebpf_panic;

/// The kernel's `struct sock`. The programs below do not look inside it.
#[repr(C)]
pub struct sock {
    _private: [u8; 0],
}

/// The members of the kernel's `struct tcp_congestion_ops` that the
/// instances below set. The kernel's `name` is a `char` array; any array of
/// 16 one-byte integers has its layout.
#[repr(C)]
pub struct tcp_congestion_ops {
    pub init: Option<unsafe extern "C" fn(*mut sock)>,
    pub ssthresh: Option<unsafe extern "C" fn(*mut sock) -> u32>,
    pub cong_avoid: Option<unsafe extern "C" fn(*mut sock, u32, u32)>,
    pub undo_cwnd: Option<unsafe extern "C" fn(*mut sock) -> u32>,
    pub name: [u8; 16],
}

const fn algorithm_name(name: &[u8]) -> [u8; 16] {
    let mut out = [0; 16];
    let mut i = 0;
    while i < name.len() {
        out[i] = name[i];
        i += 1;
    }
    out
}

/// The number of sockets that switched to one of the algorithms below.
#[map(name = "init_calls")]
static INIT_CALLS: Array<u64> = Array::with_max_entries(1, 0);

fn count_init() {
    if let Some(calls) = INIT_CALLS.get_ptr_mut(0) {
        unsafe {
            *calls += 1;
        }
    }
}

/// A congestion control algorithm that the kernel registers when the map's
/// value is written.
pub struct AyaMacroPlain;

#[struct_ops(plain)]
impl tcp_congestion_ops for AyaMacroPlain {
    const name: [u8; 16] = algorithm_name(b"aya_macro_plain");

    fn init(_sk: *mut sock) {
        count_init();
    }

    fn ssthresh(_sk: *mut sock) -> u32 {
        16
    }

    fn cong_avoid(_sk: *mut sock, _ack: u32, _acked: u32) {}

    fn undo_cwnd(_sk: *mut sock) -> u32 {
        16
    }
}

/// The same algorithm, registered through a link. Kernels before 6.4 cannot
/// create it, so it is only created on request.
pub struct AyaMacroLink;

#[struct_ops(optional, name = "macro_link")]
impl tcp_congestion_ops for AyaMacroLink {
    const name: [u8; 16] = algorithm_name(b"aya_macro_link");

    fn init(_sk: *mut sock) {
        count_init();
    }

    fn ssthresh(_sk: *mut sock) -> u32 {
        16
    }

    fn cong_avoid(_sk: *mut sock, _ack: u32, _acked: u32) {}

    fn undo_cwnd(_sk: *mut sock) -> u32 {
        16
    }
}
