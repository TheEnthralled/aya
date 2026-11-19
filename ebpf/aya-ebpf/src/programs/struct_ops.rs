use core::ffi::c_void;

use crate::{Argument, EbpfContext, args::btf_arg};

/// The context of a `struct_ops` program: the arguments the kernel passes to
/// the struct member the program implements.
pub struct StructOpsContext {
    ctx: *mut c_void,
}

impl StructOpsContext {
    pub const fn new(ctx: *mut c_void) -> Self {
        Self { ctx }
    }

    /// Returns the `n`th argument of the struct member the program
    /// implements, starting from 0.
    ///
    /// The [`struct_ops`](crate::macros::struct_ops) macro calls this for
    /// every argument, so programs written with it do not need to.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use aya_ebpf::programs::StructOpsContext;
    /// # #[expect(non_camel_case_types)]
    /// # struct sock {
    /// #     sk_pacing_rate: u64,
    /// # }
    /// unsafe fn cong_avoid(ctx: StructOpsContext) {
    ///     let sk: *const sock = ctx.arg(0);
    ///     let ack: u32 = ctx.arg(1);
    ///
    ///     // Do something with sk and ack
    /// }
    /// ```
    pub fn arg<T: Argument>(&self, n: usize) -> T {
        btf_arg(self, n)
    }
}

impl EbpfContext for StructOpsContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx
    }
}
