//! `struct_ops` programs.

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_STRUCT_OPS;

use crate::programs::{
    FdLink, FdLinkId, ProgramData, ProgramError, ProgramType, define_link_wrapper,
    load_program_without_attach_type,
};

/// A program that implements one member of a kernel `struct_ops` type.
///
/// [`StructOps`] programs are not attached one by one. They are the function
/// pointer members of a `struct_ops` instance, and the instance as a whole is
/// loaded and attached through [`Ebpf::struct_ops_mut`](crate::Ebpf::struct_ops_mut).
///
/// The kernel struct and the member a program is loaded for are taken from
/// the instances in the object file that refer to it.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.6.
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_STRUCT_OPS")]
pub struct StructOps {
    pub(crate) data: ProgramData<StructOpsLink>,
}

impl StructOps {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::StructOps;

    /// Loads the program inside the kernel.
    ///
    /// [`maps::StructOps::load`](crate::maps::StructOps::load) calls this for
    /// every program of an instance.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program_without_attach_type(BPF_PROG_TYPE_STRUCT_OPS, &mut self.data)
    }
}

define_link_wrapper!(StructOpsLink, StructOpsLinkId, FdLink, FdLinkId, StructOps,);
