//! Program struct and type bindings.

pub mod cgroup_skb;
pub mod cgroup_sock;
pub mod cgroup_sock_addr;
pub mod cgroup_sockopt;
pub mod sk_reuseport;
pub mod sk_skb;
mod types;
pub mod xdp;

pub use cgroup_skb::CgroupSkbAttachType;
pub use cgroup_sock::CgroupSockAttachType;
pub use cgroup_sock_addr::CgroupSockAddrAttachType;
pub use cgroup_sockopt::CgroupSockoptAttachType;
pub use sk_reuseport::SkReuseportAttachType;
pub use sk_skb::SkSkbKind;
pub use xdp::XdpAttachType;

/// The struct type and function pointer member a `struct_ops` program implements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructOpsAttachment {
    /// Index of the struct type into the type table located in .BTF.
    pub type_id: u32,
    /// Name of the function pointer member.
    pub member_name: String,
    /// Where the program attaches in the kernel. `None` until the `struct_ops`
    /// instances are resolved against the kernel's BTF.
    pub attach_target: Option<StructOpsAttachTarget>,
}

/// The kernel struct type and member a `struct_ops` program is loaded for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructOpsAttachTarget {
    /// Kernel BTF id of the struct type, passed as the program's
    /// `attach_btf_id`.
    pub kernel_type_id: u32,
    /// Index of the member in the kernel struct, passed as the program's
    /// `expected_attach_type`.
    pub member_index: u32,
}
