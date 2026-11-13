//! Map struct and type bindings.

use crate::{
    EbpfSectionKind, InvalidTypeBinding,
    btf::{BtfError, BtfKind},
    generated::bpf_map_type,
    programs::StructOpsAttachTarget,
};

impl TryFrom<u32> for bpf_map_type {
    type Error = InvalidTypeBinding<u32>;

    fn try_from(map_type: u32) -> Result<Self, Self::Error> {
        Ok(match map_type {
            x if x == Self::BPF_MAP_TYPE_UNSPEC as u32 => Self::BPF_MAP_TYPE_UNSPEC,
            x if x == Self::BPF_MAP_TYPE_HASH as u32 => Self::BPF_MAP_TYPE_HASH,
            x if x == Self::BPF_MAP_TYPE_ARRAY as u32 => Self::BPF_MAP_TYPE_ARRAY,
            x if x == Self::BPF_MAP_TYPE_PROG_ARRAY as u32 => Self::BPF_MAP_TYPE_PROG_ARRAY,
            x if x == Self::BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 => {
                Self::BPF_MAP_TYPE_PERF_EVENT_ARRAY
            }
            x if x == Self::BPF_MAP_TYPE_PERCPU_HASH as u32 => Self::BPF_MAP_TYPE_PERCPU_HASH,
            x if x == Self::BPF_MAP_TYPE_PERCPU_ARRAY as u32 => Self::BPF_MAP_TYPE_PERCPU_ARRAY,
            x if x == Self::BPF_MAP_TYPE_STACK_TRACE as u32 => Self::BPF_MAP_TYPE_STACK_TRACE,
            x if x == Self::BPF_MAP_TYPE_CGROUP_ARRAY as u32 => Self::BPF_MAP_TYPE_CGROUP_ARRAY,
            x if x == Self::BPF_MAP_TYPE_LRU_HASH as u32 => Self::BPF_MAP_TYPE_LRU_HASH,
            x if x == Self::BPF_MAP_TYPE_LRU_PERCPU_HASH as u32 => {
                Self::BPF_MAP_TYPE_LRU_PERCPU_HASH
            }
            x if x == Self::BPF_MAP_TYPE_LPM_TRIE as u32 => Self::BPF_MAP_TYPE_LPM_TRIE,
            x if x == Self::BPF_MAP_TYPE_ARRAY_OF_MAPS as u32 => Self::BPF_MAP_TYPE_ARRAY_OF_MAPS,
            x if x == Self::BPF_MAP_TYPE_HASH_OF_MAPS as u32 => Self::BPF_MAP_TYPE_HASH_OF_MAPS,
            x if x == Self::BPF_MAP_TYPE_DEVMAP as u32 => Self::BPF_MAP_TYPE_DEVMAP,
            x if x == Self::BPF_MAP_TYPE_SOCKMAP as u32 => Self::BPF_MAP_TYPE_SOCKMAP,
            x if x == Self::BPF_MAP_TYPE_CPUMAP as u32 => Self::BPF_MAP_TYPE_CPUMAP,
            x if x == Self::BPF_MAP_TYPE_XSKMAP as u32 => Self::BPF_MAP_TYPE_XSKMAP,
            x if x == Self::BPF_MAP_TYPE_SOCKHASH as u32 => Self::BPF_MAP_TYPE_SOCKHASH,
            x if x == Self::BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED as u32 => {
                Self::BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED
            }
            x if x == Self::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY as u32 => {
                Self::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
            }
            x if x == Self::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED as u32 => {
                Self::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED
            }
            x if x == Self::BPF_MAP_TYPE_QUEUE as u32 => Self::BPF_MAP_TYPE_QUEUE,
            x if x == Self::BPF_MAP_TYPE_STACK as u32 => Self::BPF_MAP_TYPE_STACK,
            x if x == Self::BPF_MAP_TYPE_SK_STORAGE as u32 => Self::BPF_MAP_TYPE_SK_STORAGE,
            x if x == Self::BPF_MAP_TYPE_DEVMAP_HASH as u32 => Self::BPF_MAP_TYPE_DEVMAP_HASH,
            x if x == Self::BPF_MAP_TYPE_STRUCT_OPS as u32 => Self::BPF_MAP_TYPE_STRUCT_OPS,
            x if x == Self::BPF_MAP_TYPE_RINGBUF as u32 => Self::BPF_MAP_TYPE_RINGBUF,
            x if x == Self::BPF_MAP_TYPE_INODE_STORAGE as u32 => Self::BPF_MAP_TYPE_INODE_STORAGE,
            x if x == Self::BPF_MAP_TYPE_TASK_STORAGE as u32 => Self::BPF_MAP_TYPE_TASK_STORAGE,
            x if x == Self::BPF_MAP_TYPE_BLOOM_FILTER as u32 => Self::BPF_MAP_TYPE_BLOOM_FILTER,
            x if x == Self::BPF_MAP_TYPE_USER_RINGBUF as u32 => Self::BPF_MAP_TYPE_USER_RINGBUF,
            x if x == Self::BPF_MAP_TYPE_CGRP_STORAGE as u32 => Self::BPF_MAP_TYPE_CGRP_STORAGE,
            x if x == Self::BPF_MAP_TYPE_ARENA as u32 => Self::BPF_MAP_TYPE_ARENA,
            x if x == Self::BPF_MAP_TYPE_INSN_ARRAY as u32 => Self::BPF_MAP_TYPE_INSN_ARRAY,
            _ => return Err(InvalidTypeBinding { value: map_type }),
        })
    }
}

/// BTF definition of a map
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BtfMapDef {
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
    pub(crate) map_extra: u64,
    pub(crate) pinning: PinningType,
    /// BTF type id of the map key
    pub btf_key_type_id: u32,
    /// BTF type id of the map value
    pub btf_value_type_id: u32,
}

/// The pinning type
///
/// Upon pinning a map, a file representation is created for the map,
/// so that the map can be alive and retrievable across sessions.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum PinningType {
    /// No pinning
    #[default]
    None = 0,
    /// Pin by the name
    ByName = 1,
}

/// The error type returned when failing to parse a [`PinningType`].
#[derive(Debug, thiserror::Error)]
pub enum PinningError {
    /// Unsupported pinning type
    #[error("unsupported pinning type `{pinning_type}`")]
    Unsupported {
        /// The unsupported pinning type
        pinning_type: u32,
    },
}

impl TryFrom<u32> for PinningType {
    type Error = PinningError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ByName),
            pinning_type => Err(PinningError::Unsupported { pinning_type }),
        }
    }
}

/// Map definition in legacy BPF map declaration style
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct bpf_map_def {
    // minimum features required by old BPF programs
    /// The map type
    pub map_type: u32,
    /// The key size
    pub key_size: u32,
    /// The value size
    pub value_size: u32,
    /// Max entry number
    pub max_entries: u32,
    /// Map flags
    pub map_flags: u32,
    // optional features
    /// Id
    pub id: u32,
    /// Pinning type
    pub pinning: PinningType,
}

/// The first five __u32 of `bpf_map_def` must be defined.
pub(crate) const MINIMUM_MAP_SIZE: usize = size_of::<u32>() * 5;

/// A struct_ops instance as found in the object file, before it is resolved
/// against the kernel's BTF.
#[derive(Clone, Debug)]
pub struct StructOpsInfo {
    /// Index into the type table located in .BTF.
    /// Gives us the struct's name to match in vmlinux BTF through btf.type_name(btf.type_by_id(type_id)?).
    /// and STRUCT member metadata (which members are function pointers, offsets).
    pub type_id: u32,
    /// Struct type name ex.: Qdisc_ops
    pub struct_name: String,
    /// Whether it is placed under .struct_ops or .struct_ops.link
    pub is_link: bool,
    /// Whether the section name starts with `?`.
    pub is_optional: bool,
    /// The instance's bytes from the section. Function pointer members are
    /// filled in by relocations, so they are zero here.
    pub data: Vec<u8>,
    /// Index of the ELF section holding the instance.
    pub section_index: usize,
    /// Index of the instance's symbol in the symbol table.
    pub symbol_index: usize,
    /// Struct members who are function pointers. Not all of these members point to functions in
    /// struct_ops program sections.
    pub func_ptrs: Vec<StructOpsFnPtrMember>,
}

/// A struct_ops struct member which is a function pointer.
#[derive(Clone, Debug)]
pub struct StructOpsFnPtrMember {
    /// Member name.
    pub name: String,
    /// raw bit offset from the start of the enclosing struct.
    pub bit_offset: usize,
    /// Name of the struct_ops program the member points to, if any.
    pub program: Option<String>,
}

/// A struct_ops instance resolved against the kernel's BTF, ready to be
/// created as a `BPF_MAP_TYPE_STRUCT_OPS` map.
#[derive(Clone, Debug)]
pub struct StructOpsMap {
    /// map_type STRUCT_OPS, key_size 4, max_entries 1, map_flags BPF_F_LINK
    /// for .struct_ops.link, value_size = size of the kernel's
    /// `bpf_struct_ops_<struct_name>`. Both BTF type ids are 0.
    pub def: BtfMapDef,
    pub(crate) section_index: usize,
    pub(crate) symbol_index: usize,
    /// Kernel BTF id of `bpf_struct_ops_<struct_name>`, passed as
    /// `btf_vmlinux_value_type_id` when the map is created.
    pub btf_vmlinux_value_type_id: u32,
    /// The map value in kernel layout, `def.value_size` bytes long. Scalar
    /// members are already copied in; function pointer slots are zero until
    /// the loader writes the program fds.
    pub data: Vec<u8>,
    /// Function pointer members that a program implements.
    pub programs: Vec<StructOpsProgramSlot>,
    /// Struct type name, e.g. `Qdisc_ops`.
    pub struct_name: String,
    /// Whether it is placed under .struct_ops or .struct_ops.link
    pub is_link: bool,
    /// Whether the section name starts with `?`.
    pub is_optional: bool,
}

/// Where one program's fd goes in a struct_ops map value.
#[derive(Clone, Debug)]
pub struct StructOpsProgramSlot {
    /// Member name, e.g. `enqueue`.
    pub member_name: String,
    /// Name of the program implementing the member.
    pub program: String,
    /// Byte offset of the member from the start of the map value. This
    /// already includes the offset of the wrapper's `data` member.
    pub value_offset: usize,
}

/// Errors raised while resolving struct_ops instances against the kernel's BTF.
#[derive(Debug, thiserror::Error)]
pub enum StructOpsError {
    /// The object defines struct_ops instances but carries no BTF.
    #[error("the object has struct_ops instances but no BTF")]
    NoBtf,

    /// Error reading the object's or the kernel's BTF.
    #[error("BTF error")]
    BtfError(#[from] BtfError),

    /// The kernel's BTF has no struct with this name. For the
    /// `bpf_struct_ops_` wrapper this means the kernel does not support the
    /// struct_ops type.
    #[error("struct_ops `{name}`: struct `{type_name}` not found in kernel BTF")]
    KernelTypeNotFound {
        /// The struct_ops instance.
        name: String,
        /// The struct that was looked up.
        type_name: String,
    },

    /// The kernel's wrapper struct has no member holding the struct_ops type.
    #[error(
        "struct_ops `{name}`: kernel struct `{wrapper_name}` has no member of type `{struct_name}`"
    )]
    WrapperDataMemberNotFound {
        /// The struct_ops instance.
        name: String,
        /// The kernel's wrapper struct.
        wrapper_name: String,
        /// The struct_ops type.
        struct_name: String,
    },

    /// The instance sets a member the kernel's struct does not have.
    #[error(
        "struct_ops `{name}`: member `{member}` is set but the kernel's `{struct_name}` has no such member"
    )]
    MemberNotFound {
        /// The struct_ops instance.
        name: String,
        /// The struct_ops type.
        struct_name: String,
        /// The member.
        member: String,
    },

    /// Bitfield members cannot be translated to the kernel's layout.
    #[error("struct_ops `{name}`: member `{member}` is a bitfield, which is not supported")]
    BitfieldMember {
        /// The struct_ops instance.
        name: String,
        /// The member.
        member: String,
    },

    /// The member's type is of a different kind in the object and the kernel.
    #[error(
        "struct_ops `{name}`: member `{member}` has kind {kind:?} but the kernel's has kind {kernel_kind:?}"
    )]
    MemberKindMismatch {
        /// The struct_ops instance.
        name: String,
        /// The member.
        member: String,
        /// Kind of the member's type in the object.
        kind: BtfKind,
        /// Kind of the member's type in the kernel.
        kernel_kind: BtfKind,
    },

    /// The member's type has a different size in the object and the kernel.
    #[error(
        "struct_ops `{name}`: member `{member}` is {size} bytes but the kernel's is {kernel_size} bytes"
    )]
    MemberSizeMismatch {
        /// The struct_ops instance.
        name: String,
        /// The member.
        member: String,
        /// Size of the member in the object.
        size: usize,
        /// Size of the member in the kernel.
        kernel_size: usize,
    },

    /// The member does not fit in the instance's bytes or in the map value.
    #[error(
        "struct_ops `{name}`: member `{member}` at offset {offset} with size {size} does not fit in {len} bytes"
    )]
    MemberOutOfBounds {
        /// The struct_ops instance.
        name: String,
        /// The member.
        member: String,
        /// Byte offset of the member.
        offset: usize,
        /// Size of the member in bytes.
        size: usize,
        /// Number of bytes available.
        len: usize,
    },

    /// A program implements a member that is not a function pointer in the
    /// kernel's struct.
    #[error("struct_ops `{name}`: kernel member `{member}` is not a function pointer")]
    NotAFunctionPointer {
        /// The struct_ops instance.
        name: String,
        /// The member.
        member: String,
    },

    /// A program backs two different kernel struct types or members.
    #[error(
        "struct_ops program `{program}` is used as {attach_target:?} and as {other_attach_target:?}"
    )]
    ProgramReuse {
        /// The program.
        program: String,
        /// The kernel struct type and member being assigned.
        attach_target: StructOpsAttachTarget,
        /// The kernel struct type and member assigned earlier.
        other_attach_target: StructOpsAttachTarget,
    },
}

/// Map data defined in `maps` or `.maps` sections
#[derive(Debug, Clone)]
pub enum Map {
    /// A map defined in the `maps` section
    Legacy(LegacyMap),
    /// A map defined in the `.maps` section
    Btf(BtfMap),
    /// struct_ops instance that will be loaded as a map.
    StructOps(StructOpsMap),
}

impl Map {
    /// Returns the map type
    pub const fn map_type(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.map_type,
            Self::Btf(m) => m.def.map_type,
            Self::StructOps(m) => m.def.map_type,
        }
    }

    /// Returns the key size in bytes
    pub const fn key_size(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.key_size,
            Self::Btf(m) => m.def.key_size,
            Self::StructOps(m) => m.def.key_size,
        }
    }

    /// Returns the value size in bytes
    pub const fn value_size(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.value_size,
            Self::Btf(m) => m.def.value_size,
            Self::StructOps(m) => m.def.value_size,
        }
    }

    /// Set the value size in bytes
    pub const fn set_value_size(&mut self, size: u32) {
        match self {
            Self::Legacy(m) => m.def.value_size = size,
            Self::Btf(m) => m.def.value_size = size,
            Self::StructOps(m) => m.def.value_size = size,
        }
    }

    /// Returns the max entry number
    pub const fn max_entries(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.max_entries,
            Self::Btf(m) => m.def.max_entries,
            Self::StructOps(m) => m.def.max_entries,
        }
    }

    /// Sets the max entry number
    pub const fn set_max_entries(&mut self, v: u32) {
        match self {
            Self::Legacy(m) => m.def.max_entries = v,
            Self::Btf(m) => m.def.max_entries = v,
            Self::StructOps(m) => m.def.max_entries = v,
        }
    }

    /// Returns the map flags
    pub const fn map_flags(&self) -> u32 {
        match self {
            Self::Legacy(m) => m.def.map_flags,
            Self::Btf(m) => m.def.map_flags,
            Self::StructOps(m) => m.def.map_flags,
        }
    }

    /// Returns per-map-type extra fields.
    pub const fn map_extra(&self) -> u64 {
        match self {
            Self::Legacy(_) => 0,
            Self::Btf(m) => m.def.map_extra,
            Self::StructOps(m) => m.def.map_extra,
        }
    }

    /// Returns the pinning type of the map
    pub const fn pinning(&self) -> PinningType {
        match self {
            Self::Legacy(m) => m.def.pinning,
            Self::Btf(m) => m.def.pinning,
            Self::StructOps(m) => m.def.pinning,
        }
    }

    /// Returns the map data
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Legacy(m) => &m.data,
            Self::Btf(m) => &m.data,
            Self::StructOps(m) => &m.data,
        }
    }

    /// Returns the map data as mutable
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Legacy(m) => m.data.as_mut(),
            Self::Btf(m) => m.data.as_mut(),
            Self::StructOps(m) => m.data.as_mut(),
        }
    }

    /// Returns the section index
    pub const fn section_index(&self) -> usize {
        match self {
            Self::Legacy(m) => m.section_index,
            Self::Btf(m) => m.section_index,
            Self::StructOps(m) => m.section_index,
        }
    }

    /// Returns the section kind.
    pub const fn section_kind(&self) -> EbpfSectionKind {
        match self {
            Self::Legacy(m) => m.section_kind,
            Self::Btf(_) => EbpfSectionKind::BtfMaps,
            Self::StructOps(_) => EbpfSectionKind::StructOps,
        }
    }

    /// Returns the symbol index.
    ///
    /// This is `None` for data maps (.bss, .data and .rodata) since those don't
    /// need symbols in order to be relocated.
    pub const fn symbol_index(&self) -> Option<usize> {
        match self {
            Self::Legacy(m) => m.symbol_index,
            Self::Btf(m) => Some(m.symbol_index),
            Self::StructOps(m) => Some(m.symbol_index),
        }
    }

    /// Returns the inner map definition, in case of a map of maps.
    ///
    /// The inner map is a synthetic object with no ELF presence of its own,
    /// so neutral metadata values are used.
    pub fn inner(&self) -> Option<Self> {
        match self {
            Self::Legacy(m) => m.inner_def.as_ref().map(|inner_def| {
                Self::Legacy(LegacyMap {
                    def: *inner_def,
                    inner_def: None,
                    section_index: 0,
                    section_kind: EbpfSectionKind::Undefined,
                    symbol_index: None,
                    data: Vec::new(),
                })
            }),
            Self::Btf(m) => m.inner_def.as_ref().map(|inner_def| {
                Self::Btf(BtfMap {
                    def: *inner_def,
                    inner_def: None,
                    section_index: 0,
                    symbol_index: 0,
                    data: Vec::new(),
                })
            }),
            // BTF maps representing struct_ops instances
            // have only 1 key whose value is not another BTF map.
            Self::StructOps(_) => None,
        }
    }

    /// Creates a new map definition from raw parameters.
    pub const fn new_from_params(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        flags: u32,
    ) -> Self {
        Self::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type,
                key_size,
                value_size,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None,
            },
            inner_def: None,
            section_index: 0,
            section_kind: EbpfSectionKind::Undefined,
            symbol_index: None,
            data: Vec::new(),
        })
    }
}

/// A map declared with legacy BPF map declaration style, most likely from a `maps` section.
///
/// See [Drop support for legacy BPF map declaration syntax - Libbpf: the road to v1.0](https://github.com/libbpf/libbpf/wiki/Libbpf:-the-road-to-v1.0#drop-support-for-legacy-bpf-map-declaration-syntax)
/// for more info.
#[derive(Debug, Clone)]
pub struct LegacyMap {
    /// The definition of the map
    pub def: bpf_map_def,
    /// The definition of the inner map, in case of a map of maps.
    pub inner_def: Option<bpf_map_def>,
    /// The section index
    pub section_index: usize,
    /// The section kind
    pub section_kind: EbpfSectionKind,
    /// The symbol index.
    ///
    /// This is None for data maps (.bss .data and .rodata).  We don't need
    /// symbols to relocate those since they don't contain multiple maps, but
    /// are just a flat array of bytes.
    pub symbol_index: Option<usize>,
    /// The map data
    pub data: Vec<u8>,
}

/// A BTF-defined map, most likely from a `.maps` section.
#[derive(Debug, Clone)]
pub struct BtfMap {
    /// The definition of the map
    pub def: BtfMapDef,
    /// The definition of the inner map, in case of a map of maps.
    pub(crate) inner_def: Option<BtfMapDef>,
    pub(crate) section_index: usize,
    pub(crate) symbol_index: usize,
    pub(crate) data: Vec<u8>,
}
