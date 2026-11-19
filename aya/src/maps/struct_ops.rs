//! `struct_ops` instances.

use std::{
    collections::HashMap,
    os::fd::{AsFd as _, AsRawFd as _},
};

use aya_obj::{generated::bpf_attach_type::BPF_STRUCT_OPS, maps::StructOpsMap};

use crate::{
    maps::{MapData, MapFd},
    programs::{Program, ProgramError, links::FdLink},
    sys::{
        LinkTarget, SyscallError, bpf_link_create, bpf_map_delete_elem, bpf_map_update_elem_ptr,
    },
};

/// The key of the single element of a `struct_ops` map.
const KEY: u32 = 0;

/// Errors from operations on a [`StructOps`] instance.
#[derive(Debug, thiserror::Error)]
pub enum StructOpsError {
    /// A member of the instance points at a program the object does not have.
    #[error("struct_ops program `{program}` not found")]
    ProgramNotFound {
        /// The program's name.
        program: String,
    },

    /// A member of the instance points at a program of another type.
    #[error("`{program}` is not a struct_ops program")]
    UnexpectedProgramType {
        /// The program's name.
        program: String,
    },

    /// Loading or using one of the instance's programs failed.
    #[error(transparent)]
    ProgramError(#[from] ProgramError),

    /// A syscall failed.
    #[error(transparent)]
    SyscallError(#[from] SyscallError),

    /// The instance is already attached.
    #[error("the struct_ops instance is already attached")]
    AlreadyAttached,

    /// The instance is not attached.
    #[error("the struct_ops instance is not attached")]
    NotAttached,

    /// The kernel fixes an instance's value when it is first attached.
    #[error("members cannot be set once the struct_ops instance has been attached")]
    ValueAlreadyWritten,

    /// The kernel's struct has no such member, or it is a function pointer.
    #[error("struct `{struct_name}` has no member `{member}` that can be set")]
    InvalidMember {
        /// The `struct_ops` type.
        struct_name: String,
        /// The member's name.
        member: String,
    },

    /// The value is larger than the member.
    #[error("{len} bytes do not fit in member `{member}`, which is {size} bytes")]
    ValueTooLarge {
        /// The member's name.
        member: String,
        /// Length of the value.
        len: usize,
        /// Size of the member.
        size: usize,
    },
}

/// A `struct_ops` map and its registration with the kernel.
#[derive(Debug)]
pub(crate) struct StructOpsInstance {
    obj: StructOpsMap,
    fd: MapFd,
    /// Whether the map's element has been written. The kernel accepts that
    /// once, and for an instance without a link it is what registers it.
    value_written: bool,
    /// The link registering an instance from `.struct_ops.link`.
    link: Option<FdLink>,
}

impl StructOpsInstance {
    /// Takes a created map if it is a `struct_ops` map, and hands it back if
    /// it is not.
    #[expect(
        clippy::result_large_err,
        reason = "the Err variant is the map handed back, not an error"
    )]
    pub(crate) fn try_new(data: MapData) -> Result<Self, MapData> {
        match data {
            MapData {
                obj: aya_obj::Map::StructOps(obj),
                fd,
            } => Ok(Self {
                obj,
                fd,
                value_written: false,
                link: None,
            }),
            data => Err(data),
        }
    }

    const fn is_attached(&self) -> bool {
        if self.obj.is_link {
            self.link.is_some()
        } else {
            self.value_written
        }
    }

    /// Unregisters an instance that has no link.
    fn delete_element(&mut self) -> Result<(), SyscallError> {
        bpf_map_delete_elem(self.fd.as_fd(), &KEY).map_err(|io_error| SyscallError {
            call: "bpf_map_delete_elem",
            io_error,
        })?;
        self.value_written = false;
        Ok(())
    }
}

impl Drop for StructOpsInstance {
    fn drop(&mut self) {
        // A link unregisters its instance when it is closed. Without a link
        // the kernel keeps the instance registered until the element is
        // deleted, even after every file descriptor is gone.
        if !self.obj.is_link && self.value_written {
            drop(self.delete_element());
        }
    }
}

/// A `struct_ops` instance: a kernel struct whose function pointer members are
/// implemented by eBPF programs.
///
/// Attaching an instance registers it with the kernel subsystem that owns
/// its struct type. A `tcp_congestion_ops` instance, for example, becomes a
/// congestion control algorithm that sockets can select by its `name`.
///
/// Instances come from the `.struct_ops` and `.struct_ops.link` sections of
/// the object file. One from `.struct_ops.link` is attached through a link.
/// Either kind is detached when the [`Ebpf`](crate::Ebpf) it belongs to is
/// dropped.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.6. Instances
/// in `.struct_ops.link` require 6.4.
///
/// # Examples
///
/// ```no_run
/// # #[derive(Debug, thiserror::Error)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     StructOps(#[from] aya::maps::StructOpsError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// let mut cubic = bpf.struct_ops_mut("cubic").unwrap();
/// // Register the algorithm under another name than the object gives it.
/// cubic.set_member("name", b"bpf_cubic")?;
/// cubic.load()?;
/// cubic.attach()?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_MAP_TYPE_STRUCT_OPS")]
pub struct StructOps<'a> {
    instance: &'a mut StructOpsInstance,
    programs: &'a mut HashMap<String, Program>,
}

impl<'a> StructOps<'a> {
    pub(crate) const fn new(
        instance: &'a mut StructOpsInstance,
        programs: &'a mut HashMap<String, Program>,
    ) -> Self {
        Self { instance, programs }
    }

    /// The name of the kernel struct type, e.g. `tcp_congestion_ops`.
    pub fn struct_name(&self) -> &str {
        &self.instance.obj.struct_name
    }

    /// Whether the instance is currently registered with the kernel.
    pub const fn is_attached(&self) -> bool {
        self.instance.is_attached()
    }

    /// Sets a member of the struct that is not a function pointer.
    ///
    /// The member is looked up in the kernel's definition of the struct, so
    /// it does not have to be one the object file sets. A `value` shorter
    /// than the member is padded with zeros.
    ///
    /// Members can only be set before the instance is first attached.
    pub fn set_member(&mut self, member: &str, value: &[u8]) -> Result<(), StructOpsError> {
        if self.instance.value_written {
            return Err(StructOpsError::ValueAlreadyWritten);
        }
        let obj = &mut self.instance.obj;
        let Some((value_offset, size)) = obj
            .members
            .iter()
            .find(|m| m.name == member)
            .map(|m| (m.value_offset, m.size))
        else {
            return Err(StructOpsError::InvalidMember {
                struct_name: obj.struct_name.clone(),
                member: member.to_owned(),
            });
        };
        if value.len() > size {
            return Err(StructOpsError::ValueTooLarge {
                member: member.to_owned(),
                len: value.len(),
                size,
            });
        }
        let slot = &mut obj.data[value_offset..value_offset + size];
        slot.fill(0);
        slot[..value.len()].copy_from_slice(value);
        Ok(())
    }

    /// Loads the programs that implement the instance's members.
    ///
    /// Programs that are already loaded, for example because another
    /// instance uses them too, are left as they are.
    pub fn load(&mut self) -> Result<(), StructOpsError> {
        for slot in &self.instance.obj.programs {
            match self.programs.get_mut(&slot.program) {
                Some(Program::StructOps(program)) => {
                    if program.fd().is_err() {
                        program.load()?;
                    }
                }
                Some(_) => {
                    return Err(StructOpsError::UnexpectedProgramType {
                        program: slot.program.clone(),
                    });
                }
                None => {
                    return Err(StructOpsError::ProgramNotFound {
                        program: slot.program.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Registers the instance with the kernel.
    ///
    /// The instance's programs must be loaded first, see [`StructOps::load`].
    ///
    /// An instance without a link can be attached only once: the kernel does
    /// not accept its value a second time.
    pub fn attach(&mut self) -> Result<(), StructOpsError> {
        if self.instance.is_attached() {
            return Err(StructOpsError::AlreadyAttached);
        }

        if !self.instance.value_written {
            let Self { instance, programs } = self;
            let StructOpsMap {
                programs: slots,
                data: value,
                ..
            } = &mut instance.obj;
            for slot in slots.iter() {
                let fd = match programs.get(&slot.program) {
                    Some(Program::StructOps(program)) => program.fd()?.as_fd().as_raw_fd(),
                    Some(_) => {
                        return Err(StructOpsError::UnexpectedProgramType {
                            program: slot.program.clone(),
                        });
                    }
                    None => {
                        return Err(StructOpsError::ProgramNotFound {
                            program: slot.program.clone(),
                        });
                    }
                };
                // The kernel reads a program fd from each function pointer
                // member, as a pointer-sized integer.
                let fd = (fd as usize).to_ne_bytes();
                value[slot.value_offset..slot.value_offset + fd.len()].copy_from_slice(&fd);
            }
            bpf_map_update_elem_ptr(instance.fd.as_fd(), &KEY, value.as_mut_ptr(), 0).map_err(
                |io_error| SyscallError {
                    call: "bpf_map_update_elem",
                    io_error,
                },
            )?;
            instance.value_written = true;
        }

        if self.instance.obj.is_link {
            let link_fd = bpf_link_create(
                self.instance.fd.as_fd(),
                LinkTarget::None,
                BPF_STRUCT_OPS,
                0,
                None,
            )
            .map_err(|io_error| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;
            self.instance.link = Some(FdLink::new(link_fd));
        }
        Ok(())
    }

    /// Unregisters the instance.
    pub fn detach(&mut self) -> Result<(), StructOpsError> {
        if !self.instance.is_attached() {
            return Err(StructOpsError::NotAttached);
        }
        if self.instance.obj.is_link {
            // Closing the link unregisters the instance.
            self.instance.link = None;
        } else {
            self.instance.delete_element()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use assert_matches::assert_matches;
    use aya_obj::{
        generated::bpf_cmd,
        maps::{BtfMapDef, StructOpsMember, StructOpsProgramSlot},
    };

    use super::*;
    use crate::{
        maps::test_utils,
        sys::{Syscall, override_syscall},
    };

    thread_local! {
        /// The `bpf()` commands issued since the last `record_syscalls`.
        static COMMANDS: RefCell<Vec<bpf_cmd>> = const { RefCell::new(Vec::new()) };
    }

    fn record_syscalls() {
        COMMANDS.with_borrow_mut(Vec::clear);
        override_syscall(|call| match call {
            Syscall::Ebpf { cmd, attr } => {
                if cmd == bpf_cmd::BPF_LINK_CREATE {
                    let link_create = unsafe { attr.link_create };
                    assert_eq!(link_create.attach_type, BPF_STRUCT_OPS as u32);
                }
                COMMANDS.with_borrow_mut(|commands| commands.push(cmd));
                // Only link creation returns a file descriptor.
                if cmd == bpf_cmd::BPF_LINK_CREATE {
                    Ok(crate::MockableFd::mock_signed_fd().into())
                } else {
                    Ok(0)
                }
            }
            call => panic!("unexpected syscall {call:?}"),
        });
    }

    fn commands() -> Vec<bpf_cmd> {
        COMMANDS.with_borrow_mut(std::mem::take)
    }

    /// An instance of a struct with one settable member, `id`, at bytes 8..24.
    fn instance(is_link: bool, programs: &[&str]) -> StructOpsInstance {
        let obj = aya_obj::Map::StructOps(StructOpsMap {
            def: BtfMapDef::default(),
            section_index: 0,
            symbol_index: 0,
            btf_vmlinux_value_type_id: 1,
            data: vec![0xff; 32],
            programs: programs
                .iter()
                .map(|program| StructOpsProgramSlot {
                    member_name: "enqueue".to_owned(),
                    program: (*program).to_owned(),
                    value_offset: 24,
                })
                .collect(),
            members: vec![StructOpsMember {
                name: "id".to_owned(),
                value_offset: 8,
                size: 16,
            }],
            struct_name: "test_ops".to_owned(),
            is_link,
            is_optional: false,
        });
        StructOpsInstance::try_new(test_utils::new_map(obj)).unwrap()
    }

    #[test]
    fn test_set_member() {
        let mut instance = instance(false, &[]);
        let mut programs = HashMap::new();
        let mut struct_ops = StructOps::new(&mut instance, &mut programs);

        struct_ops.set_member("id", b"a long name").unwrap();
        // A shorter value replaces the whole member.
        struct_ops.set_member("id", b"short").unwrap();

        let data = &instance.obj.data;
        assert_eq!(&data[8..24], b"short\0\0\0\0\0\0\0\0\0\0\0");
        // Nothing outside the member is touched.
        assert!(data[..8].iter().chain(&data[24..]).all(|b| *b == 0xff));
    }

    #[test]
    fn test_set_member_invalid() {
        let mut instance = instance(false, &[]);
        let mut programs = HashMap::new();
        let mut struct_ops = StructOps::new(&mut instance, &mut programs);

        // Function pointer members are not in the table either.
        assert_matches!(
            struct_ops.set_member("enqueue", &[0]),
            Err(StructOpsError::InvalidMember { struct_name, member })
                if struct_name == "test_ops" && member == "enqueue"
        );
        assert_matches!(
            struct_ops.set_member("id", &[0; 17]),
            Err(StructOpsError::ValueTooLarge { member, len: 17, size: 16 }) if member == "id"
        );
    }

    #[test]
    fn test_attach_without_link() {
        let mut instance = instance(false, &[]);
        let mut programs = HashMap::new();
        let mut struct_ops = StructOps::new(&mut instance, &mut programs);
        record_syscalls();

        assert_matches!(struct_ops.detach(), Err(StructOpsError::NotAttached));
        assert!(!struct_ops.is_attached());

        struct_ops.attach().unwrap();
        assert!(struct_ops.is_attached());
        assert_eq!(commands(), [bpf_cmd::BPF_MAP_UPDATE_ELEM]);

        assert_matches!(struct_ops.attach(), Err(StructOpsError::AlreadyAttached));
        assert_matches!(
            struct_ops.set_member("id", b"late"),
            Err(StructOpsError::ValueAlreadyWritten)
        );

        struct_ops.detach().unwrap();
        assert!(!struct_ops.is_attached());
        assert_eq!(commands(), [bpf_cmd::BPF_MAP_DELETE_ELEM]);
    }

    #[test]
    fn test_attach_with_link() {
        let mut instance = instance(true, &[]);
        let mut programs = HashMap::new();
        let mut struct_ops = StructOps::new(&mut instance, &mut programs);
        record_syscalls();

        struct_ops.attach().unwrap();
        assert!(struct_ops.is_attached());
        assert_eq!(
            commands(),
            [bpf_cmd::BPF_MAP_UPDATE_ELEM, bpf_cmd::BPF_LINK_CREATE]
        );

        // Detaching closes the link, which is not a bpf() call.
        struct_ops.detach().unwrap();
        assert!(!struct_ops.is_attached());
        assert_eq!(commands(), []);

        // The value is written only once; attaching again needs just a link.
        struct_ops.attach().unwrap();
        assert_eq!(commands(), [bpf_cmd::BPF_LINK_CREATE]);
    }

    #[test]
    fn test_drop_unregisters_instance_without_link() {
        let mut attached = instance(false, &[]);
        let never_attached = instance(false, &[]);
        let mut programs = HashMap::new();
        record_syscalls();

        StructOps::new(&mut attached, &mut programs)
            .attach()
            .unwrap();
        assert_eq!(commands(), [bpf_cmd::BPF_MAP_UPDATE_ELEM]);

        drop(never_attached);
        assert_eq!(commands(), []);

        drop(attached);
        assert_eq!(commands(), [bpf_cmd::BPF_MAP_DELETE_ELEM]);
    }

    #[test]
    fn test_missing_program() {
        let mut instance = instance(true, &["missing"]);
        let mut programs = HashMap::new();
        let mut struct_ops = StructOps::new(&mut instance, &mut programs);
        record_syscalls();

        assert_matches!(
            struct_ops.load(),
            Err(StructOpsError::ProgramNotFound { program }) if program == "missing"
        );
        assert_matches!(
            struct_ops.attach(),
            Err(StructOpsError::ProgramNotFound { program }) if program == "missing"
        );
        // Nothing reached the kernel.
        assert_eq!(commands(), []);
        assert!(!struct_ops.is_attached());
    }
}
