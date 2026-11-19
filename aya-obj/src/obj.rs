//! Object file loading, parsing, and relocation.

use std::{
    borrow::ToOwned as _,
    cell::LazyCell,
    collections::{BTreeMap, HashSet},
    ffi::{CStr, CString, FromBytesWithNulError},
    mem, ptr,
    slice::from_raw_parts_mut,
    str::FromStr,
    string::ToString as _,
};

use log::debug;
use object::{
    Endian as _, Endianness, ObjectSymbol as _, ObjectSymbolTable as _, RelocationTarget,
    SectionIndex, SectionKind, SymbolKind,
    read::{Object as _, ObjectSection as _, Section as ObjSection},
};

use crate::{
    btf::{
        Array, Btf, BtfError, BtfExt, BtfKind, BtfMember, BtfType, DataSecEntry, FuncSecInfo,
        LineSecInfo, Struct, Var,
    },
    generated::{
        BPF_CALL, BPF_F_LINK, BPF_F_RDONLY_PROG, BPF_JMP, BPF_K, bpf_func_id, bpf_insn,
        bpf_map_info,
        bpf_map_type::{BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_STRUCT_OPS},
    },
    maps::{
        BtfMap, BtfMapDef, LegacyMap, MINIMUM_MAP_SIZE, Map, PinningType, StructOpsError,
        StructOpsFnPtrMember, StructOpsInfo, StructOpsMap, StructOpsMember, StructOpsProgramSlot,
        bpf_map_def,
    },
    programs::{
        CgroupSkbAttachType, CgroupSockAddrAttachType, CgroupSockAttachType,
        CgroupSockoptAttachType, SkReuseportAttachType, SkSkbKind, StructOpsAttachTarget,
        StructOpsAttachment, XdpAttachType,
    },
    relocation::{INS_SIZE, Relocation, Symbol},
    util::HashMap,
};

const KERNEL_VERSION_ANY: u32 = 0xFFFF_FFFE;

/// The loaded object file representation
#[derive(Clone, Debug)]
pub struct Object {
    /// The endianness
    pub endianness: Endianness,
    /// Program license
    pub license: CString,
    /// Kernel version
    pub kernel_version: Option<u32>,
    /// Program BTF
    pub btf: Option<Btf>,
    /// Program BTF.ext
    pub btf_ext: Option<BtfExt>,
    /// Referenced maps
    pub maps: HashMap<String, Map>,
    /// The instances defined in `.struct_ops` and `.struct_ops.link`
    /// sections, by name.
    pub struct_ops: HashMap<String, StructOpsInfo>,
    /// The struct type and member each `struct_ops` program implements, by
    /// program name.
    pub struct_ops_attachments: HashMap<String, StructOpsAttachment>,
    /// A hash map of programs, using the program names parsed
    /// in [`ProgramSection`]s as keys.
    pub programs: HashMap<String, Program>,
    /// Functions
    pub functions: BTreeMap<(usize, u64), Function>,
    pub(crate) relocations: HashMap<SectionIndex, HashMap<u64, Relocation>>,
    pub(crate) symbol_table: HashMap<usize, Symbol>,
    pub(crate) symbols_by_section: HashMap<SectionIndex, Vec<usize>>,
    pub(crate) section_infos: HashMap<String, (SectionIndex, u64)>,
    // symbol_offset_by_name caches symbols that could be referenced from a
    // BTF VAR type so the offsets can be fixed up
    pub(crate) symbol_offset_by_name: HashMap<String, u64>,
}

/// An eBPF program
#[derive(Debug, Clone)]
pub struct Program {
    /// The license
    pub license: CString,
    /// The kernel version
    pub kernel_version: Option<u32>,
    /// The section containing the program
    pub section: ProgramSection,
    /// The section index of the program
    pub section_index: usize,
    /// The address of the program
    pub address: u64,
}

impl Program {
    /// The key used by [`Object::functions`]
    pub const fn function_key(&self) -> (usize, u64) {
        (self.section_index, self.address)
    }
}

/// An eBPF function
#[derive(Debug, Clone)]
pub struct Function {
    /// The address
    pub address: u64,
    /// The function name
    pub name: String,
    /// The section index
    pub section_index: SectionIndex,
    /// The section offset
    pub section_offset: usize,
    /// The eBPF byte code instructions
    pub instructions: Vec<bpf_insn>,
    /// The function info
    pub func_info: FuncSecInfo,
    /// The line info
    pub line_info: LineSecInfo,
    /// Function info record size
    pub func_info_rec_size: usize,
    /// Line info record size
    pub line_info_rec_size: usize,
}

/// Section types containing eBPF programs
///
/// Section Name Parsing
///
/// Section types are parsed from the section name strings.
///
/// In order for Aya to treat a section as a [`ProgramSection`],
/// there are a few requirements:
/// - The section must be an executable code section.
/// - The section name must conform to [Program Types and ELF Sections].
///
/// [Program Types and ELF Sections]: https://docs.kernel.org/bpf/libbpf/program_types.html
///
/// # Unsupported Sections
///
/// Currently, the following section names are not supported yet:
/// - `flow_dissector`: `BPF_PROG_TYPE_FLOW_DISSECTOR`
/// - `ksyscall+` or `kretsyscall+`
/// - `usdt+`
/// - `kprobe.multi+` or `kretprobe.multi+`: `BPF_TRACE_KPROBE_MULTI`
/// - `lsm_cgroup+`
/// - `lwt_in`, `lwt_out`, `lwt_seg6local`, `lwt_xmit`
/// - `raw_tp.w+`, `raw_tracepoint.w+`
/// - `action`
/// - `syscall`
/// - `struct_ops+`
/// - `fmod_ret+`, `fmod_ret.s+`
/// - `iter+`, `iter.s+`
#[derive(Debug, Clone)]
#[expect(missing_docs, reason = "TODO")]
pub enum ProgramSection {
    KRetProbe,
    KProbe,
    UProbe {
        sleepable: bool,
        multi: bool,
    },
    URetProbe {
        sleepable: bool,
        multi: bool,
    },
    TracePoint,
    SocketFilter,
    Xdp {
        frags: bool,
        attach_type: XdpAttachType,
    },
    SkMsg,
    SkSkbStream {
        kind: SkSkbKind,
    },
    SockOps,
    SchedClassifier,
    CgroupSkb {
        attach_type: Option<CgroupSkbAttachType>,
    },
    CgroupSockAddr {
        attach_type: CgroupSockAddrAttachType,
    },
    CgroupSysctl,
    CgroupSockopt {
        attach_type: CgroupSockoptAttachType,
    },
    LircMode2,
    PerfEvent,
    RawTracePoint,
    Lsm {
        sleepable: bool,
    },
    LsmCgroup,
    BtfTracePoint,
    FEntry {
        sleepable: bool,
    },
    FExit {
        sleepable: bool,
    },
    FlowDissector,
    Extension,
    SkLookup,
    SkReuseport {
        attach_type: SkReuseportAttachType,
    },
    CgroupSock {
        attach_type: CgroupSockAttachType,
    },
    CgroupDevice,
    Iter {
        sleepable: bool,
    },
    StructOps {
        sleepable: bool,
    },
}

impl FromStr for ProgramSection {
    type Err = ParseError;

    fn from_str(section: &str) -> Result<Self, ParseError> {
        // parse the common case, eg "xdp/program_name" or
        // "sk_skb/stream_verdict/program_name"
        let mut pieces = section.split('/');
        let mut next = || {
            pieces
                .next()
                .ok_or_else(|| ParseError::InvalidProgramSection {
                    section: section.to_owned(),
                })
        };
        let kind = next()?;

        Ok(match kind {
            "kprobe" => Self::KProbe,
            "kretprobe" => Self::KRetProbe,
            "uprobe" => Self::UProbe {
                sleepable: false,
                multi: false,
            },
            "uprobe.s" => Self::UProbe {
                sleepable: true,
                multi: false,
            },
            "uprobe.multi" => Self::UProbe {
                sleepable: false,
                multi: true,
            },
            "uprobe.multi.s" => Self::UProbe {
                sleepable: true,
                multi: true,
            },
            "uretprobe" => Self::URetProbe {
                sleepable: false,
                multi: false,
            },
            "uretprobe.s" => Self::URetProbe {
                sleepable: true,
                multi: false,
            },
            "uretprobe.multi" => Self::URetProbe {
                sleepable: false,
                multi: true,
            },
            "uretprobe.multi.s" => Self::URetProbe {
                sleepable: true,
                multi: true,
            },
            "xdp" | "xdp.frags" => Self::Xdp {
                frags: kind == "xdp.frags",
                attach_type: match pieces.next() {
                    None => XdpAttachType::Interface,
                    Some("cpumap") => XdpAttachType::CpuMap,
                    Some("devmap") => XdpAttachType::DevMap,
                    Some(_) => {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                },
            },
            "tp_btf" => Self::BtfTracePoint,
            "tracepoint" | "tp" => Self::TracePoint,
            "socket" => Self::SocketFilter,
            "sk_msg" => Self::SkMsg,
            "sk_skb" => {
                let name = next()?;
                let kind = match name {
                    "stream_parser" => SkSkbKind::StreamParser,
                    "stream_verdict" => SkSkbKind::StreamVerdict,
                    _ => {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                };
                Self::SkSkbStream { kind }
            }
            "sockops" => Self::SockOps,
            "classifier" => Self::SchedClassifier,
            "cgroup_skb" => {
                let name = next()?;
                let attach_type = Some(match name {
                    "ingress" => CgroupSkbAttachType::Ingress,
                    "egress" => CgroupSkbAttachType::Egress,
                    _ => {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                });
                Self::CgroupSkb { attach_type }
            }
            "cgroup" => {
                let name = next()?;
                match name {
                    "skb" => Self::CgroupSkb { attach_type: None },
                    "sysctl" => Self::CgroupSysctl,
                    "dev" => Self::CgroupDevice,
                    "getsockopt" => Self::CgroupSockopt {
                        attach_type: CgroupSockoptAttachType::Get,
                    },
                    "setsockopt" => Self::CgroupSockopt {
                        attach_type: CgroupSockoptAttachType::Set,
                    },
                    "sock" => Self::CgroupSock {
                        attach_type: CgroupSockAttachType::default(),
                    },
                    "post_bind4" => Self::CgroupSock {
                        attach_type: CgroupSockAttachType::PostBind4,
                    },
                    "post_bind6" => Self::CgroupSock {
                        attach_type: CgroupSockAttachType::PostBind6,
                    },
                    "sock_create" => Self::CgroupSock {
                        attach_type: CgroupSockAttachType::SockCreate,
                    },
                    "sock_release" => Self::CgroupSock {
                        attach_type: CgroupSockAttachType::SockRelease,
                    },
                    "bind4" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::Bind4,
                    },
                    "bind6" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::Bind6,
                    },
                    "connect4" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::Connect4,
                    },
                    "connect6" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::Connect6,
                    },
                    "getpeername4" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::GetPeerName4,
                    },
                    "getpeername6" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::GetPeerName6,
                    },
                    "getsockname4" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::GetSockName4,
                    },
                    "getsockname6" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::GetSockName6,
                    },
                    "sendmsg4" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::UDPSendMsg4,
                    },
                    "sendmsg6" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::UDPSendMsg6,
                    },
                    "recvmsg4" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::UDPRecvMsg4,
                    },
                    "recvmsg6" => Self::CgroupSockAddr {
                        attach_type: CgroupSockAddrAttachType::UDPRecvMsg6,
                    },
                    _ => {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                }
            }
            "lirc_mode2" => Self::LircMode2,
            "perf_event" => Self::PerfEvent,
            "raw_tp" | "raw_tracepoint" => Self::RawTracePoint,
            "lsm" => Self::Lsm { sleepable: false },
            "lsm.s" => Self::Lsm { sleepable: true },
            "lsm_cgroup" => Self::LsmCgroup,
            "fentry" => Self::FEntry { sleepable: false },
            "fentry.s" => Self::FEntry { sleepable: true },
            "fexit" => Self::FExit { sleepable: false },
            "fexit.s" => Self::FExit { sleepable: true },
            "flow_dissector" => Self::FlowDissector,
            "freplace" => Self::Extension,
            "sk_lookup" => Self::SkLookup,
            "sk_reuseport" => {
                let attach_type = if let Some(attach_type) = pieces.next() {
                    if attach_type == "migrate" {
                        SkReuseportAttachType::SelectOrMigrate
                    } else {
                        return Err(ParseError::InvalidProgramSection {
                            section: section.to_owned(),
                        });
                    }
                } else {
                    SkReuseportAttachType::Select
                };
                Self::SkReuseport { attach_type }
            }
            "iter" => Self::Iter { sleepable: false },
            "iter.s" => Self::Iter { sleepable: true },
            "struct_ops" => Self::StructOps { sleepable: false },
            "struct_ops.s" => Self::StructOps { sleepable: true },
            _ => {
                return Err(ParseError::InvalidProgramSection {
                    section: section.to_owned(),
                });
            }
        })
    }
}

impl Object {
    /// Parses the binary data as an object file into an [Object]
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let obj = object::read::File::parse(data).map_err(ParseError::ElfError)?;
        let endianness = obj.endianness();

        let license = if let Some(section) = obj.section_by_name("license") {
            parse_license(Section::try_from(&section)?.data)?
        } else {
            CString::new("GPL").unwrap()
        };

        let kernel_version = if let Some(section) = obj.section_by_name("version") {
            parse_version(Section::try_from(&section)?.data, endianness)?
        } else {
            None
        };

        let mut bpf_obj = Self::new(endianness, license, kernel_version);

        if let Some(symbol_table) = obj.symbol_table() {
            for symbol in symbol_table.symbols() {
                let name = symbol
                    .name()
                    .ok()
                    .map(String::from)
                    .ok_or(BtfError::InvalidSymbolName)?;
                let sym = Symbol {
                    index: symbol.index().0,
                    name: Some(name.clone()),
                    section_index: symbol.section().index().map(|i| i.0),
                    address: symbol.address(),
                    size: symbol.size(),
                    is_definition: symbol.is_definition(),
                    kind: symbol.kind(),
                    is_weak: symbol.is_weak(),
                };
                bpf_obj.symbol_table.insert(symbol.index().0, sym);
                if let Some(section_idx) = symbol.section().index() {
                    bpf_obj
                        .symbols_by_section
                        .entry(section_idx)
                        .or_default()
                        .push(symbol.index().0);
                }
                if symbol.is_global() || symbol.kind() == SymbolKind::Data {
                    bpf_obj.symbol_offset_by_name.insert(name, symbol.address());
                }
            }
        }

        // .BTF and .BTF.ext sections must be parsed first
        // as they're required to prepare function and line information
        // when parsing program sections
        if let Some(s) = obj.section_by_name(".BTF") {
            bpf_obj.parse_section(Section::try_from(&s)?)?;
            if let Some(s) = obj.section_by_name(".BTF.ext") {
                bpf_obj.parse_section(Section::try_from(&s)?)?;
            }

            bpf_obj.collect_ksyms_from_btf()?;
        }

        // Parse PROGRAM sections.
        for s in obj.sections() {
            let section = Section::try_from(&s)?;
            if section.kind != EbpfSectionKind::Program {
                continue;
            }
            bpf_obj.parse_section(section)?;
        }

        for s in obj.sections() {
            let section = Section::try_from(&s)?;
            if let Ok(name) = s.name()
                && (name == ".BTF"
                    || name == ".BTF.ext"
                    || section.kind == EbpfSectionKind::Program)
            {
                continue;
            }
            bpf_obj.parse_section(section)?;
        }

        Ok(bpf_obj)
    }

    fn new(endianness: Endianness, license: CString, kernel_version: Option<u32>) -> Self {
        Self {
            endianness,
            license,
            kernel_version,
            btf: None,
            btf_ext: None,
            maps: HashMap::new(),
            struct_ops: HashMap::new(),
            struct_ops_attachments: HashMap::new(),
            programs: HashMap::new(),
            functions: BTreeMap::new(),
            relocations: HashMap::new(),
            symbol_table: HashMap::new(),
            symbols_by_section: HashMap::new(),
            section_infos: HashMap::new(),
            symbol_offset_by_name: HashMap::new(),
        }
    }

    /// Returns true if this object contains CO-RE relocations.
    pub fn has_btf_relocations(&self) -> bool {
        self.btf_ext
            .as_ref()
            .is_some_and(|ext| !ext.relocations().is_empty())
    }

    /// Patches map data
    pub fn patch_map_data(
        &mut self,
        globals: HashMap<&str, (&[u8], bool)>,
    ) -> Result<(), ParseError> {
        let symbols: HashMap<String, &Symbol> = self
            .symbol_table
            .iter()
            .filter(|(_, s)| s.name.is_some())
            .map(|(_, s)| (s.name.as_ref().unwrap().clone(), s))
            .collect();

        for (name, (data, must_exist)) in globals {
            if let Some(symbol) = symbols.get(name) {
                if data.len() as u64 != symbol.size {
                    return Err(ParseError::InvalidGlobalData {
                        name: name.to_string(),
                        sym_size: symbol.size,
                        data_size: data.len(),
                    });
                }
                let (_, map) = self
                    .maps
                    .iter_mut()
                    // assumption: there is only one map created per section where we're trying to
                    // patch data. this assumption holds true for the .rodata section at least
                    .find(|(_, m)| symbol.section_index == Some(m.section_index()))
                    .ok_or_else(|| ParseError::MapNotFound {
                        index: symbol.section_index.unwrap_or(0),
                    })?;
                let start = symbol.address as usize;
                let end = start + symbol.size as usize;
                if start > end || end > map.data().len() {
                    return Err(ParseError::InvalidGlobalData {
                        name: name.to_string(),
                        sym_size: symbol.size,
                        data_size: data.len(),
                    });
                }
                map.data_mut().splice(start..end, data.iter().copied());
            } else if must_exist {
                return Err(ParseError::SymbolNotFound {
                    name: name.to_owned(),
                });
            }
        }
        Ok(())
    }

    fn parse_btf(&mut self, section: &Section<'_>) -> Result<(), BtfError> {
        self.btf = Some(Btf::parse(section.data, self.endianness)?);

        Ok(())
    }

    fn parse_btf_ext(&mut self, section: &Section<'_>) -> Result<(), BtfError> {
        self.btf_ext = Some(BtfExt::parse(
            section.data,
            self.endianness,
            self.btf.as_ref().unwrap(),
        )?);
        Ok(())
    }

    fn parse_programs(&mut self, section: &Section<'_>) -> Result<(), ParseError> {
        let program_section = ProgramSection::from_str(section.name)?;
        let syms = self.symbols_by_section.get(&section.index).ok_or_else(|| {
            ParseError::NoSymbolsForSection {
                section_name: section.name.to_string(),
            }
        })?;
        for symbol_index in syms {
            let symbol = self
                .symbol_table
                .get(symbol_index)
                .expect("all symbols in symbols_by_section are also in symbol_table");

            // Here we get both ::Label (LBB*) and ::Text symbols, and we only want the latter.
            let name = match (symbol.name.as_ref(), symbol.kind) {
                (Some(name), SymbolKind::Text) if !name.is_empty() => name,
                _ => continue,
            };

            let (p, f) =
                self.parse_program(section, program_section.clone(), name.clone(), symbol)?;
            let key = p.function_key();
            self.programs.insert(f.name.clone(), p);
            self.functions.insert(key, f);
        }
        Ok(())
    }

    fn parse_program(
        &self,
        section: &Section<'_>,
        program_section: ProgramSection,
        name: String,
        symbol: &Symbol,
    ) -> Result<(Program, Function), ParseError> {
        let offset = symbol.address as usize - section.address as usize;
        let (func_info, line_info, func_info_rec_size, line_info_rec_size) =
            get_func_and_line_info(self.btf_ext.as_ref(), symbol, section, offset, true);

        let start = symbol.address as usize;
        let end = (symbol.address + symbol.size) as usize;

        let function = Function {
            name,
            address: symbol.address,
            section_index: section.index,
            section_offset: start,
            instructions: copy_instructions(&section.data[start..end])?,
            func_info,
            line_info,
            func_info_rec_size,
            line_info_rec_size,
        };

        Ok((
            Program {
                license: self.license.clone(),
                kernel_version: self.kernel_version,
                section: program_section,
                section_index: section.index.0,
                address: symbol.address,
            },
            function,
        ))
    }

    fn parse_text_section(&mut self, section: Section<'_>) -> Result<(), ParseError> {
        let mut symbols_by_address = HashMap::new();

        for sym in self.symbol_table.values() {
            if sym.is_definition
                && sym.kind == SymbolKind::Text
                && sym.section_index == Some(section.index.0)
            {
                if symbols_by_address.contains_key(&sym.address) {
                    return Err(ParseError::SymbolTableConflict {
                        section_index: section.index.0,
                        address: sym.address,
                    });
                }
                symbols_by_address.insert(sym.address, sym);
            }
        }

        let mut offset = 0;
        while offset < section.data.len() {
            let address = section.address + offset as u64;
            let sym = symbols_by_address
                .get(&address)
                .ok_or(ParseError::UnknownSymbol {
                    section_index: section.index.0,
                    address,
                })?;
            if sym.size == 0 {
                return Err(ParseError::InvalidSymbol {
                    index: sym.index,
                    name: sym.name.clone(),
                });
            }

            let (func_info, line_info, func_info_rec_size, line_info_rec_size) =
                get_func_and_line_info(self.btf_ext.as_ref(), sym, &section, offset, false);

            self.functions.insert(
                (section.index.0, sym.address),
                Function {
                    address,
                    name: sym.name.clone().unwrap(),
                    section_index: section.index,
                    section_offset: offset,
                    instructions: copy_instructions(
                        &section.data[offset..offset + sym.size as usize],
                    )?,
                    func_info,
                    line_info,
                    func_info_rec_size,
                    line_info_rec_size,
                },
            );

            offset += sym.size as usize;
        }

        if !section.relocations.is_empty() {
            self.relocations.insert(
                section.index,
                section
                    .relocations
                    .into_iter()
                    .map(|rel| (rel.offset, rel))
                    .collect(),
            );
        }

        Ok(())
    }

    fn parse_btf_maps(&mut self, section: &Section<'_>) -> Result<(), ParseError> {
        if self.btf.is_none() {
            return Err(ParseError::NoBTF);
        }
        let btf = self.btf.as_ref().unwrap();
        let maps: HashMap<&String, usize> = self
            .symbols_by_section
            .get(&section.index)
            .ok_or_else(|| ParseError::NoSymbolsForSection {
                section_name: section.name.to_owned(),
            })?
            .iter()
            .filter_map(|s| {
                let symbol = &self.symbol_table[s];
                symbol.name.as_ref().map(|name| (name, symbol.index))
            })
            .collect();

        for t in btf.types() {
            if let BtfType::DataSec(datasec) = &t {
                let type_name = btf.type_name(t)?;
                if type_name == section.name {
                    // each btf_var_secinfo contains a map
                    for info in &datasec.entries {
                        let (map_name, def, inner_def) = parse_btf_map_def(btf, info)?;
                        let symbol_index =
                            maps.get(&map_name)
                                .ok_or_else(|| ParseError::SymbolNotFound {
                                    name: map_name.clone(),
                                })?;
                        self.maps.insert(
                            map_name,
                            Map::Btf(BtfMap {
                                def,
                                inner_def,
                                section_index: section.index.0,
                                symbol_index: *symbol_index,
                                data: Vec::new(),
                            }),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Turns every parsed `struct_ops` instance into a `Map::StructOps`.
    ///
    /// Optional instances, from sections starting with `?`, are skipped unless
    /// named in `create_optional`, and stay in `struct_ops`. On error the
    /// object is left unchanged, so the call can be retried.
    pub fn resolve_struct_ops(
        &mut self,
        kernel_btf: &Btf,
        create_optional: &HashSet<&str>,
    ) -> Result<(), StructOpsError> {
        if self.struct_ops.is_empty() {
            return Ok(());
        }
        let Some(btf) = self.btf.as_ref() else {
            return Err(StructOpsError::NoBtf);
        };

        // Looks up a struct type in the kernel's BTF by name, on behalf of one instance.
        fn kernel_struct<'a>(
            kernel_btf: &'a Btf,
            name: &str,
            type_name: &str,
        ) -> Result<(u32, &'a Struct), StructOpsError> {
            let type_id = kernel_btf
                .id_by_type_name_kind(type_name, BtfKind::Struct)
                .map_err(|err| match err {
                    BtfError::UnknownBtfTypeName { type_name } => {
                        StructOpsError::KernelTypeNotFound {
                            name: name.to_owned(),
                            type_name,
                        }
                    }
                    err => err.into(),
                })?;
            match kernel_btf.type_by_id(type_id)? {
                BtfType::Struct(s) => Ok((type_id, s)),
                _ => Err(BtfError::UnexpectedBtfType { type_id }.into()),
            }
        }

        // Whether a struct member is a bitfield, in either of BTF's two encodings.
        fn is_bitfield_member(btf: &Btf, s: &Struct, member: &BtfMember) -> Result<bool, BtfError> {
            // Current encoding: the struct has kind_flag set and the member's
            // offset carries the bitfield size.
            if s.member_bit_field_size(member) != 0 {
                return Ok(true);
            }

            // Legacy encoding: the member's int type is narrower than its
            // storage, or starts at a bit offset inside it.
            let member_type_id = btf.resolve_type(member.btf_type)?;
            Ok(match btf.type_by_id(member_type_id)? {
                BtfType::Int(int) => int.bits() != int.size * 8 || int.offset() != 0,
                _ => false,
            })
        }

        // Nothing below changes the object until every instance has resolved,
        // so a failed call can be retried.
        let mut resolved: Vec<(String, StructOpsMap)> = Vec::new();
        // Program name -> attachment, for the programs this call resolves.
        let mut attachments: HashMap<String, StructOpsAttachment> = HashMap::new();

        // Whether a struct member is a pointer to a function, skipping typedefs
        // and modifiers on the member's type and on the type it points to.
        fn is_fn_ptr_member(btf: &Btf, member: &BtfMember) -> Result<bool, BtfError> {
            let member_type_id = btf.resolve_type(member.btf_type)?;
            Ok(match btf.type_by_id(member_type_id)? {
                BtfType::Ptr(ptr) => {
                    let pointee_type_id = btf.resolve_type(ptr.btf_type)?;
                    matches!(btf.type_by_id(pointee_type_id)?, BtfType::FuncProto(_))
                }
                _ => false,
            })
        }

        for (name, info) in &self.struct_ops {
            // Optional instances are only created when asked for.
            if info.is_optional && !create_optional.contains(name.as_str()) {
                continue;
            }
            let name = name.clone();

            let (kernel_struct_ops_type_id, kernel_struct_ops) =
                kernel_struct(kernel_btf, &name, &info.struct_name)?;

            // All kernel registered struct_ops BTF types have a wrapper type whose name has
            // the form "bpf_struct_ops_<struct_ops_type> ex.: bpf_struct_ops_Qdisc_ops"
            let kernel_struct_ops_wrapper_name = format!("bpf_struct_ops_{}", info.struct_name);
            let (btf_vmlinux_value_type_id, wrapper) =
                kernel_struct(kernel_btf, &name, &kernel_struct_ops_wrapper_name)?;
            let Some(wrapper_data_member) = wrapper
                .members
                .iter()
                .find(|member| kernel_struct_ops_type_id == member.btf_type)
            else {
                return Err(StructOpsError::WrapperDataMemberNotFound {
                    name,
                    wrapper_name: kernel_struct_ops_wrapper_name,
                    struct_name: info.struct_name.clone(),
                });
            };
            let value_size = wrapper.size;

            let BtfType::Struct(obj_struct_ops) = btf.type_by_id(info.type_id)? else {
                return Err(BtfError::UnexpectedBtfType {
                    type_id: info.type_id,
                }
                .into());
            };

            // we are copying into the buffer that will be assigned to the BTF map value
            // representing the struct_ops in memory. Thus we first have to offset into
            // the map's data member, then add the struct_ops member offset.
            let data_offset = wrapper.member_bit_offset(wrapper_data_member) / 8;

            let mut data = vec![0u8; value_size as usize];
            for member in &obj_struct_ops.members {
                let member_name = btf.string_at(member.name_offset)?;

                // Function pointer members are handled below.
                if info.func_ptrs.iter().any(|f| f.name == member_name) {
                    continue;
                }

                if is_bitfield_member(btf, obj_struct_ops, member)? {
                    return Err(StructOpsError::BitfieldMember {
                        name,
                        member: member_name.into_owned(),
                    });
                }

                let o_member_offset = obj_struct_ops.member_bit_offset(member) / 8;
                let o_member_size = btf.type_size(member.btf_type)?;
                let src = o_member_offset
                    .checked_add(o_member_size)
                    .and_then(|end| info.data.get(o_member_offset..end))
                    .ok_or_else(|| StructOpsError::MemberOutOfBounds {
                        name: name.clone(),
                        member: member_name.to_string(),
                        offset: o_member_offset,
                        size: o_member_size,
                        len: info.data.len(),
                    })?;

                match kernel_struct_ops.members.iter().find(|m| {
                    kernel_btf
                        .string_at(m.name_offset)
                        .is_ok_and(|kernel_member_name| kernel_member_name == member_name)
                }) {
                    None => {
                        // A member the kernel does not have is fine as long as
                        // the object leaves it zeroed.
                        let is_zeroed = src.iter().all(|&b| b == 0);
                        if !is_zeroed {
                            return Err(StructOpsError::MemberNotFound {
                                name,
                                struct_name: info.struct_name.clone(),
                                member: member_name.into_owned(),
                            });
                        }
                    }
                    Some(kernel_member) => {
                        if is_bitfield_member(kernel_btf, kernel_struct_ops, kernel_member)? {
                            return Err(StructOpsError::BitfieldMember {
                                name,
                                member: member_name.into_owned(),
                            });
                        }

                        let member_type_id = btf.resolve_type(member.btf_type)?;
                        let kernel_member_type_id =
                            kernel_btf.resolve_type(kernel_member.btf_type)?;

                        let member_type = btf.type_by_id(member_type_id)?;
                        let kernel_member_type = kernel_btf.type_by_id(kernel_member_type_id)?;

                        if member_type.kind() != kernel_member_type.kind() {
                            return Err(StructOpsError::MemberKindMismatch {
                                name,
                                member: member_name.into_owned(),
                                kind: member_type.kind(),
                                kernel_kind: kernel_member_type.kind(),
                            });
                        }

                        let size = kernel_btf.type_size(kernel_member_type_id)?;
                        if o_member_size != size {
                            return Err(StructOpsError::MemberSizeMismatch {
                                name,
                                member: member_name.into_owned(),
                                size: o_member_size,
                                kernel_size: size,
                            });
                        }

                        let k_member_offset =
                            data_offset + kernel_struct_ops.member_bit_offset(kernel_member) / 8;
                        let data_len = data.len();
                        k_member_offset
                            .checked_add(size)
                            .and_then(|end| data.get_mut(k_member_offset..end))
                            .ok_or_else(|| StructOpsError::MemberOutOfBounds {
                                name: name.clone(),
                                member: member_name.to_string(),
                                offset: k_member_offset,
                                size,
                                len: data_len,
                            })?
                            .copy_from_slice(src);
                    }
                }
            }

            // Where each program's fd goes in the map value.
            let mut programs: Vec<StructOpsProgramSlot> = Vec::new();

            for fn_ptr in &info.func_ptrs {
                // A member no program implements stays zero in the map value.
                let Some(program) = &fn_ptr.program else {
                    continue;
                };

                // The member's position in the kernel struct is what the kernel
                // expects as the program's expected_attach_type.
                let Some((kernel_member_index, kernel_fn_ptr_member)) =
                    kernel_struct_ops.members.iter().enumerate().find(|(_, m)| {
                        kernel_btf
                            .string_at(m.name_offset)
                            .is_ok_and(|name| name == fn_ptr.name)
                    })
                else {
                    // The kernel struct has no member with this name, so there is
                    // nothing for the program to implement.
                    return Err(StructOpsError::MemberNotFound {
                        name,
                        struct_name: info.struct_name.clone(),
                        member: fn_ptr.name.clone(),
                    });
                };

                if is_bitfield_member(kernel_btf, kernel_struct_ops, kernel_fn_ptr_member)? {
                    return Err(StructOpsError::BitfieldMember {
                        name,
                        member: fn_ptr.name.clone(),
                    });
                }

                // The kernel member must be a function pointer too.
                if !is_fn_ptr_member(kernel_btf, kernel_fn_ptr_member)? {
                    return Err(StructOpsError::NotAFunctionPointer {
                        name,
                        member: fn_ptr.name.clone(),
                    });
                }

                programs.push(StructOpsProgramSlot {
                    member_name: fn_ptr.name.clone(),
                    program: program.clone(),
                    value_offset: data_offset
                        + kernel_struct_ops.member_bit_offset(kernel_fn_ptr_member) / 8,
                });

                // Record the kernel struct's type id and the member index. These
                // become the program's attach_btf_id and expected_attach_type.
                let attach_target = StructOpsAttachTarget {
                    kernel_type_id: kernel_struct_ops_type_id,
                    member_index: kernel_member_index as u32,
                };
                // A program can back several instances, but only as the same
                // member of the same kernel struct type.
                let other = attachments
                    .get(program)
                    .or_else(|| self.struct_ops_attachments.get(program))
                    .and_then(|attachment| attachment.attach_target);
                if let Some(other) = other
                    && other != attach_target
                {
                    return Err(StructOpsError::ProgramReuse {
                        program: program.clone(),
                        attach_target,
                        other_attach_target: other,
                    });
                }
                attachments.insert(
                    program.clone(),
                    StructOpsAttachment {
                        type_id: info.type_id,
                        member_name: fn_ptr.name.clone(),
                        attach_target: Some(attach_target),
                    },
                );
            }

            // The kernel struct's other members, so that their value can be
            // replaced by name before the instance is registered.
            let mut members = Vec::new();
            for kernel_member in &kernel_struct_ops.members {
                if is_fn_ptr_member(kernel_btf, kernel_member)? {
                    continue;
                }
                // A member whose size cannot be determined cannot be set.
                let Ok(size) = kernel_btf.type_size(kernel_member.btf_type) else {
                    continue;
                };
                members.push(StructOpsMember {
                    name: kernel_btf
                        .string_at(kernel_member.name_offset)?
                        .into_owned(),
                    value_offset: data_offset
                        + kernel_struct_ops.member_bit_offset(kernel_member) / 8,
                    size,
                });
            }

            let map = StructOpsMap {
                def: BtfMapDef {
                    map_type: BPF_MAP_TYPE_STRUCT_OPS as u32,
                    key_size: size_of::<u32>() as u32,
                    value_size,
                    max_entries: 1,
                    map_flags: if info.is_link { BPF_F_LINK } else { 0 },
                    map_extra: 0,
                    pinning: PinningType::None,
                    // The kernel rejects these for struct_ops maps; the value
                    // type is named by btf_vmlinux_value_type_id.
                    btf_key_type_id: 0,
                    btf_value_type_id: 0,
                },
                section_index: info.section_index,
                symbol_index: info.symbol_index,
                btf_vmlinux_value_type_id,
                data,
                programs,
                members,
                struct_name: info.struct_name.clone(),
                is_link: info.is_link,
                is_optional: info.is_optional,
            };
            resolved.push((name, map));
        }

        for (program, attachment) in attachments {
            self.struct_ops_attachments
                .entry(program)
                .and_modify(|existing| existing.attach_target = attachment.attach_target)
                .or_insert(attachment);
        }
        for (name, map) in resolved {
            self.struct_ops.remove(&name);
            self.maps.insert(name, Map::StructOps(map));
        }

        Ok(())
    }

    // https://docs.kernel.org/bpf/btf.html

    fn parse_struct_ops(&mut self, section: &Section<'_>) -> Result<(), ParseError> {
        if self.btf.is_none() {
            return Err(ParseError::NoBTF);
        }
        let btf = self.btf.as_ref().unwrap();

        let section_name = String::from(section.name);
        let trimmed_section_name = section_name
            .strip_prefix('?')
            .unwrap_or(section_name.as_str());
        let is_link = trimmed_section_name == ".struct_ops.link";
        let is_optional = section_name.starts_with('?');

        let name_to_sec_syms: HashMap<&String, &Symbol> = self
            .symbols_by_section
            .get(&section.index)
            .ok_or_else(|| ParseError::NoSymbolsForSection {
                section_name: section.name.to_owned(),
            })?
            .iter()
            .filter_map(|s| {
                let symbol = &self.symbol_table[s];
                symbol.name.as_ref().map(|name| (name, symbol))
            })
            .collect();

        // Section byte offset of a function pointer member -> (instance name, index
        // into the instance's func_ptrs).
        let mut func_ptr_at_section_offset: HashMap<usize, (String, usize)> = HashMap::new();

        let mut struct_ops_instances: HashMap<String, StructOpsInfo> = HashMap::new();

        // (instance name, start, end) of each instance, in bytes from the start of the section.
        let mut instance_byte_ranges: Vec<(String, usize, usize)> = Vec::new();

        let mut found_datasec = false;

        for t in btf.types() {
            if let BtfType::DataSec(datasec) = &t {
                let type_name = btf.type_name(t)?;
                if type_name == section.name {
                    found_datasec = true;

                    // each .struct_ops section should only contain VAR symbols
                    for entry in &datasec.entries {
                        let (var, s, type_id) = parse_struct_from_datasec_entry(btf, entry)?;
                        let name = btf.string_at(var.name_offset)?.to_string();
                        let func_ptrs = parse_struct_ops_func_ptrs(btf, s)?;

                        let var_symbol = name_to_sec_syms
                            .get(&name)
                            .ok_or_else(|| ParseError::SymbolNotFound { name: name.clone() })?;

                        // BPF objects are relocatable files. The ELF spec defines a symbol's
                        // values as an offset from the start of the section so section.address
                        // is 0 here.
                        let var_section_byte_offset =
                            (var_symbol.address - section.address) as usize;
                        let var_size = btf.type_size(type_id)?;

                        let data = var_section_byte_offset
                            .checked_add(var_size)
                            .and_then(|end| section.data.get(var_section_byte_offset..end))
                            .ok_or_else(|| ParseError::InvalidGlobalData {
                                name: name.clone(),
                                sym_size: var_size as u64,
                                data_size: section.data.len(),
                            })?
                            .to_vec();

                        // Instances must not share bytes of the section.
                        let var_section_byte_end = var_section_byte_offset + var_size;
                        if let Some((other_name, _, _)) =
                            instance_byte_ranges.iter().find(|(_, start, end)| {
                                var_section_byte_offset < *end && *start < var_section_byte_end
                            })
                        {
                            return Err(ParseError::StructOpsInstanceOverlap {
                                name,
                                other_name: other_name.clone(),
                            });
                        }
                        instance_byte_ranges.push((
                            name.clone(),
                            var_section_byte_offset,
                            var_section_byte_end,
                        ));

                        func_ptrs.iter().enumerate().for_each(|(index, fn_ptr)| {
                            // In bytes.
                            let fn_ptr_member_byte_offset = fn_ptr.bit_offset / 8;

                            let fn_ptr_section_byte_offset =
                                var_section_byte_offset + fn_ptr_member_byte_offset;

                            func_ptr_at_section_offset
                                .insert(fn_ptr_section_byte_offset, (name.clone(), index));
                        });

                        struct_ops_instances.insert(
                            name,
                            StructOpsInfo {
                                type_id,
                                struct_name: btf.string_at(s.name_offset)?.to_string(),
                                is_link,
                                is_optional,
                                data,
                                section_index: section.index.0,
                                symbol_index: var_symbol.index,
                                func_ptrs,
                            },
                        );
                    }
                }
            }
        }

        // Without a DATASEC there is no type info for the section's instances.
        if !found_datasec {
            return Err(BtfError::UnknownBtfTypeName {
                type_name: section.name.to_owned(),
            }
            .into());
        }

        let struct_ops_program_sections: HashSet<usize> = self
            .programs
            .iter()
            .filter(|(_, program)| matches!(program.section, ProgramSection::StructOps { .. }))
            .map(|(_, program)| program.section_index)
            .collect();

        for relocation in &section.relocations {
            let (struct_ops_name, func_ptr_index) = func_ptr_at_section_offset
                .get(&(relocation.offset as usize))
                .ok_or_else(|| ParseError::InvalidRelocation {
                    section: section.name.to_owned(),
                    offset: relocation.offset as usize,
                })?;

            let sym_at_reloc = self.symbol_table.get(&relocation.symbol_index).ok_or(
                ParseError::InvalidSymbol {
                    index: relocation.symbol_index,
                    name: None,
                },
            )?;
            if sym_at_reloc.kind != SymbolKind::Text
                || !sym_at_reloc.is_definition
                || !sym_at_reloc
                    .section_index
                    .is_some_and(|index| struct_ops_program_sections.contains(&index))
            {
                return Err(ParseError::InvalidSymbol {
                    index: sym_at_reloc.index,
                    name: sym_at_reloc.name.clone(),
                });
            }

            let sym_name = sym_at_reloc.name.clone().ok_or(ParseError::InvalidSymbol {
                index: sym_at_reloc.index,
                name: None,
            })?;

            // A program can back several instances, but only as the same
            // member of the same struct type.
            let struct_ops_instance = struct_ops_instances.get_mut(struct_ops_name).unwrap();
            let type_id = struct_ops_instance.type_id;
            let struct_ops_func_ptr = &mut struct_ops_instance.func_ptrs[*func_ptr_index];
            let attachment = StructOpsAttachment {
                type_id,
                member_name: struct_ops_func_ptr.name.clone(),
                attach_target: None,
            };
            let existing = self
                .struct_ops_attachments
                .entry(sym_name.clone())
                .or_insert_with(|| attachment.clone());
            if *existing != attachment {
                return Err(ParseError::StructOpsProgramReuse {
                    program: sym_name,
                    member_name: attachment.member_name,
                    other_member_name: existing.member_name.clone(),
                });
            }

            // Each function pointer member is filled in by at most one relocation.
            if struct_ops_func_ptr.program.replace(sym_name).is_some() {
                return Err(ParseError::InvalidRelocation {
                    section: section.name.to_owned(),
                    offset: relocation.offset as usize,
                });
            }
        }

        self.struct_ops.extend(struct_ops_instances);

        Ok(())
    }

    // Parses multiple map definition contained in a single `maps` section (which is
    // different from `.maps` which is used for BTF). We can tell where each map is
    // based on the symbol table.
    fn parse_maps_section<'a, I: Iterator<Item = &'a usize>>(
        &self,
        maps: &mut HashMap<String, Map>,
        section: &Section<'_>,
        symbols: I,
    ) -> Result<(), ParseError> {
        let mut have_symbols = false;
        // each symbol in the section is a separate map
        for i in symbols {
            let sym = self
                .symbol_table
                .get(i)
                .ok_or_else(|| ParseError::SymbolNotFound {
                    name: i.to_string(),
                })?;
            let start = sym.address as usize;
            let end = start + sym.size as usize;
            let data = &section.data[start..end];
            let name = sym
                .name
                .as_ref()
                .ok_or(ParseError::MapSymbolNameNotFound { i: *i })?;
            let def = parse_map_def(name, data)?;
            maps.insert(
                name.clone(),
                Map::Legacy(LegacyMap {
                    section_index: section.index.0,
                    section_kind: section.kind,
                    symbol_index: Some(sym.index),
                    def,
                    inner_def: None,
                    data: Vec::new(),
                    btf_value_type_id: None,
                }),
            );
            have_symbols = true;
        }
        if !have_symbols {
            return Err(ParseError::NoSymbolsForSection {
                section_name: section.name.to_owned(),
            });
        }

        Ok(())
    }

    fn parse_section(&mut self, section: Section<'_>) -> Result<(), ParseError> {
        self.section_infos
            .insert(section.name.to_owned(), (section.index, section.size));
        match section.kind {
            EbpfSectionKind::Data | EbpfSectionKind::Rodata | EbpfSectionKind::Bss => {
                let mut map = parse_data_map_section(&section);
                // The DATASEC named after the section describes its contents.
                if let (Map::Legacy(map), Some(btf)) = (&mut map, &self.btf) {
                    map.btf_value_type_id = btf
                        .id_by_type_name_kind(section.name, BtfKind::DataSec)
                        .ok();
                }
                self.maps.insert(section.name.to_string(), map);
            }
            EbpfSectionKind::Text => self.parse_text_section(section)?,
            EbpfSectionKind::Btf => self.parse_btf(&section)?,
            EbpfSectionKind::BtfExt => self.parse_btf_ext(&section)?,
            EbpfSectionKind::BtfMaps => self.parse_btf_maps(&section)?,
            EbpfSectionKind::Maps => {
                // take out self.maps so we can borrow the iterator below
                // without cloning or collecting
                let mut maps = mem::take(&mut self.maps);

                // extract the symbols for the .maps section, we'll need them
                // during parsing
                let symbols = self
                    .symbols_by_section
                    .get(&section.index)
                    .ok_or_else(|| ParseError::NoSymbolsForSection {
                        section_name: section.name.to_owned(),
                    })?
                    .iter();

                let res = self.parse_maps_section(&mut maps, &section, symbols);

                // put the maps back
                self.maps = maps;

                res?
            }
            EbpfSectionKind::Program => {
                self.parse_programs(&section)?;
                if !section.relocations.is_empty() {
                    self.relocations.insert(
                        section.index,
                        section
                            .relocations
                            .into_iter()
                            .map(|rel| (rel.offset, rel))
                            .collect(),
                    );
                }
            }
            EbpfSectionKind::StructOps => self.parse_struct_ops(&section)?,
            EbpfSectionKind::Undefined | EbpfSectionKind::License | EbpfSectionKind::Version => {}
        }

        Ok(())
    }

    /// Sanitizes BPF functions.
    pub fn sanitize_functions(&mut self, probe_read_kernel_supported: impl FnOnce() -> bool) {
        // Checking whether the kernel supports the address-space-specific probe-read
        // helpers can require loading a small BPF program. Defer the check until the
        // sanitization encounters a call to one of those helpers, then reuse the result.
        let support = LazyCell::new(probe_read_kernel_supported);
        let probe_read_kernel_supported = || *support;

        for function in self.functions.values_mut() {
            function.sanitize(&probe_read_kernel_supported);
        }
    }
}

fn insn_is_helper_call(ins: bpf_insn) -> bool {
    let klass = u32::from(ins.code & 0x07);
    let op = u32::from(ins.code & 0xF0);
    let src = u32::from(ins.code & 0x08);

    klass == BPF_JMP && op == BPF_CALL && src == BPF_K && ins.src_reg() == 0 && ins.dst_reg() == 0
}

impl Function {
    fn sanitize(&mut self, probe_read_kernel_supported: &impl Fn() -> bool) {
        const BPF_FUNC_PROBE_READ_KERNEL: i32 = bpf_func_id::BPF_FUNC_probe_read_kernel as i32;
        const BPF_FUNC_PROBE_READ_USER: i32 = bpf_func_id::BPF_FUNC_probe_read_user as i32;
        const BPF_FUNC_PROBE_READ: i32 = bpf_func_id::BPF_FUNC_probe_read as i32;
        const BPF_FUNC_PROBE_READ_KERNEL_STR: i32 =
            bpf_func_id::BPF_FUNC_probe_read_kernel_str as i32;
        const BPF_FUNC_PROBE_READ_USER_STR: i32 = bpf_func_id::BPF_FUNC_probe_read_user_str as i32;
        const BPF_FUNC_PROBE_READ_STR: i32 = bpf_func_id::BPF_FUNC_probe_read_str as i32;

        for inst in &mut self.instructions {
            if !insn_is_helper_call(*inst) {
                continue;
            }

            let fallback = match inst.imm {
                BPF_FUNC_PROBE_READ_KERNEL | BPF_FUNC_PROBE_READ_USER => BPF_FUNC_PROBE_READ,
                BPF_FUNC_PROBE_READ_KERNEL_STR | BPF_FUNC_PROBE_READ_USER_STR => {
                    BPF_FUNC_PROBE_READ_STR
                }
                _ => continue,
            };
            if !probe_read_kernel_supported() {
                inst.imm = fallback;
            }
        }
    }
}

/// Errors caught during parsing the object file
#[derive(Debug, thiserror::Error)]
#[expect(missing_docs, reason = "TODO")]
pub enum ParseError {
    #[error("error parsing ELF data")]
    ElfError(object::read::Error),

    /// Error parsing BTF object
    #[error("BTF error")]
    BtfError(#[from] BtfError),

    #[error("invalid license `{data:?}`: missing NULL terminator")]
    MissingLicenseNullTerminator { data: Vec<u8> },

    #[error("invalid license `{data:?}`")]
    InvalidLicense { data: Vec<u8> },

    #[error("invalid kernel version `{data:?}`")]
    InvalidKernelVersion { data: Vec<u8> },

    #[error("error parsing section with index {index}")]
    SectionError {
        index: usize,
        error: object::read::Error,
    },

    #[error("unsupported relocation target")]
    UnsupportedRelocationTarget,

    #[error(
        "no corresponding relocation entry found for symbol {name} in section {section} at section offset {offset:#X}"
    )]
    NoValidRelocationFound {
        section: String,
        name: String,
        offset: u64,
    },

    #[error(
        "invalid relocation entry found for section {section} corresponding to offset {offset:#X}"
    )]
    InvalidRelocation { section: String, offset: usize },

    #[error("invalid program section `{section}`")]
    InvalidProgramSection { section: String },

    #[error("invalid program code")]
    InvalidProgramCode,

    #[error("error parsing map `{name}`")]
    InvalidMapDefinition { name: String },

    #[error("two or more symbols in section `{section_index}` have the same address {address:#X}")]
    SymbolTableConflict { section_index: usize, address: u64 },

    #[error("unknown symbol in section `{section_index}` at address {address:#X}")]
    UnknownSymbol { section_index: usize, address: u64 },

    #[error("invalid symbol, index `{index}` name: {}", .name.as_deref().unwrap_or("[unknown]"))]
    InvalidSymbol { index: usize, name: Option<String> },

    #[error("symbol {name} has size `{sym_size}`, but provided data is of size `{data_size}`")]
    InvalidGlobalData {
        name: String,
        sym_size: u64,
        data_size: usize,
    },

    #[error("symbol with name {name} not found in the symbols table")]
    SymbolNotFound { name: String },

    #[error("map for section with index {index} not found")]
    MapNotFound { index: usize },

    #[error("the map number {i} in the `maps` section doesn't have a symbol name")]
    MapSymbolNameNotFound { i: usize },

    #[error("no symbols found in the {section_name} section")]
    NoSymbolsForSection { section_name: String },

    #[error(
        "struct_ops program {program} is used for member {member_name} but is already used for member {other_member_name}"
    )]
    StructOpsProgramReuse {
        program: String,
        member_name: String,
        other_member_name: String,
    },

    #[error("struct_ops instance {name} overlaps struct_ops instance {other_name}")]
    StructOpsInstanceOverlap { name: String, other_name: String },

    /// No BTF parsed for object
    #[error("no BTF parsed for object")]
    NoBTF,
}

/// Invalid bindings to the bpf type from the parsed/received value.
pub struct InvalidTypeBinding<T> {
    /// The value parsed/received.
    pub value: T,
}

/// The kind of an ELF section.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EbpfSectionKind {
    /// Undefined
    Undefined,
    /// `maps`
    Maps,
    /// `.maps`
    BtfMaps,
    /// A program section
    Program,
    /// `.data`
    Data,
    /// `.rodata`
    Rodata,
    /// `.bss`
    Bss,
    /// `.text`
    Text,
    /// `.BTF`
    Btf,
    /// `.BTF.ext`
    BtfExt,
    /// `.struct_ops`
    StructOps,
    /// `license`
    License,
    /// `version`
    Version,
}

impl EbpfSectionKind {
    fn from_name(name: &str) -> Self {
        if name.starts_with("license") {
            Self::License
        } else if name.starts_with("version") {
            Self::Version
        } else if name.starts_with("maps") {
            Self::Maps
        } else if name.starts_with(".maps") {
            Self::BtfMaps
        } else if name.starts_with(".text") {
            Self::Text
        } else if name.starts_with(".bss") {
            Self::Bss
        } else if name.starts_with(".data") {
            Self::Data
        } else if name.starts_with(".rodata") {
            Self::Rodata
        } else if name == ".struct_ops"
            || name == "?.struct_ops"
            || name == ".struct_ops.link"
            || name == "?.struct_ops.link"
        {
            Self::StructOps
        } else if name == ".BTF" {
            Self::Btf
        } else if name == ".BTF.ext" {
            Self::BtfExt
        } else {
            Self::Undefined
        }
    }
}

#[derive(Debug)]
struct Section<'a> {
    index: SectionIndex,
    kind: EbpfSectionKind,
    address: u64,
    name: &'a str,
    data: &'a [u8],
    size: u64,
    relocations: Vec<Relocation>,
}

impl<'a> TryFrom<&'a ObjSection<'_, '_>> for Section<'a> {
    type Error = ParseError;

    fn try_from(section: &'a ObjSection<'_, '_>) -> Result<Self, ParseError> {
        let index = section.index();
        let map_err = |error| ParseError::SectionError {
            index: index.0,
            error,
        };
        let name = section.name().map_err(map_err)?;
        let kind = match EbpfSectionKind::from_name(name) {
            EbpfSectionKind::Undefined => {
                if section.kind() == SectionKind::Text && section.size() > 0 {
                    EbpfSectionKind::Program
                } else {
                    EbpfSectionKind::Undefined
                }
            }
            k => k,
        };
        Ok(Section {
            index,
            kind,
            address: section.address(),
            name,
            data: section.data().map_err(map_err)?,
            size: section.size(),
            relocations: section
                .relocations()
                .map(|(offset, r)| {
                    Ok(Relocation {
                        symbol_index: match r.target() {
                            RelocationTarget::Symbol(index) => index.0,
                            _ => return Err(ParseError::UnsupportedRelocationTarget),
                        },
                        offset,
                        size: r.size(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

fn parse_license(data: &[u8]) -> Result<CString, ParseError> {
    if data.len() < 2 {
        return Err(ParseError::InvalidLicense {
            data: data.to_vec(),
        });
    }
    CStr::from_bytes_with_nul(data)
        .map_err(|err| match err {
            FromBytesWithNulError::NotNulTerminated => ParseError::MissingLicenseNullTerminator {
                data: data.to_vec(),
            },
            FromBytesWithNulError::InteriorNul { position: _ } => ParseError::InvalidLicense {
                data: data.to_vec(),
            },
        })
        .map(ToOwned::to_owned)
}

fn parse_version(data: &[u8], endianness: Endianness) -> Result<Option<u32>, ParseError> {
    let data = data
        .try_into()
        .map_err(
            |std::array::TryFromSliceError { .. }| ParseError::InvalidKernelVersion {
                data: data.to_vec(),
            },
        )?;

    let v = endianness.read_u32(data);

    Ok(if v == KERNEL_VERSION_ANY {
        None
    } else {
        Some(v)
    })
}

// Gets an integer value from a BTF map definition K/V pair.
// type_id should be a PTR to an ARRAY.
// the value is encoded in the array nr_elems field.
fn get_map_field(btf: &Btf, type_id: u32) -> Result<u32, BtfError> {
    let pty = match &btf.type_by_id(type_id)? {
        BtfType::Ptr(pty) => pty,
        other => {
            return Err(BtfError::UnexpectedBtfType {
                type_id: other.btf_type().unwrap_or(0),
            });
        }
    };
    let arr = match &btf.type_by_id(pty.btf_type)? {
        BtfType::Array(Array { array, .. }) => array,
        other => {
            return Err(BtfError::UnexpectedBtfType {
                type_id: other.btf_type().unwrap_or(0),
            });
        }
    };
    Ok(arr.len)
}

// Parse '.bss' '.data' and '.rodata' sections. These sections are arrays of
// bytes and are relocated based on their section index.
fn parse_data_map_section(section: &Section<'_>) -> Map {
    let (def, data) = match section.kind {
        EbpfSectionKind::Data | EbpfSectionKind::Rodata => {
            let def = bpf_map_def {
                map_type: BPF_MAP_TYPE_ARRAY as u32,
                key_size: size_of::<u32>() as u32,
                // We need to use section.size here since
                // .bss will always have data.len() == 0
                value_size: section.size as u32,
                max_entries: 1,
                map_flags: if section.kind == EbpfSectionKind::Rodata {
                    BPF_F_RDONLY_PROG
                } else {
                    0
                },
                ..Default::default()
            };
            (def, section.data.to_vec())
        }
        EbpfSectionKind::Bss => {
            let def = bpf_map_def {
                map_type: BPF_MAP_TYPE_ARRAY as u32,
                key_size: size_of::<u32>() as u32,
                value_size: section.size as u32,
                max_entries: 1,
                map_flags: 0,
                ..Default::default()
            };
            (def, vec![0; section.size as usize])
        }
        #[expect(clippy::unreachable, reason = "unexpected section kind")]
        kind => {
            unreachable!("unexpected section kind: {kind:?}")
        }
    };
    Map::Legacy(LegacyMap {
        section_index: section.index.0,
        section_kind: section.kind,
        // Data maps don't require symbols to be relocated
        symbol_index: None,
        def,
        inner_def: None,
        data,
        btf_value_type_id: None,
    })
}

fn parse_map_def(name: &str, data: &[u8]) -> Result<bpf_map_def, ParseError> {
    if data.len() < MINIMUM_MAP_SIZE {
        return Err(ParseError::InvalidMapDefinition {
            name: name.to_owned(),
        });
    }

    if data.len() < size_of::<bpf_map_def>() {
        let mut map_def = bpf_map_def::default();
        unsafe {
            let map_def_ptr = from_raw_parts_mut(ptr::from_mut(&mut map_def).cast(), data.len());
            map_def_ptr.copy_from_slice(data);
        }
        Ok(map_def)
    } else {
        Ok(unsafe { ptr::read_unaligned(data.as_ptr().cast()) })
    }
}

fn parse_struct_from_datasec_entry<'a>(
    btf: &'a Btf,
    entry: &DataSecEntry,
) -> Result<(&'a Var, &'a Struct, u32), BtfError> {
    let ty = match btf.type_by_id(entry.btf_type)? {
        BtfType::Var(var) => var,
        other => {
            return Err(BtfError::UnexpectedBtfType {
                type_id: other.btf_type().unwrap_or(0),
            });
        }
    };

    let root_type = btf.resolve_type(ty.btf_type)?;
    let s = match btf.type_by_id(root_type)? {
        BtfType::Struct(s) => s,
        other => {
            return Err(BtfError::UnexpectedBtfType {
                type_id: other.btf_type().unwrap_or(0),
            });
        }
    };

    Ok((ty, s, root_type))
}

fn parse_btf_map_def(
    btf: &Btf,
    info: &DataSecEntry,
) -> Result<(String, BtfMapDef, Option<BtfMapDef>), BtfError> {
    let (ty, s, _) = parse_struct_from_datasec_entry(btf, info)?;
    let map_name = btf.string_at(ty.name_offset)?;
    let (map_def, inner_def) = parse_btf_map_struct(btf, s, &map_name, false)?;
    Ok((map_name.to_string(), map_def, inner_def))
}

/// Returns the members of a `struct_ops` struct type that are function pointers.
fn parse_struct_ops_func_ptrs(
    btf: &Btf,
    s: &Struct,
) -> Result<Vec<StructOpsFnPtrMember>, BtfError> {
    let mut func_ptrs = Vec::new();

    for m in &s.members {
        // Skip typedefs and modifiers (const, volatile, ...) on the member's
        // type, and again on the type it points to.
        let member_type_id = btf.resolve_type(m.btf_type)?;
        if let BtfType::Ptr(pty) = btf.type_by_id(member_type_id)? {
            let pointee_type_id = btf.resolve_type(pty.btf_type)?;
            // Function pointer
            if let BtfType::FuncProto(_) = btf.type_by_id(pointee_type_id)? {
                let func_ptr_member_name = btf.string_at(m.name_offset)?.to_string();

                func_ptrs.push(StructOpsFnPtrMember {
                    bit_offset: Struct::member_bit_offset(s, m),
                    name: func_ptr_member_name,
                    program: None,
                });
            }
        }
    }

    Ok(func_ptrs)
}

/// Parses BTF struct members into a map definition.
///
/// When `is_inner` is true, rejects `values` and `pinning` fields, matching
/// libbpf behavior for inner map definitions.
fn parse_btf_map_struct(
    btf: &Btf,
    s: &Struct,
    map_name: &str,
    is_inner: bool,
) -> Result<(BtfMapDef, Option<BtfMapDef>), BtfError> {
    let mut map_def = BtfMapDef::default();
    let mut inner_map_def = None;

    for m in &s.members {
        match btf.string_at(m.name_offset)?.as_ref() {
            "type" => {
                map_def.map_type = get_map_field(btf, m.btf_type)?;
            }
            "key" => {
                if let BtfType::Ptr(pty) = btf.type_by_id(m.btf_type)? {
                    let t = pty.btf_type;
                    map_def.key_size = btf.type_size(t)? as u32;
                    map_def.btf_key_type_id = t;
                } else {
                    return Err(BtfError::UnexpectedBtfType {
                        type_id: m.btf_type,
                    });
                }
            }
            "key_size" => {
                map_def.key_size = get_map_field(btf, m.btf_type)?;
            }
            "value" => {
                if let BtfType::Ptr(pty) = btf.type_by_id(m.btf_type)? {
                    let t = pty.btf_type;
                    map_def.value_size = btf.type_size(t)? as u32;
                    map_def.btf_value_type_id = t;
                } else {
                    return Err(BtfError::UnexpectedBtfType {
                        type_id: m.btf_type,
                    });
                }
            }
            "value_size" => {
                map_def.value_size = get_map_field(btf, m.btf_type)?;
            }
            "max_entries" => {
                map_def.max_entries = get_map_field(btf, m.btf_type)?;
            }
            "map_flags" => {
                map_def.map_flags = get_map_field(btf, m.btf_type)?;
            }
            "map_extra" => {
                map_def.map_extra = get_map_field(btf, m.btf_type)?.into();
            }
            "pinning" => {
                if is_inner {
                    return Err(BtfError::InnerMapCannotBePinned {
                        name: map_name.to_owned(),
                    });
                }
                let pinning = get_map_field(btf, m.btf_type)?;
                map_def.pinning = PinningType::try_from(pinning).unwrap_or_else(|_| {
                    debug!("{pinning} is not a valid pin type. using PIN_NONE");
                    PinningType::None
                });
            }
            "values" => {
                if is_inner {
                    return Err(BtfError::MultiLevelMapInMapNotSupported {
                        name: map_name.to_owned(),
                    });
                }
                // The inner map type is encoded as a zero-length array of pointers
                // to the inner struct, matching libbpf's parse_btf_map_def().
                let arr = match btf.type_by_id(m.btf_type)? {
                    BtfType::Array(Array { array, .. }) => array,
                    other => {
                        return Err(BtfError::UnexpectedBtfType {
                            type_id: other.btf_type().unwrap_or(0),
                        });
                    }
                };
                if arr.len != 0 {
                    return Err(BtfError::InvalidValuesSpec {
                        name: map_name.to_owned(),
                    });
                }
                let elem_type_id = btf.resolve_type(arr.element_type)?;
                let ptr = match btf.type_by_id(elem_type_id)? {
                    BtfType::Ptr(ptr) => ptr,
                    other => {
                        return Err(BtfError::UnexpectedBtfType {
                            type_id: other.btf_type().unwrap_or(0),
                        });
                    }
                };
                let inner_struct_id = btf.resolve_type(ptr.btf_type)?;
                let inner_s = match btf.type_by_id(inner_struct_id)? {
                    BtfType::Struct(s) => s,
                    other => {
                        return Err(BtfError::UnexpectedBtfType {
                            type_id: other.btf_type().unwrap_or(0),
                        });
                    }
                };
                let (inner_def, _) = parse_btf_map_struct(btf, inner_s, map_name, true)?;
                inner_map_def = Some(inner_def);
                // Map-of-maps value is always an fd (u32).
                map_def.value_size = size_of::<u32>() as u32;
            }
            other => {
                debug!("skipping unknown map section: {other}");
            }
        }
    }
    Ok((map_def, inner_map_def))
}

/// Parses a [`bpf_map_info`] into a [`Map`].
pub const fn parse_map_info(info: bpf_map_info, pinned: PinningType) -> Map {
    // Some BTF maps are keyless, for example bloom filters, and may only set
    // `btf_value_type_id`. Checking the value type avoids treating those maps
    // as legacy maps.
    if info.btf_value_type_id != 0 {
        Map::Btf(BtfMap {
            def: BtfMapDef {
                map_type: info.type_,
                key_size: info.key_size,
                value_size: info.value_size,
                max_entries: info.max_entries,
                map_flags: info.map_flags,
                map_extra: info.map_extra,
                pinning: pinned,
                btf_key_type_id: info.btf_key_type_id,
                btf_value_type_id: info.btf_value_type_id,
            },
            inner_def: None,
            section_index: 0,
            symbol_index: 0,
            data: Vec::new(),
        })
    } else {
        Map::Legacy(LegacyMap {
            def: bpf_map_def {
                map_type: info.type_,
                key_size: info.key_size,
                value_size: info.value_size,
                max_entries: info.max_entries,
                map_flags: info.map_flags,
                pinning: pinned,
                id: info.id,
            },
            inner_def: None,
            section_index: 0,
            symbol_index: None,
            section_kind: EbpfSectionKind::Undefined,
            data: Vec::new(),
            btf_value_type_id: None,
        })
    }
}

/// Copies a block of eBPF instructions
pub fn copy_instructions(data: &[u8]) -> Result<Vec<bpf_insn>, ParseError> {
    let (chunks, tail) = data.as_chunks::<{ size_of::<bpf_insn>() }>();
    if !tail.is_empty() {
        return Err(ParseError::InvalidProgramCode);
    }
    let instructions = chunks
        .iter()
        .map(|d| unsafe { ptr::read_unaligned(d.as_ptr().cast()) })
        .collect::<Vec<_>>();
    Ok(instructions)
}

fn get_func_and_line_info(
    btf_ext: Option<&BtfExt>,
    symbol: &Symbol,
    section: &Section<'_>,
    offset: usize,
    rewrite_insn_off: bool,
) -> (FuncSecInfo, LineSecInfo, usize, usize) {
    btf_ext.map_or_default(|btf_ext| {
        let instruction_offset = (offset / INS_SIZE) as u32;
        let symbol_size_instructions = (symbol.size as usize / INS_SIZE) as u32;

        let mut func_info = btf_ext.func_info.get(section.name);
        func_info.func_info.retain_mut(|f| {
            let retain = f.insn_off == instruction_offset;
            if retain && rewrite_insn_off {
                f.insn_off = 0;
            }
            retain
        });

        let mut line_info = btf_ext.line_info.get(section.name);
        line_info
            .line_info
            .retain_mut(|l| match l.insn_off.checked_sub(instruction_offset) {
                None => false,
                Some(insn_off) => {
                    let retain = insn_off < symbol_size_instructions;
                    if retain && rewrite_insn_off {
                        l.insn_off = insn_off
                    }
                    retain
                }
            });
        (
            func_info,
            line_info,
            btf_ext.func_info_rec_size(),
            btf_ext.line_info_rec_size(),
        )
    })
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::{
        btf::{self, BtfFeature, DataSec, FuncProto},
        generated::{bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER, btf_ext_header},
    };

    const FAKE_INS_LEN: u64 = 8;

    fn fake_section<'a>(
        kind: EbpfSectionKind,
        name: &'a str,
        data: &'a [u8],
        index: Option<usize>,
    ) -> Section<'a> {
        let idx = index.unwrap_or(0);
        Section {
            index: SectionIndex(idx),
            kind,
            address: 0,
            name,
            data,
            size: data.len() as u64,
            relocations: Vec::new(),
        }
    }

    fn fake_ins() -> bpf_insn {
        bpf_insn {
            code: 0,
            _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
            off: 0,
            imm: 0,
        }
    }

    fn fake_sym(
        obj: &mut Object,
        section_index: usize,
        address: u64,
        name: &str,
        size: u64,
    ) -> usize {
        fake_sym_with_kind(obj, section_index, SymbolKind::Text, address, name, size)
    }

    fn fake_sym_with_kind(
        obj: &mut Object,
        section_index: usize,
        kind: SymbolKind,
        address: u64,
        name: &str,
        size: u64,
    ) -> usize {
        let idx = obj.symbol_table.len();
        obj.symbol_table.insert(
            idx + 1,
            Symbol {
                index: idx + 1,
                section_index: Some(section_index),
                name: Some(name.to_string()),
                address,
                size,
                is_definition: true,
                kind,
                is_weak: false,
            },
        );
        obj.symbols_by_section
            .entry(SectionIndex(section_index))
            .or_default()
            .push(idx + 1);

        idx + 1
    }

    fn bytes_of<T>(val: &T) -> &[u8] {
        // Safety: This is for testing only
        unsafe { crate::util::bytes_of(val) }
    }

    #[test]
    fn test_parse_map_info_keyless_btf_map() {
        let mut info = unsafe { mem::zeroed::<bpf_map_info>() };
        info.type_ = BPF_MAP_TYPE_BLOOM_FILTER as u32;
        info.value_size = 4;
        info.max_entries = 64;
        info.map_extra = 3;
        info.btf_value_type_id = 7;

        let map = parse_map_info(info, PinningType::None);
        assert_matches!(map, Map::Btf(m) => {
            assert_eq!(m.def.map_type, BPF_MAP_TYPE_BLOOM_FILTER as u32);
            assert_eq!(m.def.key_size, 0);
            assert_eq!(m.def.value_size, 4);
            assert_eq!(m.def.max_entries, 64);
            assert_eq!(m.def.map_extra, 3);
            assert_eq!(m.def.btf_key_type_id, 0);
            assert_eq!(m.def.btf_value_type_id, 7);
        });
    }

    #[test]
    fn test_parse_generic_error() {
        assert_matches!(Object::parse(&b"foo"[..]), Err(ParseError::ElfError(_)))
    }

    #[test]
    fn test_parse_license() {
        assert_matches!(parse_license(b""), Err(ParseError::InvalidLicense { .. }));

        assert_matches!(parse_license(b"\0"), Err(ParseError::InvalidLicense { .. }));

        assert_matches!(
            parse_license(b"GPL"),
            Err(ParseError::MissingLicenseNullTerminator { .. })
        );

        assert_eq!(parse_license(b"GPL\0").unwrap().to_str().unwrap(), "GPL");
    }

    #[expect(
        clippy::big_endian_bytes,
        clippy::little_endian_bytes,
        reason = "that's the point"
    )]
    #[test]
    fn test_parse_version() {
        assert_matches!(
            parse_version(b"", Endianness::Little),
            Err(ParseError::InvalidKernelVersion { .. })
        );

        assert_matches!(
            parse_version(b"123", Endianness::Little),
            Err(ParseError::InvalidKernelVersion { .. })
        );

        assert_matches!(
            parse_version(&0xFFFF_FFFEu32.to_le_bytes(), Endianness::Little),
            Ok(None)
        );

        assert_matches!(
            parse_version(&0xFFFF_FFFEu32.to_be_bytes(), Endianness::Big),
            Ok(None)
        );

        assert_matches!(
            parse_version(&1234u32.to_le_bytes(), Endianness::Little),
            Ok(Some(1234))
        );
    }

    #[test]
    fn test_parse_map_def_error() {
        assert_matches!(
            parse_map_def("foo", &[]),
            Err(ParseError::InvalidMapDefinition { .. })
        );
    }

    #[test]
    fn test_parse_map_short() {
        let def = bpf_map_def {
            map_type: 1,
            key_size: 2,
            value_size: 3,
            max_entries: 4,
            map_flags: 5,
            id: 0,
            pinning: PinningType::None,
        };

        assert_eq!(
            parse_map_def("foo", &bytes_of(&def)[..MINIMUM_MAP_SIZE]).unwrap(),
            def
        );
    }

    #[test]
    fn test_parse_map_def() {
        let def = bpf_map_def {
            map_type: 1,
            key_size: 2,
            value_size: 3,
            max_entries: 4,
            map_flags: 5,
            id: 6,
            pinning: PinningType::ByName,
        };

        assert_eq!(parse_map_def("foo", bytes_of(&def)).unwrap(), def);
    }

    #[test]
    fn test_parse_map_def_with_padding() {
        let def = bpf_map_def {
            map_type: 1,
            key_size: 2,
            value_size: 3,
            max_entries: 4,
            map_flags: 5,
            id: 6,
            pinning: PinningType::ByName,
        };
        let mut buf = [0u8; 128];
        unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast(), def) }

        assert_eq!(parse_map_def("foo", &buf).unwrap(), def);
    }

    #[test]
    fn test_parse_map_data() {
        let map_data = b"map data";
        assert_matches!(
            parse_data_map_section(
                &fake_section(
                    EbpfSectionKind::Data,
                    ".bss",
                    map_data,
                    None,
                ),
            ),
            Map::Legacy(LegacyMap {
                section_index: 0,
                section_kind: EbpfSectionKind::Data,
                symbol_index: None,
                def: bpf_map_def {
                    map_type: _map_type,
                    key_size: 4,
                    value_size,
                    max_entries: 1,
                    map_flags: 0,
                    id: 0,
                    pinning: PinningType::None,
                },
                data,
                btf_value_type_id: None,
                ..
            }) if data == map_data && value_size == map_data.len() as u32
        )
    }

    fn fake_obj() -> Object {
        Object::new(Endianness::Little, CString::new("GPL").unwrap(), None)
    }

    #[test]
    fn sanitizes_empty_btf_files_to_none() {
        let mut obj = fake_obj();

        let btf = Btf::new();
        let btf_bytes = btf.to_bytes();
        obj.parse_section(fake_section(EbpfSectionKind::Btf, ".BTF", &btf_bytes, None))
            .unwrap();

        const FUNC_INFO_LEN: u32 = 4;
        const LINE_INFO_LEN: u32 = 4;
        const CORE_RELO_LEN: u32 = 16;
        let ext_header = btf_ext_header {
            magic: 0xeb9f,
            version: 1,
            flags: 0,
            hdr_len: 24,
            func_info_off: 0,
            func_info_len: FUNC_INFO_LEN,
            line_info_off: FUNC_INFO_LEN,
            line_info_len: LINE_INFO_LEN,
            core_relo_off: FUNC_INFO_LEN + LINE_INFO_LEN,
            core_relo_len: CORE_RELO_LEN,
        };
        let btf_ext_bytes = bytes_of::<btf_ext_header>(&ext_header).to_vec();
        obj.parse_section(fake_section(
            EbpfSectionKind::BtfExt,
            ".BTF.ext",
            &btf_ext_bytes,
            None,
        ))
        .unwrap();

        let btf = obj
            .fixup_and_sanitize_btf(|| Some(|_: BtfFeature| false))
            .unwrap();
        assert!(btf.is_none());
    }

    #[test]
    fn test_parse_program_error() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", 1);
        assert_matches!(
            obj.parse_programs(&fake_section(
                EbpfSectionKind::Program,
                "kprobe/foo",
                &42u32.to_ne_bytes(),
                None,
            )),
            Err(ParseError::InvalidProgramCode)
        );
    }

    #[test]
    fn test_parse_program() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        obj.parse_programs(&fake_section(
            EbpfSectionKind::Program,
            "kprobe/foo",
            bytes_of(&fake_ins()),
            None,
        ))
        .unwrap();

        let prog_foo = &obj.programs["foo"];

        assert_matches!(prog_foo, Program {
            license,
            kernel_version: None,
            section: ProgramSection::KProbe,
            ..
        } => assert_eq!(license.to_str().unwrap(), "GPL"));

        assert_matches!(
            obj.functions.get(&prog_foo.function_key()),
            Some(Function {
                name,
                address: 0,
                section_index: SectionIndex(0),
                section_offset: 0,
                instructions,
            ..}) if name == "foo" && instructions.len() == 1
        )
    }

    #[test]
    fn test_parse_section_map() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", size_of::<bpf_map_def>() as u64);
        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Maps,
                "maps/foo",
                bytes_of(&bpf_map_def {
                    map_type: 1,
                    key_size: 2,
                    value_size: 3,
                    max_entries: 4,
                    map_flags: 5,
                    ..Default::default()
                }),
                None,
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key("foo"));
    }

    #[test]
    fn test_parse_multiple_program_in_same_section() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);
        fake_sym(&mut obj, 0, FAKE_INS_LEN, "bar", FAKE_INS_LEN);

        let insns = [fake_ins(), fake_ins()];
        let data = bytes_of(&insns);

        obj.parse_programs(&fake_section(
            EbpfSectionKind::Program,
            "kprobe",
            data,
            None,
        ))
        .unwrap();

        let prog_foo = &obj.programs["foo"];
        let function_foo = &obj.functions[&prog_foo.function_key()];
        let prog_bar = &obj.programs["bar"];
        let function_bar = &obj.functions[&prog_bar.function_key()];

        assert_matches!(prog_foo, Program {
            license,
            kernel_version: None,
            section: ProgramSection::KProbe,
            ..
        } => assert_eq!(license.to_str().unwrap(), "GPL"));
        assert_matches!(
            function_foo,
            Function {
                name,
                address: 0,
                section_index: SectionIndex(0),
                section_offset: 0,
                instructions,
                ..
            }  if name == "foo" && instructions.len() == 1
        );

        assert_matches!(prog_bar, Program {
            license,
            kernel_version: None,
            section: ProgramSection::KProbe ,
            ..
        } => assert_eq!(license.to_str().unwrap(), "GPL"));
        assert_matches!(
            function_bar,
            Function {
                name,
                address: 8,
                section_index: SectionIndex(0),
                section_offset: 8,
                instructions,
                ..
            }  if name == "bar" && instructions.len() == 1
        );
    }

    #[test]
    fn test_parse_section_multiple_maps() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", size_of::<bpf_map_def>() as u64);
        fake_sym(&mut obj, 0, 28, "bar", size_of::<bpf_map_def>() as u64);
        fake_sym(&mut obj, 0, 60, "baz", size_of::<bpf_map_def>() as u64);
        let def = &bpf_map_def {
            map_type: 1,
            key_size: 2,
            value_size: 3,
            max_entries: 4,
            map_flags: 5,
            ..Default::default()
        };
        let map_data = bytes_of(def).to_vec();
        let mut buf = vec![];
        buf.extend(&map_data);
        buf.extend(&map_data);
        // throw in some padding
        buf.extend([0, 0, 0, 0]);
        buf.extend(&map_data);
        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Maps,
                "maps",
                buf.as_slice(),
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key("foo"));
        assert!(obj.maps.contains_key("bar"));
        assert!(obj.maps.contains_key("baz"));
        for map in obj.maps.values() {
            assert_matches!(map, Map::Legacy(m) => {
                assert_eq!(&m.def, def);
            })
        }
    }

    #[test]
    fn test_parse_section_data() {
        let mut obj = fake_obj();
        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".bss",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".bss"));

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".rodata",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".rodata"));

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".rodata.boo",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".rodata.boo"));

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".data",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".data"));

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Data,
                ".data.boo",
                b"map data",
                None
            )),
            Ok(())
        );
        assert!(obj.maps.contains_key(".data.boo"));
    }

    #[test]
    fn test_parse_section_kprobe() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "kprobe/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::KProbe,
                ..
            })
        );
    }

    #[rstest]
    #[case::uprobe_plain(
        "uprobe/foo",
        ProgramSection::UProbe { sleepable: false, multi: false }
    )]
    #[case::uprobe_sleepable(
        "uprobe.s/foo",
        ProgramSection::UProbe { sleepable: true, multi: false }
    )]
    #[case::uprobe_multi(
        "uprobe.multi/foo",
        ProgramSection::UProbe { sleepable: false, multi: true }
    )]
    #[case::uprobe_multi_sleepable(
        "uprobe.multi.s/foo",
        ProgramSection::UProbe { sleepable: true, multi: true }
    )]
    #[case::uretprobe_plain(
        "uretprobe/foo",
        ProgramSection::URetProbe { sleepable: false, multi: false }
    )]
    #[case::uretprobe_sleepable(
        "uretprobe.s/foo",
        ProgramSection::URetProbe { sleepable: true, multi: false }
    )]
    #[case::uretprobe_multi(
        "uretprobe.multi/foo",
        ProgramSection::URetProbe { sleepable: false, multi: true }
    )]
    #[case::uretprobe_multi_sleepable(
        "uretprobe.multi.s/foo",
        ProgramSection::URetProbe { sleepable: true, multi: true }
    )]
    fn test_parse_section_user_probe(
        #[case] section: &str,
        #[case] expected_section: ProgramSection,
    ) {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                section,
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        let program = obj.programs.remove("foo").unwrap();
        assert_matches!((program.section, expected_section),
            (
                ProgramSection::UProbe {
                    sleepable: actual_sleepable,
                    multi: actual_multi,
                },
                ProgramSection::UProbe { sleepable, multi },
            )
            | (
                ProgramSection::URetProbe {
                    sleepable: actual_sleepable,
                    multi: actual_multi,
                },
                ProgramSection::URetProbe { sleepable, multi },
            ) => assert_eq!((actual_sleepable, actual_multi), (sleepable, multi))
        );
    }

    #[test]
    fn test_parse_section_trace_point() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);
        fake_sym(&mut obj, 1, 0, "bar", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "tracepoint/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::TracePoint,
                ..
            })
        );

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "tp/foo/bar",
                bytes_of(&fake_ins()),
                Some(1),
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("bar"),
            Some(Program {
                section: ProgramSection::TracePoint,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_socket_filter() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "socket/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::SocketFilter,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_xdp() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "xdp",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Xdp { frags: false, .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_xdp_frags() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "xdp.frags",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Xdp { frags: true, .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_struct_ops() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "struct_ops/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::StructOps { sleepable: false },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_struct_ops_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "bar", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "struct_ops.s/bar",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("bar"),
            Some(Program {
                section: ProgramSection::StructOps { sleepable: true },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sk_reuseport() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "sk_reuseport",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::SkReuseport {
                    attach_type: SkReuseportAttachType::Select,
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sk_reuseport_migrate() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "sk_reuseport/migrate",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::SkReuseport {
                    attach_type: SkReuseportAttachType::SelectOrMigrate,
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_raw_tp() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);
        fake_sym(&mut obj, 1, 0, "bar", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "raw_tp/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::RawTracePoint,
                ..
            })
        );

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "raw_tracepoint/bar",
                bytes_of(&fake_ins()),
                Some(1)
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("bar"),
            Some(Program {
                section: ProgramSection::RawTracePoint,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_lsm() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "lsm/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Lsm { sleepable: false },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_lsm_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "lsm.s/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::Lsm {
                    sleepable: true,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_lsm_cgroup() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "lsm_cgroup/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::LsmCgroup,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_data_btf_value_type() {
        let mut obj = fake_obj();

        // Only `.data.described` has a DATASEC.
        let mut btf = Btf::new();
        let name_offset = btf.add_string(".data.described");
        let datasec_id = btf.add_type(BtfType::DataSec(DataSec::new(name_offset, Vec::new(), 8)));
        let btf_data = btf.to_bytes();
        obj.parse_section(fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None))
            .unwrap();

        for name in [".data.described", ".data.plain"] {
            obj.parse_section(fake_section(EbpfSectionKind::Data, name, b"map data", None))
                .unwrap();
        }

        assert_matches!(
            &obj.maps[".data.described"],
            Map::Legacy(LegacyMap { btf_value_type_id, .. })
                if *btf_value_type_id == Some(datasec_id)
        );
        assert_matches!(
            &obj.maps[".data.plain"],
            Map::Legacy(LegacyMap {
                btf_value_type_id: None,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_btf_tracepoint() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "tp_btf/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::BtfTracePoint,
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_skskb_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "stream_parser", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "sk_skb/stream_parser",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("stream_parser"),
            Some(Program {
                section: ProgramSection::SkSkbStream {
                    kind: SkSkbKind::StreamParser
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_skskb_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "my_parser", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "sk_skb/stream_parser/my_parser",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("my_parser"),
            Some(Program {
                section: ProgramSection::SkSkbStream {
                    kind: SkSkbKind::StreamParser
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_fentry() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "fentry/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::FEntry { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_fentry_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "fentry.s/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::FEntry {
                    sleepable: true,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_fexit() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "fexit/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::FExit { .. },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_fexit_sleepable() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "fexit.s/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::FExit {
                    sleepable: true,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_cgroup_skb_ingress_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "ingress", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup_skb/ingress",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("ingress"),
            Some(Program {
                section: ProgramSection::CgroupSkb {
                    attach_type: Some(CgroupSkbAttachType::Ingress),
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_cgroup_skb_ingress_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup_skb/ingress/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::CgroupSkb {
                    attach_type: Some(CgroupSkbAttachType::Ingress),
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_cgroup_skb_no_direction_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "skb", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/skb",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("skb"),
            Some(Program {
                section: ProgramSection::CgroupSkb { attach_type: None },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_cgroup_skb_no_direction_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/skb/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::CgroupSkb { attach_type: None },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sock_addr_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/connect4/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::CgroupSockAddr {
                    attach_type: CgroupSockAddrAttachType::Connect4,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sock_addr_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "connect4", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/connect4",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("connect4"),
            Some(Program {
                section: ProgramSection::CgroupSockAddr {
                    attach_type: CgroupSockAddrAttachType::Connect4,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sockopt_named() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "foo", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/getsockopt/foo",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("foo"),
            Some(Program {
                section: ProgramSection::CgroupSockopt {
                    attach_type: CgroupSockoptAttachType::Get,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_parse_section_sockopt_unnamed() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "getsockopt", FAKE_INS_LEN);

        assert_matches!(
            obj.parse_section(fake_section(
                EbpfSectionKind::Program,
                "cgroup/getsockopt",
                bytes_of(&fake_ins()),
                None
            )),
            Ok(())
        );
        assert_matches!(
            obj.programs.get("getsockopt"),
            Some(Program {
                section: ProgramSection::CgroupSockopt {
                    attach_type: CgroupSockoptAttachType::Get,
                    ..
                },
                ..
            })
        );
    }

    #[test]
    fn test_patch_map_data() {
        let mut obj = fake_obj();
        obj.maps.insert(
            ".rodata".to_owned(),
            Map::Legacy(LegacyMap {
                def: bpf_map_def {
                    map_type: BPF_MAP_TYPE_ARRAY as u32,
                    key_size: size_of::<u32>() as u32,
                    value_size: 3,
                    max_entries: 1,
                    map_flags: BPF_F_RDONLY_PROG,
                    id: 1,
                    pinning: PinningType::None,
                },
                inner_def: None,
                section_index: 1,
                section_kind: EbpfSectionKind::Rodata,
                symbol_index: Some(1),
                data: vec![0, 0, 0],
                btf_value_type_id: None,
            }),
        );
        obj.symbol_table.insert(
            1,
            Symbol {
                index: 1,
                section_index: Some(1),
                name: Some("my_config".to_owned()),
                address: 0,
                size: 3,
                is_definition: true,
                kind: SymbolKind::Data,
                is_weak: false,
            },
        );

        let test_data: &[u8] = &[1, 2, 3];
        obj.patch_map_data(HashMap::from([
            ("my_config", (test_data, true)),
            ("optional_variable", (test_data, false)),
        ]))
        .unwrap();

        let map = &obj.maps[".rodata"];
        assert_eq!(test_data, map.data());
    }

    #[test]
    fn test_parse_btf_map_section() {
        let mut obj = fake_obj();
        fake_sym(&mut obj, 0, 0, "map_1", 0);
        fake_sym(&mut obj, 0, 0, "map_2", 0);
        // generated from:
        // objcopy --dump-section .BTF=test.btf ./target/bpfel-unknown-none/debug/multimap-btf.bpf.o
        // hexdump -v  -e '7/1 "0x%02X, " 1/1  " 0x%02X,\n"' test.btf
        let data: &[u8] = cfg_select! {
            target_endian = "little" => &[
                0x9F, 0xEB, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x01,
                0x00, 0x00, 0xF0, 0x01, 0x00, 0x00, 0xCC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02, 0x06, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                0x07, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
                0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                0x09, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x0A, 0x00,
                0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0C, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x04, 0x00, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x05, 0x00,
                0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                0x80, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xC0, 0x00,
                0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x0D, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x04, 0x20, 0x00,
                0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x4A, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x4E, 0x00,
                0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00,
                0x0B, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
                0x70, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0C, 0x12, 0x00, 0x00, 0x00, 0xB0, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,
                0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xB5, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x0E, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xBE, 0x01,
                0x00, 0x00, 0x02, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xC4, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0F,
                0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x69, 0x6E, 0x74, 0x00, 0x5F, 0x5F, 0x41, 0x52, 0x52, 0x41, 0x59,
                0x5F, 0x53, 0x49, 0x5A, 0x45, 0x5F, 0x54, 0x59, 0x50, 0x45, 0x5F, 0x5F, 0x00, 0x5F,
                0x5F, 0x75, 0x33, 0x32, 0x00, 0x75, 0x6E, 0x73, 0x69, 0x67, 0x6E, 0x65, 0x64, 0x20,
                0x69, 0x6E, 0x74, 0x00, 0x5F, 0x5F, 0x75, 0x36, 0x34, 0x00, 0x75, 0x6E, 0x73, 0x69,
                0x67, 0x6E, 0x65, 0x64, 0x20, 0x6C, 0x6F, 0x6E, 0x67, 0x20, 0x6C, 0x6F, 0x6E, 0x67,
                0x00, 0x74, 0x79, 0x70, 0x65, 0x00, 0x6B, 0x65, 0x79, 0x00, 0x76, 0x61, 0x6C, 0x75,
                0x65, 0x00, 0x6D, 0x61, 0x78, 0x5F, 0x65, 0x6E, 0x74, 0x72, 0x69, 0x65, 0x73, 0x00,
                0x6D, 0x61, 0x70, 0x5F, 0x31, 0x00, 0x6D, 0x61, 0x70, 0x5F, 0x32, 0x00, 0x63, 0x74,
                0x78, 0x00, 0x62, 0x70, 0x66, 0x5F, 0x70, 0x72, 0x6F, 0x67, 0x00, 0x74, 0x72, 0x61,
                0x63, 0x65, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x00, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x68,
                0x6F, 0x6D, 0x65, 0x2F, 0x64, 0x61, 0x76, 0x65, 0x2F, 0x64, 0x65, 0x76, 0x2F, 0x61,
                0x79, 0x61, 0x2D, 0x72, 0x73, 0x2F, 0x61, 0x79, 0x61, 0x2F, 0x74, 0x65, 0x73, 0x74,
                0x2F, 0x69, 0x6E, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2D, 0x65,
                0x62, 0x70, 0x66, 0x2F, 0x73, 0x72, 0x63, 0x2F, 0x62, 0x70, 0x66, 0x2F, 0x6D, 0x75,
                0x6C, 0x74, 0x69, 0x6D, 0x61, 0x70, 0x2D, 0x62, 0x74, 0x66, 0x2E, 0x62, 0x70, 0x66,
                0x2E, 0x63, 0x00, 0x69, 0x6E, 0x74, 0x20, 0x62, 0x70, 0x66, 0x5F, 0x70, 0x72, 0x6F,
                0x67, 0x28, 0x76, 0x6F, 0x69, 0x64, 0x20, 0x2A, 0x63, 0x74, 0x78, 0x29, 0x00, 0x09,
                0x5F, 0x5F, 0x75, 0x33, 0x32, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x3D, 0x20, 0x30, 0x3B,
                0x00, 0x09, 0x5F, 0x5F, 0x75, 0x36, 0x34, 0x20, 0x74, 0x77, 0x65, 0x6E, 0x74, 0x79,
                0x5F, 0x66, 0x6F, 0x75, 0x72, 0x20, 0x3D, 0x20, 0x32, 0x34, 0x3B, 0x00, 0x09, 0x5F,
                0x5F, 0x75, 0x36, 0x34, 0x20, 0x66, 0x6F, 0x72, 0x74, 0x79, 0x5F, 0x74, 0x77, 0x6F,
                0x20, 0x3D, 0x20, 0x34, 0x32, 0x3B, 0x00, 0x20, 0x20, 0x20, 0x20, 0x62, 0x70, 0x66,
                0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5F, 0x65, 0x6C,
                0x65, 0x6D, 0x28, 0x26, 0x6D, 0x61, 0x70, 0x5F, 0x31, 0x2C, 0x20, 0x26, 0x6B, 0x65,
                0x79, 0x2C, 0x20, 0x26, 0x74, 0x77, 0x65, 0x6E, 0x74, 0x79, 0x5F, 0x66, 0x6F, 0x75,
                0x72, 0x2C, 0x20, 0x42, 0x50, 0x46, 0x5F, 0x41, 0x4E, 0x59, 0x29, 0x3B, 0x00, 0x20,
                0x20, 0x20, 0x20, 0x62, 0x70, 0x66, 0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64,
                0x61, 0x74, 0x65, 0x5F, 0x65, 0x6C, 0x65, 0x6D, 0x28, 0x26, 0x6D, 0x61, 0x70, 0x5F,
                0x32, 0x2C, 0x20, 0x26, 0x6B, 0x65, 0x79, 0x2C, 0x20, 0x26, 0x66, 0x6F, 0x72, 0x74,
                0x79, 0x5F, 0x74, 0x77, 0x6F, 0x2C, 0x20, 0x42, 0x50, 0x46, 0x5F, 0x41, 0x4E, 0x59,
                0x29, 0x3B, 0x00, 0x09, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6E, 0x20, 0x30, 0x3B, 0x00,
                0x63, 0x68, 0x61, 0x72, 0x00, 0x5F, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x00,
                0x2E, 0x6D, 0x61, 0x70, 0x73, 0x00, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x00,
            ],
            target_endian = "big" => &[
                0xEB, 0x9F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0xF0, 0x00, 0x00, 0x01, 0xF0, 0x00, 0x00, 0x01, 0xCC, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
                0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x19, 0x08, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x1F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x2C, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x0A, 0x00, 0x00, 0x00, 0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x45,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00,
                0x00, 0x05, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x08,
                0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00,
                0x00, 0xC0, 0x00, 0x00, 0x00, 0x60, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00,
                0x00, 0x20, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
                0x00, 0x4E, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x54,
                0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x66, 0x0E, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x11,
                0x00, 0x00, 0x00, 0x70, 0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00,
                0x01, 0xB0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x08,
                0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x14, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x01, 0xB5,
                0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x01, 0xBE, 0x0F, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0xC4, 0x0F, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x04, 0x00, 0x69, 0x6E, 0x74, 0x00, 0x5F, 0x5F, 0x41, 0x52, 0x52, 0x41, 0x59,
                0x5F, 0x53, 0x49, 0x5A, 0x45, 0x5F, 0x54, 0x59, 0x50, 0x45, 0x5F, 0x5F, 0x00, 0x5F,
                0x5F, 0x75, 0x33, 0x32, 0x00, 0x75, 0x6E, 0x73, 0x69, 0x67, 0x6E, 0x65, 0x64, 0x20,
                0x69, 0x6E, 0x74, 0x00, 0x5F, 0x5F, 0x75, 0x36, 0x34, 0x00, 0x75, 0x6E, 0x73, 0x69,
                0x67, 0x6E, 0x65, 0x64, 0x20, 0x6C, 0x6F, 0x6E, 0x67, 0x20, 0x6C, 0x6F, 0x6E, 0x67,
                0x00, 0x74, 0x79, 0x70, 0x65, 0x00, 0x6B, 0x65, 0x79, 0x00, 0x76, 0x61, 0x6C, 0x75,
                0x65, 0x00, 0x6D, 0x61, 0x78, 0x5F, 0x65, 0x6E, 0x74, 0x72, 0x69, 0x65, 0x73, 0x00,
                0x6D, 0x61, 0x70, 0x5F, 0x31, 0x00, 0x6D, 0x61, 0x70, 0x5F, 0x32, 0x00, 0x63, 0x74,
                0x78, 0x00, 0x62, 0x70, 0x66, 0x5F, 0x70, 0x72, 0x6F, 0x67, 0x00, 0x74, 0x72, 0x61,
                0x63, 0x65, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x00, 0x2F, 0x76, 0x61, 0x72, 0x2F, 0x68,
                0x6F, 0x6D, 0x65, 0x2F, 0x64, 0x61, 0x76, 0x65, 0x2F, 0x64, 0x65, 0x76, 0x2F, 0x61,
                0x79, 0x61, 0x2D, 0x72, 0x73, 0x2F, 0x61, 0x79, 0x61, 0x2F, 0x74, 0x65, 0x73, 0x74,
                0x2F, 0x69, 0x6E, 0x74, 0x65, 0x67, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2D, 0x65,
                0x62, 0x70, 0x66, 0x2F, 0x73, 0x72, 0x63, 0x2F, 0x62, 0x70, 0x66, 0x2F, 0x6D, 0x75,
                0x6C, 0x74, 0x69, 0x6D, 0x61, 0x70, 0x2D, 0x62, 0x74, 0x66, 0x2E, 0x62, 0x70, 0x66,
                0x2E, 0x63, 0x00, 0x69, 0x6E, 0x74, 0x20, 0x62, 0x70, 0x66, 0x5F, 0x70, 0x72, 0x6F,
                0x67, 0x28, 0x76, 0x6F, 0x69, 0x64, 0x20, 0x2A, 0x63, 0x74, 0x78, 0x29, 0x00, 0x09,
                0x5F, 0x5F, 0x75, 0x33, 0x32, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x3D, 0x20, 0x30, 0x3B,
                0x00, 0x09, 0x5F, 0x5F, 0x75, 0x36, 0x34, 0x20, 0x74, 0x77, 0x65, 0x6E, 0x74, 0x79,
                0x5F, 0x66, 0x6F, 0x75, 0x72, 0x20, 0x3D, 0x20, 0x32, 0x34, 0x3B, 0x00, 0x09, 0x5F,
                0x5F, 0x75, 0x36, 0x34, 0x20, 0x66, 0x6F, 0x72, 0x74, 0x79, 0x5F, 0x74, 0x77, 0x6F,
                0x20, 0x3D, 0x20, 0x34, 0x32, 0x3B, 0x00, 0x20, 0x20, 0x20, 0x20, 0x62, 0x70, 0x66,
                0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5F, 0x65, 0x6C,
                0x65, 0x6D, 0x28, 0x26, 0x6D, 0x61, 0x70, 0x5F, 0x31, 0x2C, 0x20, 0x26, 0x6B, 0x65,
                0x79, 0x2C, 0x20, 0x26, 0x74, 0x77, 0x65, 0x6E, 0x74, 0x79, 0x5F, 0x66, 0x6F, 0x75,
                0x72, 0x2C, 0x20, 0x42, 0x50, 0x46, 0x5F, 0x41, 0x4E, 0x59, 0x29, 0x3B, 0x00, 0x20,
                0x20, 0x20, 0x20, 0x62, 0x70, 0x66, 0x5F, 0x6D, 0x61, 0x70, 0x5F, 0x75, 0x70, 0x64,
                0x61, 0x74, 0x65, 0x5F, 0x65, 0x6C, 0x65, 0x6D, 0x28, 0x26, 0x6D, 0x61, 0x70, 0x5F,
                0x32, 0x2C, 0x20, 0x26, 0x6B, 0x65, 0x79, 0x2C, 0x20, 0x26, 0x66, 0x6F, 0x72, 0x74,
                0x79, 0x5F, 0x74, 0x77, 0x6F, 0x2C, 0x20, 0x42, 0x50, 0x46, 0x5F, 0x41, 0x4E, 0x59,
                0x29, 0x3B, 0x00, 0x09, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6E, 0x20, 0x30, 0x3B, 0x00,
                0x63, 0x68, 0x61, 0x72, 0x00, 0x5F, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x00,
                0x2E, 0x6D, 0x61, 0x70, 0x73, 0x00, 0x6C, 0x69, 0x63, 0x65, 0x6E, 0x73, 0x65, 0x00,
            ],
        };

        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", data, None);
        obj.parse_section(btf_section).unwrap();

        let map_section = fake_section(EbpfSectionKind::BtfMaps, ".maps", &[], None);
        obj.parse_section(map_section).unwrap();

        let map = &obj.maps["map_1"];
        assert_matches!(map, Map::Btf(m) => {
            assert_eq!(m.def.key_size, 4);
            assert_eq!(m.def.value_size, 8);
            assert_eq!(m.def.max_entries, 1);
        });
    }

    // Builders for fake struct_ops struct types.

    /// The type of a member of a fake `struct_ops` struct.
    #[derive(Clone, Copy)]
    enum Ty {
        /// An integer of this many bytes.
        Int(u32),
        /// A typedef of a const integer of this many bytes.
        TypedefInt(u32),
        /// A `char` array of this many elements.
        Array(u32),
        /// A pointer to a function.
        FnPtr,
        /// A pointer to something that is not a function.
        Ptr,
        /// A 3-bit bitfield in a 4-byte int, in the `kind_flag` encoding.
        Bitfield,
        /// The same bitfield in the legacy encoding.
        LegacyBitfield,
    }

    /// Member names and types, in declaration order.
    type Members<'a> = &'a [(&'a str, Ty)];

    fn ty_size(ty: Ty) -> usize {
        match ty {
            Ty::Int(size) | Ty::TypedefInt(size) | Ty::Array(size) => size as usize,
            Ty::FnPtr | Ty::Ptr => size_of::<*const ()>(),
            Ty::Bitfield | Ty::LegacyBitfield => 4,
        }
    }

    /// Byte offset of a member in a struct laid out by `fake_struct`.
    fn offset_of(members: Members<'_>, name: &str) -> usize {
        let index = members.iter().position(|(n, _)| *n == name).unwrap();
        members[..index].iter().map(|(_, ty)| ty_size(*ty)).sum()
    }

    fn struct_size(members: Members<'_>) -> usize {
        members.iter().map(|(_, ty)| ty_size(*ty)).sum()
    }

    fn fake_type(btf: &mut Btf, ty: Ty) -> u32 {
        let int = |btf: &mut Btf, size: u32| {
            let name_offset = btf.add_string("int");
            btf.add_type(BtfType::Int(btf::Int::new(
                name_offset,
                size,
                btf::IntEncoding::None,
                0,
            )))
        };
        match ty {
            Ty::Int(size) => int(btf, size),
            Ty::TypedefInt(size) => {
                let int = int(btf, size);
                let konst = btf.add_type(BtfType::Const(btf::Const::new(int)));
                let name_offset = btf.add_string("int_t");
                btf.add_type(BtfType::Typedef(btf::Typedef::new(name_offset, konst)))
            }
            Ty::Array(len) => {
                let element = int(btf, 1);
                let index = int(btf, 4);
                btf.add_type(BtfType::Array(Array::new(0, element, index, len)))
            }
            Ty::FnPtr => {
                let proto = btf.add_type(BtfType::FuncProto(FuncProto::new(vec![], 0)));
                btf.add_type(BtfType::Ptr(btf::Ptr::new(0, proto)))
            }
            Ty::Ptr => {
                let pointee = int(btf, 4);
                btf.add_type(BtfType::Ptr(btf::Ptr::new(0, pointee)))
            }
            // The bitfield size lives in the struct member, not in the type.
            Ty::Bitfield => int(btf, 4),
            Ty::LegacyBitfield => {
                let name_offset = btf.add_string("int");
                let mut int = btf::Int::new(name_offset, 4, btf::IntEncoding::None, 0);
                // Only 3 of the 32 bits are used.
                int.data = (int.data & !0xff) | 3;
                btf.add_type(BtfType::Int(int))
            }
        }
    }

    /// Adds a struct whose members are laid out back to back and returns
    /// its type id.
    fn fake_struct(btf: &mut Btf, name: &str, members: Members<'_>) -> u32 {
        let btf_members = members
            .iter()
            .map(|&(member_name, ty)| {
                let mut offset = (offset_of(members, member_name) * 8) as u32;
                if matches!(ty, Ty::Bitfield) {
                    // With kind_flag set, the high 8 bits hold the bitfield size.
                    offset |= 3 << 24;
                }
                BtfMember {
                    name_offset: btf.add_string(member_name),
                    btf_type: fake_type(btf, ty),
                    offset,
                }
            })
            .collect();
        let name_offset = btf.add_string(name);
        let s = Struct::new(name_offset, btf_members, struct_size(members) as u32);
        let has_bitfield = members.iter().any(|(_, ty)| matches!(ty, Ty::Bitfield));
        btf.add_type(if has_bitfield {
            with_kind_flag(&s)
        } else {
            BtfType::Struct(s)
        })
    }

    /// `Struct::new` never sets `kind_flag`, so set it in the serialized
    /// form and read the struct back.
    fn with_kind_flag(s: &Struct) -> BtfType {
        let mut bytes = s.to_bytes();
        let info = u32::from_ne_bytes(bytes[4..8].try_into().unwrap()) | (1 << 31);
        bytes[4..8].copy_from_slice(&info.to_ne_bytes());
        unsafe { BtfType::read(&bytes, Endianness::default()) }.unwrap()
    }

    // .BTF is section 0, .struct_ops is section 1, .struct_ops.link is section 2.
    // fake_relocations puts the program for row i in section i + offset.
    const STRUCT_OPS_SECTION_INDEX: usize = 1;
    const STRUCT_OPS_LINK_SECTION_INDEX: usize = 2;
    const PROGRAM_SECTION_INDEX_OFFSET: usize = 2;
    const LINK_PROGRAM_SECTION_INDEX_OFFSET: usize = 4;

    fn fake_qdisc_type_info(btf: &mut Btf) -> HashMap<&'static str, u32> {
        let int_name_offset = btf.add_string("int");
        let int_type_id = btf.add_type(BtfType::Int(btf::Int::new(
            int_name_offset,
            4,
            btf::IntEncoding::Signed,
            0,
        )));

        let char_name_offset = btf.add_string("char");
        let char_type_id = btf.add_type(BtfType::Int(btf::Int::new(
            char_name_offset,
            1,
            btf::IntEncoding::Signed,
            0,
        )));

        /*
         * "The index_type can be any regular int type (u8, u16, u32, u64, unsigned __int128).
         * The original design of including index_type follows DWARF, which has an index_type for
         * its array type. Currently in BTF, beyond type verification, the index_type is not
         * used."
         */
        let char_array_type_id =
            btf.add_type(BtfType::Array(Array::new(0, char_type_id, int_type_id, 16)));

        let sk_buff_name_offset = btf.add_string("sk_buff");
        let fake_sk_buff_field_name_offset = btf.add_string("fake_sk_buff_field");
        let sk_buff_type_id = btf.add_type(BtfType::Struct(Struct::new(
            sk_buff_name_offset,
            vec![BtfMember {
                name_offset: fake_sk_buff_field_name_offset,
                btf_type: int_type_id,
                offset: 0,
            }],
            4,
        )));

        let _msg_name_offset = btf.add_string("_msg");

        let sk_buff_ptr_name_offset = btf.add_string("sk_buff*");
        let sk_buff_ptr_type_id = btf.add_type(BtfType::Ptr(btf::Ptr::new(
            sk_buff_ptr_name_offset,
            sk_buff_type_id,
        )));

        let sk_buff_ptr_ptr_name_offset = btf.add_string("sk_buff**");
        let sk_buff_ptr_ptr_type_id = btf.add_type(BtfType::Ptr(btf::Ptr::new(
            sk_buff_ptr_ptr_name_offset,
            sk_buff_ptr_type_id,
        )));

        let qdisc_name_offset = btf.add_string("Qdisc");
        let qdisc_type_id = btf.add_type(BtfType::Fwd(btf::Fwd::new(qdisc_name_offset, false)));

        let qdisc_ptr_name_offset = btf.add_string("Qdisc*");
        let qdisc_ptr_type_id = btf.add_type(BtfType::Ptr(btf::Ptr::new(
            qdisc_ptr_name_offset,
            qdisc_type_id,
        )));

        let skb_name_offset = btf.add_string("skb");
        let sch_name_offset = btf.add_string("sch");
        let to_free_name_offset = btf.add_string("to_free");
        let enqueue_func_proto_type_id = btf.add_type(BtfType::FuncProto(FuncProto::new(
            vec![
                btf::BtfParam {
                    name_offset: skb_name_offset,
                    btf_type: sk_buff_ptr_type_id,
                },
                btf::BtfParam {
                    name_offset: sch_name_offset,
                    btf_type: qdisc_ptr_type_id,
                },
                btf::BtfParam {
                    name_offset: to_free_name_offset,
                    btf_type: sk_buff_ptr_ptr_type_id,
                },
            ],
            // return BTF type id.
            int_type_id,
        )));

        let enqueue_func_ptr_name_offset = btf.add_string("*enqueue");
        let enqueue_func_ptr_id = btf.add_type(BtfType::Ptr(btf::Ptr::new(
            enqueue_func_ptr_name_offset,
            enqueue_func_proto_type_id,
        )));

        let dequeue_func_proto_type_id = btf.add_type(BtfType::FuncProto(FuncProto::new(
            vec![btf::BtfParam {
                name_offset: sch_name_offset,
                btf_type: qdisc_ptr_type_id,
            }],
            sk_buff_ptr_type_id,
        )));
        let dequeue_func_ptr_name_offset = btf.add_string("*dequeue");
        let dequeue_func_ptr_id = btf.add_type(BtfType::Ptr(btf::Ptr::new(
            dequeue_func_ptr_name_offset,
            dequeue_func_proto_type_id,
        )));

        HashMap::from([
            ("enqueue", enqueue_func_proto_type_id),
            ("dequeue", dequeue_func_proto_type_id),
            ("*enqueue", enqueue_func_ptr_id),
            ("*dequeue", dequeue_func_ptr_id),
            ("char", char_type_id),
            ("char[]", char_array_type_id),
            ("int", int_type_id),
        ])
    }

    fn fake_qdisc_ops_instance(
        btf: &mut Btf,
        type_info: &HashMap<&str, u32>,
        is_link: bool,
        var_name: &str,
    ) {
        let id_name_offset = btf.add_string("id");
        let enqueue_name_offset = btf.add_string("enqueue");
        let dequeue_name_offset = btf.add_string("dequeue");
        let qdisc_ops_members = vec![
            BtfMember {
                name_offset: id_name_offset,
                btf_type: type_info["char[]"],
                offset: 128,
            },
            BtfMember {
                name_offset: enqueue_name_offset,
                btf_type: type_info["*enqueue"],
                offset: 320,
            },
            BtfMember {
                name_offset: dequeue_name_offset,
                btf_type: type_info["*dequeue"],
                offset: 384,
            },
        ];

        fake_qdisc_ops_instance_custom(btf, is_link, &[(var_name, 0)], qdisc_ops_members);
    }

    fn fake_qdisc_ops_instance_custom(
        btf: &mut Btf,
        is_link: bool,
        instances: &[(&str, u32)],
        members: Vec<BtfMember>,
    ) {
        let qdisc_ops_struct_type_id =
            if let Ok(id) = btf.id_by_type_name_kind("Qdisc_ops", BtfKind::Struct) {
                id
            } else {
                let qdisc_ops_name_offset = btf.add_string("Qdisc_ops");
                btf.add_type(BtfType::Struct(Struct::new(
                    qdisc_ops_name_offset,
                    members,
                    176,
                )))
            };

        // One DATASEC entry per instance, all in the same section.
        let datasec_entries = instances
            .iter()
            .map(|(var_name, var_offset)| {
                let var_name_offset = btf.add_string(var_name);
                let var = btf.add_type(BtfType::Var(Var::new(
                    var_name_offset,
                    qdisc_ops_struct_type_id,
                    btf::VarLinkage::Global,
                )));

                DataSecEntry {
                    btf_type: var,
                    offset: *var_offset,
                    size: 176,
                }
            })
            .collect();

        let struct_ops_name_offset = if is_link {
            btf.add_string(".struct_ops.link")
        } else {
            btf.add_string(".struct_ops")
        };

        btf.add_type(BtfType::DataSec(DataSec::new(
            struct_ops_name_offset,
            datasec_entries,
            0,
        )));
    }

    fn fake_relocations(
        obj: &mut Object,
        sec_prefix: &str,
        program_section_index_offset: usize,
        relocations: &[(&str, Option<(&str, u64)>)],
    ) -> Vec<Relocation> {
        let insns = [fake_ins()];
        let data = bytes_of(&insns);

        relocations
            .iter()
            .enumerate()
            .filter_map(|(i, (_member, program))| {
                let (program, offset) = (*program)?;

                let section_index = i + program_section_index_offset;
                let symbol_index = fake_sym(obj, section_index, 0, program, FAKE_INS_LEN);

                obj.parse_programs(&fake_section(
                    EbpfSectionKind::Program,
                    &format!("{sec_prefix}/{program}"),
                    data,
                    Some(section_index),
                ))
                .unwrap();

                Some(Relocation {
                    offset,
                    size: 64, // R_BPF_64_ABS64.
                    symbol_index,
                })
            })
            .collect()
    }

    // Function pointer member name -> program name, for the members a program implements.
    fn struct_ops_pairings(info: &StructOpsInfo) -> HashMap<String, String> {
        info.func_ptrs
            .iter()
            .filter_map(|func_ptr| {
                func_ptr
                    .program
                    .clone()
                    .map(|program| (func_ptr.name.clone(), program))
            })
            .collect()
    }

    fn fake_struct_ops_section(
        sec_index: usize,
        data: &[u8],
        relocs: Vec<Relocation>,
    ) -> Section<'_> {
        Section {
            index: SectionIndex(sec_index),
            kind: EbpfSectionKind::StructOps,
            address: 0,
            name: ".struct_ops",
            data,
            size: 176,
            relocations: relocs,
        }
    }

    fn fake_struct_ops_link_section(
        sec_index: usize,
        data: &[u8],
        relocs: Vec<Relocation>,
    ) -> Section<'_> {
        Section {
            index: SectionIndex(sec_index),
            kind: EbpfSectionKind::StructOps,
            address: 0,
            name: ".struct_ops.link",
            data,
            size: 176,
            relocations: relocs,
        }
    }

    #[test]
    fn test_parse_and_match_struct_ops_sections() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, true, "fifo_link");

        // Create mock relocation entries.
        let qdisc_ops_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_enqueue", 0x28u64))),
            ("dequeue", Some(("bpf_fifo_dequeue", 0x30u64))),
        ];
        let qdisc_ops_link_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_link_enqueue", 0x28u64))),
            ("dequeue", Some(("bpf_fifo_link_dequeue", 0x30u64))),
        ];

        // .BTF is section 0, .struct_ops is section 1, .struct_ops.link is section 2.
        // fake_relocations puts the program for row i in section i + offset, so the
        // .struct_ops programs land in sections 3 and 4, the link ones in 5 and 6.

        let relocs = fake_relocations(
            &mut obj,
            "struct_ops",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );
        let link_relocs = fake_relocations(
            &mut obj,
            "struct_ops",
            LINK_PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_link_mapping,
        );

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );
        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_LINK_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo_link",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        // Only "id" field is filled in.
        // .struct_ops function pointer member fields are 0
        // as relocatiosn determine the value of the actual
        // function addresses referred to by the pointers.
        let mut data = vec![0u8; 176];
        data[0x10..0x10 + 8].copy_from_slice(b"bpf_fifo");
        let struct_ops_section = fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, relocs);
        obj.parse_section(struct_ops_section).unwrap();

        let mut link_data = vec![0u8; 176];
        link_data[0x10..0x10 + 13].copy_from_slice(b"bpf_fifo_link");
        let struct_ops_link_section =
            fake_struct_ops_link_section(STRUCT_OPS_LINK_SECTION_INDEX, &link_data, link_relocs);
        obj.parse_section(struct_ops_link_section).unwrap();

        let btf = obj.btf.unwrap();

        let instances = [
            ("fifo", false, &qdisc_ops_mapping),
            ("fifo_link", true, &qdisc_ops_link_mapping),
        ];

        for (var_name, is_link, mapping) in instances {
            let struct_ops_impls: HashSet<&str> = mapping
                .iter()
                .filter_map(|entry| match entry.1 {
                    None => None,
                    _ => Some(entry.1.unwrap().0),
                })
                .collect();

            for name in &struct_ops_impls {
                let prog = &obj.programs[*name];
                let func = &obj.functions[&prog.function_key()];

                assert_matches!(prog, Program {
                    license,
                    kernel_version: None,
                    section: ProgramSection::StructOps { sleepable: false },
                    ..
                }  => assert_eq!(license.to_str().unwrap(), "GPL"));

                assert_matches!(
                    func,
                    Function {
                        name,
                        instructions,
                        ..
                    }  if instructions.len() == 1
                );
            }

            let struct_ops_info = &obj.struct_ops[var_name];

            assert_eq!(
                btf.id_by_type_name_kind("Qdisc_ops", BtfKind::Struct)
                    .unwrap(),
                struct_ops_info.type_id,
                "{var_name}"
            );
            assert_eq!(struct_ops_info.is_link, is_link, "{var_name}");

            let parsed_func_ptrs: HashSet<&str> = struct_ops_info
                .func_ptrs
                .iter()
                .map(|func_ptr| func_ptr.name.as_str())
                .collect();
            let expected_func_ptrs: HashSet<&str> = qdisc_ops_mapping
                .iter()
                .filter_map(|entry| match entry.1 {
                    None => None,
                    _ => Some(entry.0),
                })
                .collect();
            assert_eq!(parsed_func_ptrs, expected_func_ptrs, "{var_name}");

            let expect_pairings: HashMap<String, String> = mapping
                .iter()
                .filter_map(|entry| match entry.1 {
                    None => None,
                    _ => Some((
                        String::from_str(entry.0).unwrap(),
                        String::from_str(entry.1.unwrap().0).unwrap(),
                    )),
                })
                .collect();
            assert_eq!(
                expect_pairings,
                struct_ops_pairings(struct_ops_info),
                "{var_name}"
            );
            assert!(!struct_ops_info.is_optional, "{var_name}");
        }

        assert_eq!(obj.struct_ops["fifo"].data, data);
        assert_eq!(obj.struct_ops["fifo_link"].data, link_data);
    }

    #[test]
    fn test_target_not_a_program() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");

        // Create mock relocation entries.
        let qdisc_ops_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_enqueue", 0x28u64))),
        ];

        // .BTF is at section with index 0 and .struct_ops will be at section 1.

        let relocs = fake_relocations(
            &mut obj,
            "socket",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        // Only "id" field is filled in.
        // .struct_ops function pointer member fields are 0
        // as relocatiosn determine the value of the actual
        // function addresses referred to by the pointers.
        let mut data = vec![0u8; 176];
        data[0x10..0x10 + 8].copy_from_slice(b"bpf_fifo");
        let struct_ops_section = fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, relocs);

        assert_matches!(
            obj.parse_section(struct_ops_section),
            Err(ParseError::InvalidSymbol {index: 1, name: n}) if n == Some(String::from_str("bpf_fifo_enqueue").unwrap())
        );
    }

    #[test]
    fn test_reloc_at_struct_ops_scalar() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");

        // Create mock relocation entries.
        let qdisc_ops_mapping = vec![("id", Some(("id", 0x10u64)))];

        // .BTF is at section with index 0 and .struct_ops will be at section 1.

        let relocs = fake_relocations(
            &mut obj,
            "struct_ops",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        // Only "id" field is filled in.
        // .struct_ops function pointer member fields are 0
        // as relocatiosn determine the value of the actual
        // function addresses referred to by the pointers.
        let mut data = vec![0u8; 176];
        data[0x10..0x10 + 8].copy_from_slice(b"bpf_fifo");
        let struct_ops_section = fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, relocs);

        assert_matches!(
            obj.parse_section(struct_ops_section),
            Err(ParseError::InvalidRelocation { .. })
        );
    }

    #[test]
    fn test_struct_ops_program_in_two_members() {
        let mut obj = fake_obj();

        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");

        let qdisc_ops_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_enqueue", 0x28u64))),
        ];

        let mut relocs = fake_relocations(
            &mut obj,
            "struct_ops",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );

        // Point "dequeue" at the program already used for "enqueue".
        relocs.push(Relocation {
            offset: 0x30,
            size: relocs[0].size,
            symbol_index: relocs[0].symbol_index,
        });

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        let mut data = vec![0u8; 176];
        data[0x10..0x10 + 8].copy_from_slice(b"bpf_fifo");
        let struct_ops_section = fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, relocs);

        assert_matches!(
            obj.parse_section(struct_ops_section),
            Err(ParseError::StructOpsProgramReuse { program, member_name, other_member_name })
                if program == "bpf_fifo_enqueue" && member_name == "dequeue" && other_member_name == "enqueue"
        );
    }

    #[test]
    fn test_parse_ok_abscent_peek_mapping() {
        let mut obj = fake_obj();

        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);

        let id_name_offset = btf.add_string("id");

        let func_members = HashMap::from([
            ("enqueue", btf.add_string("enqueue")),
            ("dequeue", btf.add_string("dequeue")),
            /*
             *  struct sk_buff *        (*dequeue)(struct Qdisc *);
             *  struct sk_buff *        (*peek)(struct Qdisc *);
             *
             * https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/Qdisc_ops/
             */
            ("peek", btf.add_string("peek")),
        ]);
        let peek_type_info = fake_type_info["*dequeue"];

        fake_qdisc_ops_instance_custom(
            &mut btf,
            false,
            &[("fifo", 0)],
            vec![
                BtfMember {
                    name_offset: id_name_offset,
                    btf_type: fake_type_info["char[]"],
                    offset: 128,
                },
                BtfMember {
                    name_offset: func_members["enqueue"],
                    btf_type: fake_type_info["*enqueue"],
                    offset: 320,
                },
                BtfMember {
                    name_offset: func_members["dequeue"],
                    btf_type: fake_type_info["*dequeue"],
                    offset: 384,
                },
                BtfMember {
                    name_offset: func_members["peek"],
                    btf_type: peek_type_info,
                    offset: 448,
                },
            ],
        );

        // Create mock relocation entries.
        let qdisc_ops_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_enqueue", 0x28u64))),
            ("dequeue", Some(("bpf_fifo_dequeue", 0x30u64))),
        ];

        // .BTF is at section with index 0 and .struct_ops will be at section 1.

        let relocs = fake_relocations(
            &mut obj,
            "struct_ops",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        // Only "id" field is filled in.
        // .struct_ops function pointer member fields are 0
        // as relocatiosn determine the value of the actual
        // function addresses referred to by the pointers.
        let mut data = vec![0u8; 176];
        data[0x10..0x10 + 8].copy_from_slice(b"bpf_fifo");
        let struct_ops_section = fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, relocs);

        obj.parse_section(struct_ops_section).unwrap();

        let struct_ops_info = &obj.struct_ops["fifo"];

        let parsed_func_ptrs: HashSet<&str> = struct_ops_info
            .func_ptrs
            .iter()
            .map(|func_ptr| func_ptr.name.as_str())
            .collect();
        let expected_func_ptrs: HashSet<&str> = func_members.keys().copied().collect();
        assert_eq!(parsed_func_ptrs, expected_func_ptrs);

        let expect_pairings: HashMap<String, String> = qdisc_ops_mapping
            .iter()
            .filter_map(|entry| match entry.1 {
                None => None,
                _ => Some((
                    String::from_str(entry.0).unwrap(),
                    String::from_str(entry.1.unwrap().0).unwrap(),
                )),
            })
            .collect();
        assert_eq!(expect_pairings, struct_ops_pairings(struct_ops_info));
    }

    #[test]
    fn test_struct_ops_no_relocations() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        // No programs and no relocations: every function pointer is left unset.
        let mut data = vec![0u8; 176];
        data[0x10..0x10 + 8].copy_from_slice(b"bpf_fifo");
        let struct_ops_section =
            fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, Vec::new());
        obj.parse_section(struct_ops_section).unwrap();

        assert!(obj.programs.is_empty());
        assert_eq!(obj.struct_ops.len(), 1);

        // The instance is still recorded, with its function pointer members
        // known but nothing paired to them.
        let struct_ops_info = &obj.struct_ops["fifo"];
        assert!(!struct_ops_info.is_link);
        let parsed_func_ptrs: HashSet<&str> = struct_ops_info
            .func_ptrs
            .iter()
            .map(|func_ptr| func_ptr.name.as_str())
            .collect();
        assert_eq!(parsed_func_ptrs, HashSet::from(["enqueue", "dequeue"]));
        assert!(struct_ops_pairings(struct_ops_info).is_empty());
    }

    #[test]
    fn test_two_instances_same_section_shared_programs() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);

        // (variable name, offset of the variable within the section)
        let instances = [("fifo_a", 0u32), ("fifo_b", 176u32)];

        let id_name_offset = btf.add_string("id");
        let enqueue_name_offset = btf.add_string("enqueue");
        let dequeue_name_offset = btf.add_string("dequeue");
        fake_qdisc_ops_instance_custom(
            &mut btf,
            false,
            &instances,
            vec![
                BtfMember {
                    name_offset: id_name_offset,
                    btf_type: fake_type_info["char[]"],
                    offset: 128,
                },
                BtfMember {
                    name_offset: enqueue_name_offset,
                    btf_type: fake_type_info["*enqueue"],
                    offset: 320,
                },
                BtfMember {
                    name_offset: dequeue_name_offset,
                    btf_type: fake_type_info["*dequeue"],
                    offset: 384,
                },
            ],
        );

        let qdisc_ops_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_enqueue", 0x28u64))),
            ("dequeue", Some(("bpf_fifo_dequeue", 0x30u64))),
        ];

        // One set of programs. The helper returns the relocations for the
        // instance at section offset 0; the second instance reuses the same
        // symbols, with each relocation shifted by the variable's offset.
        let relocs_a = fake_relocations(
            &mut obj,
            "struct_ops",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );
        let relocs: Vec<Relocation> = instances
            .iter()
            .flat_map(|(_, var_offset)| {
                relocs_a.iter().map(move |reloc| Relocation {
                    offset: reloc.offset + u64::from(*var_offset),
                    size: reloc.size,
                    symbol_index: reloc.symbol_index,
                })
            })
            .collect();

        for (var_name, var_offset) in instances {
            fake_sym_with_kind(
                &mut obj,
                STRUCT_OPS_SECTION_INDEX,
                SymbolKind::Data,
                u64::from(var_offset),
                var_name,
                176,
            );
        }

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        let mut data = vec![0u8; 2 * 176];
        data[0x10..0x10 + 6].copy_from_slice(b"fifo_a");
        data[176 + 0x10..176 + 0x10 + 6].copy_from_slice(b"fifo_b");
        let struct_ops_section = Section {
            index: SectionIndex(STRUCT_OPS_SECTION_INDEX),
            kind: EbpfSectionKind::StructOps,
            address: 0,
            name: ".struct_ops",
            data: &data,
            size: data.len() as u64,
            relocations: relocs,
        };
        obj.parse_section(struct_ops_section).unwrap();

        // Sharing programs must not register them twice.
        assert_eq!(obj.programs.len(), 2);
        assert_eq!(obj.struct_ops.len(), 2);

        let expect_pairings: HashMap<String, String> = qdisc_ops_mapping
            .iter()
            .filter_map(|entry| {
                entry
                    .1
                    .map(|(prog_name, _)| (entry.0.to_string(), prog_name.to_string()))
            })
            .collect();

        for (var_name, var_offset) in instances {
            let struct_ops_info = &obj.struct_ops[var_name];
            assert!(!struct_ops_info.is_link, "{var_name}");
            assert_eq!(struct_ops_info.func_ptrs.len(), 2, "{var_name}");
            assert_eq!(
                expect_pairings,
                struct_ops_pairings(struct_ops_info),
                "{var_name}"
            );

            let var_offset = var_offset as usize;
            assert_eq!(
                struct_ops_info.data,
                data[var_offset..var_offset + 176],
                "{var_name}"
            );
        }

        // Each program is attached once, however many instances use it.
        assert_eq!(obj.struct_ops_attachments.len(), 2);
        assert_eq!(
            obj.struct_ops_attachments["bpf_fifo_enqueue"].member_name,
            "enqueue"
        );
        assert_eq!(
            obj.struct_ops_attachments["bpf_fifo_dequeue"].member_name,
            "dequeue"
        );
    }

    #[test]
    fn test_struct_ops_optional_prefix() {
        for (section_name, is_link) in [("?.struct_ops", false), ("?.struct_ops.link", true)] {
            let mut obj = fake_obj();
            let mut btf = Btf::new();

            let fake_type_info = fake_qdisc_type_info(&mut btf);

            // "fifo" goes in the unprefixed section, which is never parsed here.
            fake_qdisc_ops_instance(&mut btf, &fake_type_info, is_link, "fifo");

            // "fifo_opt" goes in the "?" section. The DATASEC name keeps the "?".
            let qdisc_ops_type_id = btf
                .id_by_type_name_kind("Qdisc_ops", BtfKind::Struct)
                .unwrap();
            let var_name_offset = btf.add_string("fifo_opt");
            let var = btf.add_type(BtfType::Var(Var::new(
                var_name_offset,
                qdisc_ops_type_id,
                btf::VarLinkage::Global,
            )));
            let section_name_offset = btf.add_string(section_name);
            btf.add_type(BtfType::DataSec(DataSec::new(
                section_name_offset,
                vec![DataSecEntry {
                    btf_type: var,
                    offset: 0,
                    size: 176,
                }],
                0,
            )));

            fake_sym_with_kind(
                &mut obj,
                STRUCT_OPS_SECTION_INDEX,
                SymbolKind::Data,
                0,
                "fifo_opt",
                176,
            );

            let btf_data = btf.to_bytes();
            let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
            obj.parse_section(btf_section).unwrap();

            let data = vec![0u8; 176];
            let struct_ops_section = Section {
                index: SectionIndex(STRUCT_OPS_SECTION_INDEX),
                kind: EbpfSectionKind::StructOps,
                address: 0,
                name: section_name,
                data: &data,
                size: 176,
                relocations: Vec::new(),
            };
            obj.parse_section(struct_ops_section).unwrap();

            // Only the instance from the "?" section is picked up, and the
            // prefix does not hide whether it is a link section.
            let parsed = &obj.struct_ops;
            assert_eq!(parsed.len(), 1, "{section_name}");
            assert_eq!(parsed["fifo_opt"].is_link, is_link, "{section_name}");
            assert!(parsed["fifo_opt"].is_optional, "{section_name}");
        }
    }

    #[test]
    fn test_struct_ops_program_in_two_members_across_sections() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, true, "fifo_link");

        let qdisc_ops_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_enqueue", 0x28u64))),
        ];
        let relocs = fake_relocations(
            &mut obj,
            "struct_ops",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );

        // "fifo_link" uses the program for "dequeue" instead.
        let link_relocs = vec![Relocation {
            offset: 0x30,
            size: relocs[0].size,
            symbol_index: relocs[0].symbol_index,
        }];

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );
        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_LINK_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo_link",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        let data = vec![0u8; 176];
        let struct_ops_section = fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, relocs);
        obj.parse_section(struct_ops_section).unwrap();

        let struct_ops_link_section =
            fake_struct_ops_link_section(STRUCT_OPS_LINK_SECTION_INDEX, &data, link_relocs);
        assert_matches!(
            obj.parse_section(struct_ops_link_section),
            Err(ParseError::StructOpsProgramReuse { program, member_name, other_member_name })
                if program == "bpf_fifo_enqueue" && member_name == "dequeue" && other_member_name == "enqueue"
        );
    }

    #[test]
    fn test_struct_ops_instance_past_section_end() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        // Qdisc_ops is 176 bytes.
        let data = vec![0u8; 100];
        let struct_ops_section =
            fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, Vec::new());

        assert_matches!(
            obj.parse_section(struct_ops_section),
            Err(ParseError::InvalidGlobalData { name, sym_size: 176, data_size: 100 }) if name == "fifo"
        );
    }

    #[test]
    fn test_struct_ops_typedef_func_ptr_member() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);

        // enqueue is declared as `const enqueue_fn_t enqueue`, where
        //   typedef int enqueue_fn(struct sk_buff *, struct Qdisc *, struct sk_buff **);
        //   typedef enqueue_fn *enqueue_fn_t;
        let enqueue_fn_name_offset = btf.add_string("enqueue_fn");
        let enqueue_fn = btf.add_type(BtfType::Typedef(btf::Typedef::new(
            enqueue_fn_name_offset,
            fake_type_info["enqueue"],
        )));
        let enqueue_fn_ptr = btf.add_type(BtfType::Ptr(btf::Ptr::new(0, enqueue_fn)));
        let enqueue_fn_t_name_offset = btf.add_string("enqueue_fn_t");
        let enqueue_fn_t = btf.add_type(BtfType::Typedef(btf::Typedef::new(
            enqueue_fn_t_name_offset,
            enqueue_fn_ptr,
        )));
        let const_enqueue_fn_t = btf.add_type(BtfType::Const(btf::Const::new(enqueue_fn_t)));

        let id_name_offset = btf.add_string("id");
        let enqueue_name_offset = btf.add_string("enqueue");
        fake_qdisc_ops_instance_custom(
            &mut btf,
            false,
            &[("fifo", 0)],
            vec![
                BtfMember {
                    name_offset: id_name_offset,
                    btf_type: fake_type_info["char[]"],
                    offset: 128,
                },
                BtfMember {
                    name_offset: enqueue_name_offset,
                    btf_type: const_enqueue_fn_t,
                    offset: 320,
                },
            ],
        );

        let qdisc_ops_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_enqueue", 0x28u64))),
        ];
        let relocs = fake_relocations(
            &mut obj,
            "struct_ops",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        let data = vec![0u8; 176];
        let struct_ops_section = fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, relocs);
        obj.parse_section(struct_ops_section).unwrap();

        let struct_ops_info = &obj.struct_ops["fifo"];
        assert_eq!(struct_ops_info.func_ptrs.len(), 1);
        assert_eq!(struct_ops_info.func_ptrs[0].name, "enqueue");
        assert_eq!(
            struct_ops_info.func_ptrs[0].program.as_deref(),
            Some("bpf_fifo_enqueue")
        );
    }

    #[test]
    fn test_struct_ops_two_relocations_same_member() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);
        fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");

        let qdisc_ops_mapping = vec![
            ("id", None),
            ("enqueue", Some(("bpf_fifo_enqueue", 0x28u64))),
        ];
        let mut relocs = fake_relocations(
            &mut obj,
            "struct_ops",
            PROGRAM_SECTION_INDEX_OFFSET,
            &qdisc_ops_mapping,
        );

        // A second relocation for "enqueue".
        relocs.push(Relocation {
            offset: relocs[0].offset,
            size: relocs[0].size,
            symbol_index: relocs[0].symbol_index,
        });

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        let data = vec![0u8; 176];
        let struct_ops_section = fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, relocs);

        assert_matches!(
            obj.parse_section(struct_ops_section),
            Err(ParseError::InvalidRelocation { section, offset: 0x28 }) if section == ".struct_ops"
        );
    }

    #[test]
    fn test_struct_ops_overlapping_instances() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        let fake_type_info = fake_qdisc_type_info(&mut btf);

        // (variable name, offset of the variable within the section).
        // Qdisc_ops is 176 bytes, so "fifo_b" starts inside "fifo_a".
        let instances = [("fifo_a", 0u32), ("fifo_b", 100u32)];

        let id_name_offset = btf.add_string("id");
        fake_qdisc_ops_instance_custom(
            &mut btf,
            false,
            &instances,
            vec![BtfMember {
                name_offset: id_name_offset,
                btf_type: fake_type_info["char[]"],
                offset: 128,
            }],
        );

        for (var_name, var_offset) in instances {
            fake_sym_with_kind(
                &mut obj,
                STRUCT_OPS_SECTION_INDEX,
                SymbolKind::Data,
                u64::from(var_offset),
                var_name,
                176,
            );
        }

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        let data = vec![0u8; 2 * 176];
        let struct_ops_section = Section {
            index: SectionIndex(STRUCT_OPS_SECTION_INDEX),
            kind: EbpfSectionKind::StructOps,
            address: 0,
            name: ".struct_ops",
            data: &data,
            size: data.len() as u64,
            relocations: Vec::new(),
        };

        assert_matches!(
            obj.parse_section(struct_ops_section),
            Err(ParseError::StructOpsInstanceOverlap { name, other_name })
                if name == "fifo_b" && other_name == "fifo_a"
        );
    }

    #[test]
    fn test_struct_ops_section_without_datasec() {
        let mut obj = fake_obj();
        let mut btf = Btf::new();

        // Types only: no VAR and no DATASEC for the section.
        fake_qdisc_type_info(&mut btf);

        fake_sym_with_kind(
            &mut obj,
            STRUCT_OPS_SECTION_INDEX,
            SymbolKind::Data,
            0,
            "fifo",
            176,
        );

        let btf_data = btf.to_bytes();
        let btf_section = fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None);
        obj.parse_section(btf_section).unwrap();

        let data = vec![0u8; 176];
        let struct_ops_section =
            fake_struct_ops_section(STRUCT_OPS_SECTION_INDEX, &data, Vec::new());

        assert_matches!(
            obj.parse_section(struct_ops_section),
            Err(ParseError::BtfError(BtfError::UnknownBtfTypeName { type_name })) if type_name == ".struct_ops"
        );
    }

    mod resolve_struct_ops {
        use assert_matches::assert_matches;

        use super::*;

        const STRUCT_NAME: &str = "test_ops";
        const WRAPPER_NAME: &str = "bpf_struct_ops_test_ops";
        /// Byte offset of the wrapper's `data` member.
        const DATA_OFFSET: usize = 64;
        const SECTION_INDEX: usize = 7;
        const FIRST_SYMBOL_INDEX: usize = 100;

        /// The layout most tests use on both sides.
        const MEMBERS: Members<'static> = &[
            ("id", Ty::Array(16)),
            ("flags", Ty::Int(4)),
            ("enqueue", Ty::FnPtr),
            ("dequeue", Ty::FnPtr),
        ];

        /// Adds the kernel's wrapper struct for `struct_name`: a `common`
        /// header, then `data` of type `data_type_id` at `DATA_OFFSET`.
        fn fake_wrapper(btf: &mut Btf, struct_name: &str, data_type_id: u32) -> u32 {
            let members = vec![
                BtfMember {
                    name_offset: btf.add_string("common"),
                    btf_type: fake_type(btf, Ty::Int(8)),
                    offset: 0,
                },
                BtfMember {
                    name_offset: btf.add_string("data"),
                    btf_type: data_type_id,
                    offset: (DATA_OFFSET * 8) as u32,
                },
            ];
            let size = DATA_OFFSET + btf.type_size(data_type_id).unwrap();
            let name_offset = btf.add_string(&format!("bpf_struct_ops_{struct_name}"));
            btf.add_type(BtfType::Struct(Struct::new(
                name_offset,
                members,
                size as u32,
            )))
        }

        /// Kernel BTF holding the struct and its wrapper.
        fn fake_kernel_btf(struct_name: &str, members: Members<'_>) -> Btf {
            let mut btf = Btf::new();
            let type_id = fake_struct(&mut btf, struct_name, members);
            fake_wrapper(&mut btf, struct_name, type_id);
            btf
        }

        /// The map value expected when these members are set, in the layout
        /// of `kernel_members`.
        fn expected_value(kernel_members: Members<'_>, values: &[(&str, &[u8])]) -> Vec<u8> {
            let mut value = vec![0; DATA_OFFSET + struct_size(kernel_members)];
            for (member, bytes) in values {
                let offset = DATA_OFFSET + offset_of(kernel_members, member);
                value[offset..offset + bytes.len()].copy_from_slice(bytes);
            }
            value
        }

        /// An object with one `struct_ops` struct type, and the kernel BTF to
        /// resolve its instances against.
        struct Fixture<'a> {
            obj: Object,
            kernel_btf: Btf,
            obj_members: Members<'a>,
            type_id: u32,
        }

        fn fixture<'a>(obj_members: Members<'a>, kernel_members: Members<'_>) -> Fixture<'a> {
            let mut btf = Btf::new();
            let type_id = fake_struct(&mut btf, STRUCT_NAME, obj_members);
            let mut obj = fake_obj();
            obj.btf = Some(btf);
            Fixture {
                obj,
                kernel_btf: fake_kernel_btf(STRUCT_NAME, kernel_members),
                obj_members,
                type_id,
            }
        }

        impl Fixture<'_> {
            /// Adds a `.struct_ops` instance the way the parser would record
            /// it. `values` holds the bytes of the members the instance sets
            /// and `programs` pairs function pointer members with programs.
            fn instance(
                self,
                name: &str,
                values: &[(&str, &[u8])],
                programs: &[(&str, &str)],
            ) -> Self {
                self.add_instance(name, false, values, programs)
            }

            /// Same as `instance`, for `.struct_ops.link`.
            fn link_instance(
                self,
                name: &str,
                values: &[(&str, &[u8])],
                programs: &[(&str, &str)],
            ) -> Self {
                self.add_instance(name, true, values, programs)
            }

            fn add_instance(
                mut self,
                name: &str,
                is_link: bool,
                values: &[(&str, &[u8])],
                programs: &[(&str, &str)],
            ) -> Self {
                let mut data = vec![0; struct_size(self.obj_members)];
                for (member, bytes) in values {
                    let offset = offset_of(self.obj_members, member);
                    data[offset..offset + bytes.len()].copy_from_slice(bytes);
                }

                let func_ptrs: Vec<_> = self
                    .obj_members
                    .iter()
                    .filter(|(_, ty)| matches!(ty, Ty::FnPtr))
                    .map(|(member, _)| StructOpsFnPtrMember {
                        name: member.to_string(),
                        bit_offset: offset_of(self.obj_members, member) * 8,
                        program: programs
                            .iter()
                            .find(|(m, _)| m == member)
                            .map(|(_, program)| program.to_string()),
                    })
                    .collect();

                for func_ptr in &func_ptrs {
                    if let Some(program) = &func_ptr.program {
                        self.obj
                            .struct_ops_attachments
                            .entry(program.clone())
                            .or_insert_with(|| StructOpsAttachment {
                                type_id: self.type_id,
                                member_name: func_ptr.name.clone(),
                                attach_target: None,
                            });
                    }
                }

                let symbol_index = FIRST_SYMBOL_INDEX + self.obj.struct_ops.len();
                self.obj.struct_ops.insert(
                    name.to_string(),
                    StructOpsInfo {
                        type_id: self.type_id,
                        struct_name: STRUCT_NAME.to_string(),
                        is_link,
                        is_optional: false,
                        data,
                        section_index: SECTION_INDEX,
                        symbol_index,
                        func_ptrs,
                    },
                );
                self
            }

            /// Marks an instance as coming from a `?` section.
            fn optional(mut self, name: &str) -> Self {
                self.obj.struct_ops.get_mut(name).unwrap().is_optional = true;
                self
            }

            fn resolve(&mut self) -> Result<(), StructOpsError> {
                self.obj
                    .resolve_struct_ops(&self.kernel_btf, &HashSet::new())
            }

            /// The resolved map for an instance.
            fn map(&self, name: &str) -> &StructOpsMap {
                struct_ops_map(&self.obj, name)
            }

            /// Where a program was resolved to attach: (kernel type id, member index).
            fn attach_target(&self, program: &str) -> Option<(u32, u32)> {
                self.obj.struct_ops_attachments[program]
                    .attach_target
                    .map(|target| (target.kernel_type_id, target.member_index))
            }

            fn kernel_type_id(&self, name: &str) -> u32 {
                self.kernel_btf
                    .id_by_type_name_kind(name, BtfKind::Struct)
                    .unwrap()
            }
        }

        /// The resolved map for an instance.
        fn struct_ops_map<'a>(obj: &'a Object, name: &str) -> &'a StructOpsMap {
            match &obj.maps[name] {
                Map::StructOps(map) => map,
                other => panic!("{name} is not a struct_ops map: {other:?}"),
            }
        }

        /// (member name, program name, value offset) of each program slot, by offset.
        fn slots(map: &StructOpsMap) -> Vec<(&str, &str, usize)> {
            let mut slots: Vec<_> = map
                .programs
                .iter()
                .map(|slot| {
                    (
                        slot.member_name.as_str(),
                        slot.program.as_str(),
                        slot.value_offset,
                    )
                })
                .collect();
            slots.sort_by_key(|slot| slot.2);
            slots
        }

        #[test]
        fn translates_instance_into_kernel_layout() {
            // The kernel has an extra leading member and a different order.
            let kernel_members: Members<'_> = &[
                ("next", Ty::Ptr),
                ("dequeue", Ty::FnPtr),
                ("flags", Ty::Int(4)),
                ("enqueue", Ty::FnPtr),
                ("id", Ty::Array(16)),
            ];
            let values: &[(&str, &[u8])] = &[("id", b"bpf_fifo"), ("flags", &[1, 2, 3, 4])];
            let mut t = fixture(MEMBERS, kernel_members).instance(
                "fifo",
                values,
                &[("enqueue", "prog_enqueue"), ("dequeue", "prog_dequeue")],
            );
            t.resolve().unwrap();

            assert!(t.obj.struct_ops.is_empty());
            let map = t.map("fifo");

            // Scalars are at the kernel's offsets and nothing else is set.
            assert_eq!(map.data, expected_value(kernel_members, values));
            assert_eq!(
                slots(map),
                [
                    (
                        "dequeue",
                        "prog_dequeue",
                        DATA_OFFSET + offset_of(kernel_members, "dequeue")
                    ),
                    (
                        "enqueue",
                        "prog_enqueue",
                        DATA_OFFSET + offset_of(kernel_members, "enqueue")
                    ),
                ]
            );

            // Programs attach to the member's index in the kernel's struct.
            let kernel_type_id = t.kernel_type_id(STRUCT_NAME);
            assert_eq!(t.attach_target("prog_dequeue"), Some((kernel_type_id, 1)));
            assert_eq!(t.attach_target("prog_enqueue"), Some((kernel_type_id, 3)));

            assert_eq!(map.def.map_type, BPF_MAP_TYPE_STRUCT_OPS as u32);
            assert_eq!(map.def.key_size, 4);
            assert_eq!(
                map.def.value_size as usize,
                DATA_OFFSET + struct_size(kernel_members)
            );
            assert_eq!(map.def.max_entries, 1);
            assert_eq!(map.def.map_flags, 0);
            assert_eq!(map.def.btf_key_type_id, 0);
            assert_eq!(map.def.btf_value_type_id, 0);
            assert_eq!(
                map.btf_vmlinux_value_type_id,
                t.kernel_type_id(WRAPPER_NAME)
            );
            // Members that are not function pointers can be set by name.
            assert_eq!(
                map.members,
                [("next", 8), ("flags", 4), ("id", 16)].map(|(name, size)| StructOpsMember {
                    name: name.to_owned(),
                    value_offset: DATA_OFFSET + offset_of(kernel_members, name),
                    size,
                })
            );

            assert_eq!(map.struct_name, STRUCT_NAME);
            assert_eq!(map.section_index, SECTION_INDEX);
            assert_eq!(map.symbol_index, FIRST_SYMBOL_INDEX);
        }

        #[test]
        fn link_instance_gets_link_flag() {
            let mut t = fixture(MEMBERS, MEMBERS)
                .instance("plain", &[], &[])
                .link_instance("link", &[], &[]);
            t.resolve().unwrap();

            assert_eq!(t.map("plain").def.map_flags, 0);
            assert!(!t.map("plain").is_link);
            assert_eq!(t.map("link").def.map_flags, BPF_F_LINK);
            assert!(t.map("link").is_link);
        }

        #[test]
        fn object_struct_can_be_subset_of_kernel_struct() {
            let values: &[(&str, &[u8])] = &[("flags", &[1, 2, 3, 4])];
            let mut t = fixture(&[("flags", Ty::Int(4))], MEMBERS).instance("inst", values, &[]);
            t.resolve().unwrap();

            assert_eq!(t.map("inst").data, expected_value(MEMBERS, values));
        }

        #[test]
        fn zeroed_member_missing_from_kernel_is_accepted() {
            let mut t = fixture(&[("flags", Ty::Int(4)), ("extra", Ty::Int(4))], MEMBERS).instance(
                "inst",
                &[("flags", &[1, 2, 3, 4])],
                &[],
            );
            t.resolve().unwrap();

            assert_eq!(
                t.map("inst").data,
                expected_value(MEMBERS, &[("flags", &[1, 2, 3, 4])])
            );
        }

        #[test]
        fn typedefs_and_modifiers_are_skipped() {
            let plain: Members<'_> = &[("flags", Ty::Int(4))];
            let wrapped: Members<'_> = &[("flags", Ty::TypedefInt(4))];
            let values: &[(&str, &[u8])] = &[("flags", &[1, 2, 3, 4])];

            for (obj_members, kernel_members) in [(wrapped, plain), (plain, wrapped)] {
                let mut t = fixture(obj_members, kernel_members).instance("inst", values, &[]);
                t.resolve().unwrap();

                assert_eq!(t.map("inst").data, expected_value(kernel_members, values));
            }
        }

        #[test]
        fn function_pointer_without_program_is_left_unset() {
            // The kernel does not even have `peek`.
            let mut t = fixture(&[("enqueue", Ty::FnPtr), ("peek", Ty::FnPtr)], MEMBERS).instance(
                "inst",
                &[],
                &[("enqueue", "prog_enqueue")],
            );
            t.resolve().unwrap();

            let map = t.map("inst");
            assert_eq!(
                slots(map),
                [(
                    "enqueue",
                    "prog_enqueue",
                    DATA_OFFSET + offset_of(MEMBERS, "enqueue")
                )]
            );
            assert_eq!(map.data, expected_value(MEMBERS, &[]));
            assert_eq!(t.obj.struct_ops_attachments.len(), 1);
        }

        #[test]
        fn instances_can_share_programs() {
            let programs = &[("enqueue", "prog_enqueue"), ("dequeue", "prog_dequeue")];
            let mut t = fixture(MEMBERS, MEMBERS)
                .instance("first", &[], programs)
                .link_instance("second", &[], programs);
            t.resolve().unwrap();

            assert_eq!(slots(t.map("first")), slots(t.map("second")));
            assert_eq!(slots(t.map("first")).len(), 2);
            let kernel_type_id = t.kernel_type_id(STRUCT_NAME);
            assert_eq!(t.attach_target("prog_enqueue"), Some((kernel_type_id, 2)));
            assert_eq!(t.attach_target("prog_dequeue"), Some((kernel_type_id, 3)));
        }

        #[test]
        fn no_instances_needs_no_btf() {
            let mut obj = fake_obj();
            assert!(obj.btf.is_none());

            obj.resolve_struct_ops(&Btf::new(), &HashSet::new())
                .unwrap();

            assert!(obj.maps.is_empty());
        }

        #[test]
        fn member_kind_mismatch() {
            let mut t =
                fixture(&[("flags", Ty::Int(8))], &[("flags", Ty::Ptr)]).instance("inst", &[], &[]);

            assert_matches!(
                t.resolve(),
                Err(StructOpsError::MemberKindMismatch {
                    member,
                    kind: BtfKind::Int,
                    kernel_kind: BtfKind::Ptr,
                    ..
                }) if member == "flags"
            );
        }

        #[test]
        fn member_size_mismatch() {
            // `id` matches; only `flags` differs.
            let mut t = fixture(
                &[("id", Ty::Array(16)), ("flags", Ty::Int(4))],
                &[("id", Ty::Array(16)), ("flags", Ty::Int(8))],
            )
            .instance("inst", &[], &[]);

            assert_matches!(
                t.resolve(),
                Err(StructOpsError::MemberSizeMismatch {
                    member,
                    size: 4,
                    kernel_size: 8,
                    ..
                }) if member == "flags"
            );
        }

        #[test]
        fn kernel_struct_not_found() {
            let mut t = fixture(MEMBERS, MEMBERS).instance("inst", &[], &[]);
            t.kernel_btf = Btf::new();

            assert_matches!(
                t.resolve(),
                Err(StructOpsError::KernelTypeNotFound { name, type_name })
                    if name == "inst" && type_name == STRUCT_NAME
            );
        }

        #[test]
        fn kernel_wrapper_not_found() {
            let mut t = fixture(MEMBERS, MEMBERS).instance("inst", &[], &[]);
            // The struct exists, but the kernel never registered it as a
            // struct_ops type.
            t.kernel_btf = Btf::new();
            fake_struct(&mut t.kernel_btf, STRUCT_NAME, MEMBERS);

            assert_matches!(
                t.resolve(),
                Err(StructOpsError::KernelTypeNotFound { name, type_name })
                    if name == "inst" && type_name == WRAPPER_NAME
            );
        }

        #[test]
        fn wrapper_without_data_member() {
            let mut t = fixture(MEMBERS, MEMBERS).instance("inst", &[], &[]);
            t.kernel_btf = Btf::new();
            fake_struct(&mut t.kernel_btf, STRUCT_NAME, MEMBERS);
            // The wrapper's `data` member is of some other type.
            let other = fake_type(&mut t.kernel_btf, Ty::Int(8));
            fake_wrapper(&mut t.kernel_btf, STRUCT_NAME, other);

            assert_matches!(
                t.resolve(),
                Err(StructOpsError::WrapperDataMemberNotFound { wrapper_name, struct_name, .. })
                    if wrapper_name == WRAPPER_NAME && struct_name == STRUCT_NAME
            );
        }

        #[test]
        fn set_member_missing_from_kernel() {
            let mut t = fixture(&[("flags", Ty::Int(4)), ("extra", Ty::Int(4))], MEMBERS).instance(
                "inst",
                &[("extra", &[1])],
                &[],
            );

            assert_matches!(
                t.resolve(),
                Err(StructOpsError::MemberNotFound { member, struct_name, .. })
                    if member == "extra" && struct_name == STRUCT_NAME
            );
        }

        #[test]
        fn bitfield_members_are_rejected() {
            let int: Members<'_> = &[("id", Ty::Array(16)), ("flags", Ty::Int(4))];
            let bitfield: Members<'_> = &[("id", Ty::Array(16)), ("flags", Ty::Bitfield)];
            let legacy: Members<'_> = &[("id", Ty::Array(16)), ("flags", Ty::LegacyBitfield)];

            for (obj_members, kernel_members) in [
                (bitfield, int),
                (legacy, int),
                (int, bitfield),
                (int, legacy),
            ] {
                let mut t = fixture(obj_members, kernel_members).instance("inst", &[], &[]);

                assert_matches!(
                    t.resolve(),
                    Err(StructOpsError::BitfieldMember { member, .. }) if member == "flags"
                );
            }
        }

        #[test]
        fn member_past_instance_bytes() {
            let mut t = fixture(MEMBERS, MEMBERS).instance("inst", &[], &[]);
            // Only `id` and half of `flags` are left.
            t.obj.struct_ops.get_mut("inst").unwrap().data.truncate(18);

            assert_matches!(
                t.resolve(),
                Err(StructOpsError::MemberOutOfBounds {
                    member,
                    offset: 16,
                    size: 4,
                    len: 18,
                    ..
                }) if member == "flags"
            );
        }

        #[test]
        fn program_on_kernel_member_that_is_not_a_function_pointer() {
            let obj_members: Members<'_> = &[("enqueue", Ty::FnPtr)];

            for kernel_ty in [Ty::Array(8), Ty::Ptr] {
                let mut t = fixture(obj_members, &[("enqueue", kernel_ty)]).instance(
                    "inst",
                    &[],
                    &[("enqueue", "prog_enqueue")],
                );

                assert_matches!(
                    t.resolve(),
                    Err(StructOpsError::NotAFunctionPointer { member, .. }) if member == "enqueue"
                );
            }
        }

        #[test]
        fn program_on_member_missing_from_kernel() {
            let mut t = fixture(&[("enqueue", Ty::FnPtr), ("peek", Ty::FnPtr)], MEMBERS).instance(
                "inst",
                &[],
                &[("peek", "prog_peek")],
            );

            assert_matches!(
                t.resolve(),
                Err(StructOpsError::MemberNotFound { member, .. }) if member == "peek"
            );
        }

        #[test]
        fn optional_instance_is_skipped_by_default() {
            // `opt` sets a member the kernel lacks, so resolving it would fail.
            let mut t = fixture(&[("flags", Ty::Int(4)), ("extra", Ty::Int(4))], MEMBERS)
                .instance("plain", &[], &[])
                .instance("opt", &[("extra", &[1])], &[])
                .optional("opt");
            t.resolve().unwrap();

            assert!(t.obj.maps.contains_key("plain"));
            assert!(!t.obj.maps.contains_key("opt"));
            assert_eq!(t.obj.struct_ops.keys().collect::<Vec<_>>(), ["opt"]);
        }

        #[test]
        fn optional_instance_resolves_when_asked_for() {
            let mut t = fixture(MEMBERS, MEMBERS)
                .instance("opt", &[], &[("enqueue", "prog_enqueue")])
                .optional("opt");
            t.obj
                .resolve_struct_ops(&t.kernel_btf, &HashSet::from(["opt"]))
                .unwrap();

            assert!(t.map("opt").is_optional);
            assert!(t.obj.struct_ops.is_empty());
            assert!(t.attach_target("prog_enqueue").is_some());
        }

        #[test]
        fn failed_resolve_leaves_object_unchanged() {
            // `bad` pairs a valid member before one the kernel lacks.
            let obj_members: Members<'_> = &[("enqueue", Ty::FnPtr), ("peek", Ty::FnPtr)];
            let mut t = fixture(obj_members, MEMBERS)
                .instance("good", &[], &[("enqueue", "prog_enqueue")])
                .instance(
                    "bad",
                    &[],
                    &[("enqueue", "prog_enqueue"), ("peek", "prog_peek")],
                );

            assert_matches!(t.resolve(), Err(StructOpsError::MemberNotFound { .. }));
            assert!(t.obj.maps.is_empty());
            assert_eq!(t.obj.struct_ops.len(), 2);
            assert_eq!(t.attach_target("prog_enqueue"), None);

            // Drop the pairing the kernel cannot take, and try again.
            let bad = t.obj.struct_ops.get_mut("bad").unwrap();
            bad.func_ptrs
                .iter_mut()
                .find(|f| f.name == "peek")
                .unwrap()
                .program = None;
            t.resolve().unwrap();

            assert_eq!(t.obj.maps.len(), 2);
            assert!(t.obj.struct_ops.is_empty());
            assert_eq!(
                t.attach_target("prog_enqueue"),
                Some((t.kernel_type_id(STRUCT_NAME), 2))
            );
        }

        #[test]
        fn parsed_instance_resolves() {
            // Parse an instance with the parser's fixtures: `id` at 0x10,
            // `enqueue` at 0x28 and `dequeue` at 0x30 of a 176 byte struct.
            let mut obj = fake_obj();
            let mut btf = Btf::new();
            let fake_type_info = fake_qdisc_type_info(&mut btf);
            fake_qdisc_ops_instance(&mut btf, &fake_type_info, false, "fifo");

            let relocs = fake_relocations(
                &mut obj,
                "struct_ops",
                PROGRAM_SECTION_INDEX_OFFSET,
                &[
                    ("id", None),
                    ("enqueue", Some(("bpf_fifo_enqueue", 0x28))),
                    ("dequeue", Some(("bpf_fifo_dequeue", 0x30))),
                ],
            );
            let symbol_index = fake_sym_with_kind(
                &mut obj,
                STRUCT_OPS_SECTION_INDEX,
                SymbolKind::Data,
                0,
                "fifo",
                176,
            );

            let btf_data = btf.to_bytes();
            obj.parse_section(fake_section(EbpfSectionKind::Btf, ".BTF", &btf_data, None))
                .unwrap();

            let mut data = vec![0u8; 176];
            data[0x10..0x10 + 8].copy_from_slice(b"bpf_fifo");
            obj.parse_section(fake_struct_ops_section(
                STRUCT_OPS_SECTION_INDEX,
                &data,
                relocs,
            ))
            .unwrap();

            // The kernel lays the struct out differently.
            let kernel_members: Members<'_> = &[
                ("next", Ty::Ptr),
                ("dequeue", Ty::FnPtr),
                ("id", Ty::Array(16)),
                ("enqueue", Ty::FnPtr),
            ];
            let kernel_btf = fake_kernel_btf("Qdisc_ops", kernel_members);
            obj.resolve_struct_ops(&kernel_btf, &HashSet::new())
                .unwrap();

            let map = struct_ops_map(&obj, "fifo");
            assert_eq!(
                map.data,
                expected_value(kernel_members, &[("id", b"bpf_fifo")])
            );
            assert_eq!(
                slots(map),
                [
                    (
                        "dequeue",
                        "bpf_fifo_dequeue",
                        DATA_OFFSET + offset_of(kernel_members, "dequeue")
                    ),
                    (
                        "enqueue",
                        "bpf_fifo_enqueue",
                        DATA_OFFSET + offset_of(kernel_members, "enqueue")
                    ),
                ]
            );
            assert_eq!(map.struct_name, "Qdisc_ops");
            assert_eq!(map.section_index, STRUCT_OPS_SECTION_INDEX);
            assert_eq!(map.symbol_index, symbol_index);

            let kernel_type_id = kernel_btf
                .id_by_type_name_kind("Qdisc_ops", BtfKind::Struct)
                .unwrap();
            for (program, member_index) in [("bpf_fifo_dequeue", 1), ("bpf_fifo_enqueue", 3)] {
                assert_eq!(
                    obj.struct_ops_attachments[program].attach_target,
                    Some(StructOpsAttachTarget {
                        kernel_type_id,
                        member_index,
                    })
                );
            }
        }
    }
}
