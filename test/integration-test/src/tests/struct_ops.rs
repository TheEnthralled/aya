//! `struct_ops` instances, tested with a TCP congestion control algorithm.

use std::{
    fs, io,
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::fd::AsRawFd as _,
};

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, StructOpsError},
    programs::ProgramError,
    test_helpers::NetNsGuard,
    util::KernelVersion,
};
use test_log::test;

/// Whether the running kernel can register a `struct_ops` instance, through
/// a link if `link` is set.
fn struct_ops_supported(link: bool) -> bool {
    let kernel_version = KernelVersion::current().unwrap();
    let minimum = if link {
        // v6.4 (68b04864ca42, "bpf: Create links for BPF struct_ops maps.").
        KernelVersion::new(6, 4, 0)
    } else if cfg!(target_arch = "aarch64") {
        // The programs of an instance are called through a trampoline, which
        // arm64 has since v6.0 (efc9909fdce0, "bpf, arm64: Add bpf trampoline
        // for arm64").
        KernelVersion::new(6, 0, 0)
    } else {
        // v5.6 (0baf26b0fcd7, "bpf: tcp: Support tcp_congestion_ops in bpf").
        KernelVersion::new(5, 6, 0)
    };
    if kernel_version < minimum {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, struct_ops support requires {minimum:?}"
        );
        return false;
    }
    true
}

/// Whether the kernel has a congestion control algorithm with this name.
fn registered(name: &str) -> bool {
    fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
        .unwrap()
        .split_whitespace()
        .any(|algorithm| algorithm == name)
}

/// Switches a new connection over loopback to the algorithm with this name.
fn use_congestion_control(name: &str) -> io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let stream = TcpStream::connect(listener.local_addr()?)?;
    let ret = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The number of sockets that switched to an algorithm of the test object.
fn init_calls(bpf: &Ebpf) -> u64 {
    let init_calls: Array<_, u64> = bpf.map("init_calls").unwrap().try_into().unwrap();
    init_calls.get(&0, 0).unwrap()
}

#[test]
fn struct_ops() {
    if !struct_ops_supported(false) {
        return;
    }
    let _netns = NetNsGuard::new().unwrap();

    let mut bpf = Ebpf::load(crate::STRUCT_OPS).unwrap();
    // An instance in a `?` section is not created unless asked for.
    assert!(bpf.struct_ops_mut("aya_link").is_none());

    let mut plain = bpf.struct_ops_mut("aya_plain").unwrap();
    assert_eq!(plain.struct_name(), "tcp_congestion_ops");

    // The programs have to be loaded first.
    assert_matches!(
        plain.attach(),
        Err(StructOpsError::ProgramError(ProgramError::NotLoaded))
    );
    plain.load().unwrap();
    assert!(!plain.is_attached());
    assert!(!registered("aya_plain"));

    plain.attach().unwrap();
    assert!(plain.is_attached());
    assert!(registered("aya_plain"));
    assert_matches!(plain.attach(), Err(StructOpsError::AlreadyAttached));
    assert_matches!(
        plain.set_member("name", b"too_late"),
        Err(StructOpsError::ValueAlreadyWritten)
    );

    // The kernel calls the programs of the instance.
    use_congestion_control("aya_plain").unwrap();
    assert_eq!(init_calls(&bpf), 1);

    let mut plain = bpf.struct_ops_mut("aya_plain").unwrap();
    plain.detach().unwrap();
    assert!(!plain.is_attached());
    assert!(!registered("aya_plain"));
    assert_matches!(plain.detach(), Err(StructOpsError::NotAttached));
    assert_matches!(
        use_congestion_control("aya_plain"),
        Err(err) if err.kind() == io::ErrorKind::NotFound
    );
}

#[test]
fn struct_ops_set_member() {
    if !struct_ops_supported(false) {
        return;
    }
    let _netns = NetNsGuard::new().unwrap();

    let mut bpf = Ebpf::load(crate::STRUCT_OPS).unwrap();
    let mut plain = bpf.struct_ops_mut("aya_plain").unwrap();

    // Function pointers are set by the object's programs, and members the
    // kernel's struct does not have cannot be set at all.
    for member in ["cong_avoid", "no_such_member"] {
        assert_matches!(
            plain.set_member(member, &[0]),
            Err(StructOpsError::InvalidMember { struct_name, member: invalid })
                if struct_name == "tcp_congestion_ops" && invalid == member
        );
    }
    assert_matches!(
        plain.set_member("name", &[b'a'; 17]),
        Err(StructOpsError::ValueTooLarge { member, len: 17, size: 16 }) if member == "name"
    );

    // The algorithm is registered under the name set here, not the one in
    // the object.
    plain.set_member("name", b"aya_renamed").unwrap();
    plain.load().unwrap();
    plain.attach().unwrap();
    assert!(registered("aya_renamed"));
    assert!(!registered("aya_plain"));

    use_congestion_control("aya_renamed").unwrap();
    assert_eq!(init_calls(&bpf), 1);
}

#[test]
fn struct_ops_detached_on_drop() {
    if !struct_ops_supported(false) {
        return;
    }
    let _netns = NetNsGuard::new().unwrap();

    let mut bpf = Ebpf::load(crate::STRUCT_OPS).unwrap();
    let mut plain = bpf.struct_ops_mut("aya_plain").unwrap();
    plain.load().unwrap();
    plain.attach().unwrap();
    assert!(registered("aya_plain"));

    // The kernel keeps an instance without a link registered after its file
    // descriptors are closed, so dropping it has to unregister it.
    drop(bpf);
    assert!(!registered("aya_plain"));
}

#[test]
fn struct_ops_link() {
    if !struct_ops_supported(true) {
        return;
    }
    let _netns = NetNsGuard::new().unwrap();

    let mut bpf = EbpfLoader::new()
        .create_struct_ops("aya_link")
        .load(crate::STRUCT_OPS)
        .unwrap();
    let mut link = bpf.struct_ops_mut("aya_link").unwrap();
    link.load().unwrap();
    assert!(!registered("aya_link"));

    link.attach().unwrap();
    assert!(link.is_attached());
    assert!(registered("aya_link"));
    assert_matches!(link.attach(), Err(StructOpsError::AlreadyAttached));

    use_congestion_control("aya_link").unwrap();
    assert_eq!(init_calls(&bpf), 1);

    let mut link = bpf.struct_ops_mut("aya_link").unwrap();
    link.detach().unwrap();
    assert!(!registered("aya_link"));

    // An instance with a link can be registered again.
    link.attach().unwrap();
    assert!(registered("aya_link"));

    drop(bpf);
    assert!(!registered("aya_link"));
}

/// The algorithm of [`struct_ops`], written in Rust with the `struct_ops`
/// macro.
#[test]
fn struct_ops_macro() {
    if !struct_ops_supported(false) {
        return;
    }
    let _netns = NetNsGuard::new().unwrap();

    let mut bpf = Ebpf::load(crate::STRUCT_OPS_MACRO).unwrap();
    // `optional` puts the instance in a `?` section.
    assert!(bpf.struct_ops_mut("macro_link").is_none());

    // The instance is named after its type.
    let mut plain = bpf.struct_ops_mut("aya_macro_plain").unwrap();
    assert_eq!(plain.struct_name(), "tcp_congestion_ops");
    plain.load().unwrap();
    plain.attach().unwrap();
    assert!(registered("aya_macro_plain"));

    use_congestion_control("aya_macro_plain").unwrap();
    assert_eq!(init_calls(&bpf), 1);

    bpf.struct_ops_mut("aya_macro_plain")
        .unwrap()
        .detach()
        .unwrap();
    assert!(!registered("aya_macro_plain"));
}

#[test]
fn struct_ops_macro_link() {
    if !struct_ops_supported(true) {
        return;
    }
    let _netns = NetNsGuard::new().unwrap();

    let mut bpf = EbpfLoader::new()
        .create_struct_ops("macro_link")
        .load(crate::STRUCT_OPS_MACRO)
        .unwrap();
    let mut link = bpf.struct_ops_mut("macro_link").unwrap();
    link.load().unwrap();
    link.attach().unwrap();
    assert!(registered("aya_macro_link"));

    use_congestion_control("aya_macro_link").unwrap();
    assert_eq!(init_calls(&bpf), 1);

    bpf.struct_ops_mut("macro_link").unwrap().detach().unwrap();
    assert!(!registered("aya_macro_link"));
}
