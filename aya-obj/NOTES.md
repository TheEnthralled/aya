
❯ As for struct_ops support, it seems like the work to support it can be contained entirely in aya's loader. What needs to be changed? What docs should I look at to understand how to understand ex.: trampolines? Don't write any code for me.

Let me ground this in the actual code paths rather than describe from memory: what aya main already knows about struct_ops, how libbpf does the load (it is the reference implementation), and which kernel documents exist.

  Ran 2 shell commands

Yes, it can live entirely in the loader. On the eBPF side you already produce what libbpf consumes: the Qdisc_ops static in .struct_ops.link with relocations to your callbacks, the callbacks in struct_ops/<member> sections, and BTF for all of it. aya main has only stubs today: the map-type and program-type enum variants, and BPF_MAP_TYPE_STRUCT_OPS => Unsupported in the map loader. Below is what has to exist, in libbpf's order, with the libbpf function names as reading anchors since libbpf is the reference implementation.

What the loader must do

1. Parse the struct_ops sections as map definitions (init_struct_ops_maps). .struct_ops and .struct_ops.link (and their ?-prefixed optional variants) are data sections where each variable is one map, named after the static. Record its raw bytes and its local BTF type (Qdisc_ops, found through the DATASEC's VAR entries). .link means map flag BPF_F_LINK. This is aya-obj work, in obj.rs and maps.rs.
2. Recognise struct_ops/<member> program sections as a new ProgramSection carrying the member name, with program type STRUCT_OPS. ayadocumentation but doesn't parse it.
3. Collect the data relocations (bpf_object__collect_st_ops_relos). Each entry in .rel.struct_ops.maps a byte offset inside the staching the offset against the localstruct's member offsets tells you which program implements which member. This is what replaces "naming conventions": the pairing
4. Find the kernel types (find_struct_ops_kern_types). From the local type name, look up Qdisc_opsthe wrapper bpf_struct_ops_Qdisc_F for module-provided ops). Thewrapper's size is the map value size, its BTF id is btf_vmlinux_value_type_id, and its data    member's offset is where the ops .
5. Member-wise copy into the kernel layout (bpf_map__init_kern_struct_ops). For each local member,find the kernel member by name, nnd arrays (id, priv_size,static_flags) at the kernel's offsets. For function-pointer members, record which program fillsthem, and set that program's atta_ops type id and expected_attach_type to the kernel member index. A local member missing from the kernel struct disables its program rather than failing, which is howoss kernel versions.
6. Load programs with those two attach fields set (plus attach_btf_obj_fd when the type came from module BTF). The kernel takes theel member's prototype, not from yourprogram's BTF.
7. Create and populate the map: BPF_e and BTF id from step 4, then writeeach program's fd into its function-pointer slot in the kernel-layout value and BPF_MAP_UPDATE_ELEM
   key 0. That single update trigger_map_update_elem: per-member checks, init_member, trampoline preparation, validate, and for non-link maps reg() immediately.
8. Attach for .link maps: BPF_LINK_Cruct_ops_link_create) calls reg(),meaning the qdisc becomes registered under its id name; closing the link unregisters it, and
   BPF_LINK_UPDATE can swap in a newis a StructOps program type and aStructOpsMap, plus the wiring through the Program enum macros, which is the largest mechanical part
   of PR #1495.

Two aya-specific details: aya-obj's le the struct_ops sections withoutturning them into ordinary data maps, and the map's BTF must not be uploaded with the local Qdisc_ops
as value type, since the kernel want

Trampolines, and what you need to kn

Nothing in the loader touches them, ns the attach fields. Kernel C codecalls ops->enqueue() through an ordinary function pointer, so the kernel needs native code at that
address. When you update the map, bpne calls arch_prepare_bpf_trampolinewith BPF_TRAMP_F_INDIRECT to generate, per member, a small stub that saves the C arguments into an
array on the stack and calls your BPits context. That is why struct_opsprograms receive arguments like fentry programs do, why the verifier checks each argument against the
kernel prototype for that member (atcate the prototype), and why thekernel, not you, decides what enqueue may do with the skb it receives.

Reading list, in order

- tools/lib/bpf/libbpf.c at v6.18, the eight functions above; bpf_map__attach_struct_ops for the link
  path.
- kernel/bpf/bpf_struct_ops.c: bpf_struct_ops_map_update_elem (the checks your map update must pass)
  and bpf_struct_ops_prepare_trampoland arch_prepare_bpf_trampoline inarch/x86/net/bpf_jit_comp.c for the mechanism.
- net/sched/bpf_qdisc.c: init_memberreg for Qdisc_ops, which say what idmust contain, which callbacks are mandatory, and which Qdisc/sk_buff fields are writable.
- The kernel has no prose document fare the documentation:tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c, bpf_qdisc_fq.c, bpf_qdisc_common.h, and
  prog_tests/bpf_qdisc.c for the use
- Documentation/bpf/btf.rst (DATASEC/VAR, FUNC linkage) and Documentation/bpf/verifier.rst;
  Documentation/scheduler/sched-ext._ops consumer.
- The original cover letters, which explain the design better than any doc: "Introduce BPF trampoline"
  (Alexei Starovoitov, November 2019PS" (Martin KaFai Lau,January 2020), both on lore.kernel.org.
- docs.ebpf.io pages for BPF_PROG_TYTRUCT_OPS and Qdisc_ops, and aya PR#1495's aya/src/programs/struct_ops.rs as a Rust transcription of the same steps, stale but
  structurally useful.

Before writing any of it, one empiriause it is the only step that depends on the Rust toolchain: build the crate with your Qdisc_ops static and confirm with llvm-readelf -r that .rel.struct_ops.link has relocaueue, and with bpftool btf dump filethat the object BTF has a DATASEC '.struct_ops.link' whose VAR points at Qdisc_ops. If both are there, everything above is loader-only.
