// clang-format off
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// clang-format on

char _license[] SEC("license") = "GPL";

// The number of sockets that switched to one of the algorithms below.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} init_calls SEC(".maps");

static __always_inline void count_init(void) {
  __u32 key = 0;
  __u64 *calls = bpf_map_lookup_elem(&init_calls, &key);
  if (calls)
    __sync_fetch_and_add(calls, 1);
}

SEC("struct_ops/aya_init")
void BPF_PROG(aya_init, struct sock *sk) { count_init(); }

// Only the instance below that is created on request uses this program.
SEC("struct_ops/aya_link_init")
void BPF_PROG(aya_link_init, struct sock *sk) { count_init(); }

SEC("struct_ops/aya_ssthresh")
__u32 BPF_PROG(aya_ssthresh, struct sock *sk) { return 16; }

SEC("struct_ops/aya_undo_cwnd")
__u32 BPF_PROG(aya_undo_cwnd, struct sock *sk) { return 16; }

SEC("struct_ops/aya_cong_avoid")
void BPF_PROG(aya_cong_avoid, struct sock *sk, __u32 ack, __u32 acked) {}

// A congestion control algorithm that the kernel registers when the map's
// value is written.
SEC(".struct_ops")
struct tcp_congestion_ops aya_plain = {
    .init = (void *)aya_init,
    .ssthresh = (void *)aya_ssthresh,
    .undo_cwnd = (void *)aya_undo_cwnd,
    .cong_avoid = (void *)aya_cong_avoid,
    .name = "aya_plain",
};

// The same algorithm, registered through a link. Kernels before 6.4 cannot
// create it, so it is only created on request.
SEC("?.struct_ops.link")
struct tcp_congestion_ops aya_link = {
    .init = (void *)aya_link_init,
    .ssthresh = (void *)aya_ssthresh,
    .undo_cwnd = (void *)aya_undo_cwnd,
    .cong_avoid = (void *)aya_cong_avoid,
    .name = "aya_link",
};
