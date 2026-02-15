#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} execve_counter SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    (void)ctx;

    __u64 v0 = 0;
    __u64 v1 = 0;
    __u64 v2 = 0;
    __u64 *v3 = 0;
    __u64 v4 = 0;
    __u64 v6 = 0;
    __u64 v7 = 0;
    __u64 __tmp0 = 1;

    goto __block_0;

__block_0:
    v1 = bpf_get_current_pid_tgid();
    v0 = v1 + 0;
    v2 = v0 + 0;
    v3 = bpf_map_lookup_elem(&execve_counter, &v2);
    v4 = (v3 != 0);
    if (v4) goto __block_1; else goto __block_2;

__block_1:
    if (!(v3)) goto __solnix_null_fail;
    v6 = *v3;
    v7 = v6 + 1;
    *v3 = v7;
    goto __block_3;

__block_2:
    (void)bpf_map_update_elem(&execve_counter, &v2, &__tmp0, 0);
    goto __block_3;

__block_3:
    return 0;

__solnix_null_fail:
    return 0;
}
