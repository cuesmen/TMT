#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cfg_enabled SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ev_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} clone3_output SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_clone3")
int trace_clone3_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!producer_enabled(&cfg_enabled))
        return 0;

    long child = ctx->ret;
    if (child <= 0)
        return 0;

    struct data_t d = {};
    fill_task_data(&d);
    d.child_pid = (int)child;
    d.timestamp = bpf_ktime_get_ns();

    if (bpf_ringbuf_output(&clone3_output, &d, sizeof(d), 0) == 0)
        inc_ev_count(&ev_count);
    return 0;
}
