#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "include/common.h"

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
} fork_output SEC(".maps");


SEC("tracepoint/sched/sched_process_fork")
int handle_sched_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    if (!producer_enabled(&cfg_enabled))
        return 0;

    struct data_t d = {};
    fill_task_data(&d);

    d.parent_pid = ctx->parent_pid;
    d.pid = ctx->parent_pid;
    d.child_pid = ctx->child_pid;
    d.timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&d.command, sizeof(d.command));

    if (bpf_ringbuf_output(&fork_output, &d, sizeof(d), 0) == 0)
        inc_ev_count(&ev_count);

    return 0;
}
