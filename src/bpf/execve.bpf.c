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
} execve_output_in SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} execve_output_out SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    if (!producer_enabled(&cfg_enabled))
        return 0;

    struct data_t d = {};
    fill_task_data(&d);
    d.timestamp = bpf_ktime_get_ns();

    if (bpf_ringbuf_output(&execve_output_in, &d, sizeof(d), 0) == 0)
        inc_ev_count(&ev_count);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!producer_enabled(&cfg_enabled))
        return 0;

    struct data_t d = {};
    fill_task_data(&d);
    d.timestamp = bpf_ktime_get_ns();

    if (bpf_ringbuf_output(&execve_output_out, &d, sizeof(d), 0) == 0)
        inc_ev_count(&ev_count);
    return 0;
}
