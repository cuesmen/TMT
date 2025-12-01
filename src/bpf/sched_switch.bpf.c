#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* enable/disable producer (key 0: 1 => on) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cfg_enabled SEC(".maps");

/* per-CPU emitted events counter (key 0) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ev_count SEC(".maps");

/* allow-list of PIDs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   
    __type(value, __u8); 
    __uint(max_entries, 8192);
} allow_pids SEC(".maps");

/* whether to use PID filter (key 0: 1 => enabled) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); 
} cfg_useFilter SEC(".maps");

/* ring buffer sched events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} sched_output SEC(".maps");

/* Userspace-facing event */
struct run_event_t {
    u64 ts;                                     // ns
    u32 cpu;                                    // CPU id
    u32 pid;                                    // PID of subject task
    u32 type;                                   // 1: switch-in, 2: switch-out
    u32 reason;                                 // 0: runnable/yield, 1: blocked (prev_state != 0)
    char comm[TASK_COMM_LEN];
    u32 parent_pid, child_pid, pgid, tid, tgid; 
    char command[TASK_COMM_LEN];
    u64 timestamp;
};

static __always_inline bool should_emit_pid(u32 pid)
{
    /* if filter is off => emit all */
    u32 k = 0;
    u32 *flag = bpf_map_lookup_elem(&cfg_useFilter, &k);
    if (!flag || *flag == 0)
        return true;

    /* emit only if PID is allow-listed */
    u8 *ok = bpf_map_lookup_elem(&allow_pids, &pid);
    return ok && *ok == 1;
}

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    if (!producer_enabled(&cfg_enabled))
        return 0;

    u64 ts  = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();
    u32 prev = ctx->prev_pid;
    u32 next = ctx->next_pid;

    /* emit switch-out for prev */
    if (should_emit_pid(prev)) {
        struct run_event_t e = {};
        e.ts = ts; e.cpu = cpu; e.pid = prev;
        e.type = 2;                                  // switch-out
        e.reason = ctx->prev_state == 0 ? 0 : 1;     // 0 runnable, 1 blocked
        bpf_probe_read_kernel_str(e.comm, sizeof(e.comm), ctx->prev_comm);
        e.tid = prev; e.tgid = prev; e.timestamp = e.ts;
        __builtin_memcpy(e.command, e.comm, sizeof(e.comm));
        if (bpf_ringbuf_output(&sched_output, &e, sizeof(e), 0) == 0)
            inc_ev_count(&ev_count);
    }

    /* emit switch-in for next */
    if (should_emit_pid(next)) {
        struct run_event_t e = {};
        e.ts = ts; e.cpu = cpu; e.pid = next;
        e.type = 1; e.reason = 0;                    // switch-in
        bpf_probe_read_kernel_str(e.comm, sizeof(e.comm), ctx->next_comm);
        e.tid = next; e.tgid = next; e.timestamp = e.ts;
        __builtin_memcpy(e.command, e.comm, sizeof(e.comm));
        if (bpf_ringbuf_output(&sched_output, &e, sizeof(e), 0) == 0)
            inc_ev_count(&ev_count);
    }
    return 0;
}

/* program that copies the allow-list entry from parent to child */
SEC("tracepoint/sched/sched_process_fork")
int propagate_allow_on_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    if (!producer_enabled(&cfg_enabled))
        return 0;

    /* skip if filter is disabled */
    u32 key = 0;
    u32 *flag = bpf_map_lookup_elem(&cfg_useFilter, &key);
    if (!flag || *flag == 0)
        return 0; 

    u32 parent = ctx->parent_pid;
    u32 child  = ctx->child_pid;


    /* if parent was allowed, allow the child 
     * some updates may be missed, but not important due to short timing window :)
     */
    u8 one = 1;
    u8 *ok = bpf_map_lookup_elem(&allow_pids, &parent);
    if (ok && *ok == 1)
        bpf_map_update_elem(&allow_pids, &child, &one, BPF_ANY);

    return 0;
}