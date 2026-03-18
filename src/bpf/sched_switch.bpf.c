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

/*
 * Runnable depth estimation per CPU.
 * ARRAY (not PERCPU_ARRAY) so wakeup on CPU A can update target CPU B.
 */
#define MAX_TRACKED_CPUS 512
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_TRACKED_CPUS);
    __type(key, __u32);
    __type(value, u32);
} rq_depth SEC(".maps");

/*
 * Per-task runnable state used to avoid double counting wakeups and
 * to move counters correctly during migrations.
 */
struct task_rq_state {
    u32 runnable;
    u32 cpu;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);   /* pid/tid from tracepoints */
    __type(value, struct task_rq_state);
} task_state SEC(".maps");

/* Userspace-facing event */
struct run_event_t {
    u64 ts;             // ns
    u32 cpu;            // CPU id
    u32 pid;            // PID of subject task
    u32 type;           // 1: switch-in, 2: switch-out
    u32 reason;         // 0: runnable/yield, 1: blocked (prev_state != 0)
    u32 rq_depth;       // NEW (TODO remove in the next push) estimated runnable tasks on this CPU
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

static __always_inline bool cpu_key_valid(u32 cpu)
{
    return cpu < MAX_TRACKED_CPUS;
}

static __always_inline void rq_depth_inc(u32 cpu)
{
    if (!cpu_key_valid(cpu))
        return;
    u32 *depth = bpf_map_lookup_elem(&rq_depth, &cpu);
    if (!depth)
        return;
    (*depth)++;
}

static __always_inline void rq_depth_dec(u32 cpu)
{
    if (!cpu_key_valid(cpu))
        return;
    u32 *depth = bpf_map_lookup_elem(&rq_depth, &cpu);
    if (!depth)
        return;
    if (*depth > 0)
        (*depth)--;
}

static __always_inline u32 rq_depth_get(u32 cpu)
{
    if (!cpu_key_valid(cpu))
        return 0;
    u32 *depth = bpf_map_lookup_elem(&rq_depth, &cpu);
    if (!depth)
        return 0;
    return *depth;
}

static __always_inline void set_task_state(u32 pid, u32 runnable, u32 cpu)
{
    if (pid == 0)
        return;
    struct task_rq_state st = {
        .runnable = runnable,
        .cpu = cpu,
    };
    bpf_map_update_elem(&task_state, &pid, &st, BPF_ANY);
}

static __always_inline void del_task_state(u32 pid)
{
    if (pid == 0)
        return;
    bpf_map_delete_elem(&task_state, &pid);
}

/* 
 * sched_switch tracepoint:
 * - emits switch-out and switch-in
 * - updates runnable depth when a task blocks
 */
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    if (!producer_enabled(&cfg_enabled))
        return 0;

    u64 ts  = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();
    u32 prev = ctx->prev_pid;
    u32 next = ctx->next_pid;

    struct task_rq_state *prev_st = NULL;
    if (prev != 0)
        prev_st = bpf_map_lookup_elem(&task_state, &prev);

    /* 
     * If previous task is blocking (prev_state != 0),
     * it leaves the runqueue -> decrement rq_depth.
     */
    if (ctx->prev_state != 0) {
        /* Decrement only if we knew the task as runnable. */
        if (prev_st && prev_st->runnable)
            rq_depth_dec(cpu);
        set_task_state(prev, 0, cpu);
    } else {
        /* Still runnable after desched (yield/preempt/time slice end). */
        set_task_state(prev, 1, cpu);
    }

    /* Current running task is runnable on this CPU. */
    set_task_state(next, 1, cpu);

    u32 curr_depth = rq_depth_get(cpu);

    /* emit switch-out for prev */
    if (should_emit_pid(prev)) {
        struct run_event_t e = {};
        e.ts = ts;
        e.cpu = cpu;
        e.pid = prev;
        e.type = 2;                                // switch-out
        e.reason = ctx->prev_state == 0 ? 0 : 1;   // 0 runnable, 1 blocked

        e.rq_depth = curr_depth;

        bpf_probe_read_kernel_str(e.comm, sizeof(e.comm), ctx->prev_comm);
        e.tid = prev;
        e.tgid = prev;
        e.timestamp = e.ts;
        __builtin_memcpy(e.command, e.comm, sizeof(e.comm));

        if (bpf_ringbuf_output(&sched_output, &e, sizeof(e), 0) == 0)
            inc_ev_count(&ev_count);
    }

    /* emit switch-in for next */
    if (should_emit_pid(next)) {
        struct run_event_t e = {};
        e.ts = ts;
        e.cpu = cpu;
        e.pid = next;
        e.type = 1;      // switch-in
        e.reason = 0;

        e.rq_depth = curr_depth;

        bpf_probe_read_kernel_str(e.comm, sizeof(e.comm), ctx->next_comm);
        e.tid = next;
        e.tgid = next;
        e.timestamp = e.ts;
        __builtin_memcpy(e.command, e.comm, sizeof(e.comm));

        if (bpf_ringbuf_output(&sched_output, &e, sizeof(e), 0) == 0)
            inc_ev_count(&ev_count);
    }

    return 0;
}

/*
 * sched_wakeup:
 * Task becomes runnable -> increment rq_depth
 */
SEC("tracepoint/sched/sched_wakeup")
int trace_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    if (ctx->target_cpu < 0)
        return 0;

    u32 pid = (u32)ctx->pid;
    u32 target_cpu = (u32)ctx->target_cpu;
    struct task_rq_state *st = bpf_map_lookup_elem(&task_state, &pid);

    if (st && st->runnable) {
        /* Already runnable: avoid double increment; transfer if CPU changed. */
        if (st->cpu != target_cpu) {
            rq_depth_dec(st->cpu);
            rq_depth_inc(target_cpu);
        }
        set_task_state(pid, 1, target_cpu);
        return 0;
    }

    rq_depth_inc(target_cpu);
    set_task_state(pid, 1, target_cpu);

    return 0;
}

/*
 * sched_wakeup_new:
 * Newly created task becomes runnable -> increment rq_depth
 */
SEC("tracepoint/sched/sched_wakeup_new")
int trace_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
    if (ctx->target_cpu < 0)
        return 0;

    u32 pid = (u32)ctx->pid;
    u32 target_cpu = (u32)ctx->target_cpu;
    struct task_rq_state *st = bpf_map_lookup_elem(&task_state, &pid);

    if (st && st->runnable) {
        if (st->cpu != target_cpu) {
            rq_depth_dec(st->cpu);
            rq_depth_inc(target_cpu);
        }
        set_task_state(pid, 1, target_cpu);
        return 0;
    }

    rq_depth_inc(target_cpu);
    set_task_state(pid, 1, target_cpu);

    return 0;
}

/*
 * sched_migrate_task:
 * If task is runnable and moves to another CPU, move depth counter as well.
 */
SEC("tracepoint/sched/sched_migrate_task")
int trace_sched_migrate_task(struct trace_event_raw_sched_migrate_task *ctx)
{
    u32 pid = (u32)ctx->pid;
    if (pid == 0 || ctx->dest_cpu < 0)
        return 0;

    u32 dest = (u32)ctx->dest_cpu;
    struct task_rq_state *st = bpf_map_lookup_elem(&task_state, &pid);
    if (!st || !st->runnable)
        return 0;

    if (st->cpu != dest) {
        rq_depth_dec(st->cpu);
        rq_depth_inc(dest);
    }
    set_task_state(pid, 1, dest);
    return 0;
}

/*
 * sched_process_exit:
 * Cleanup task state and decrement depth if task was still runnable.
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u32 pid = (u32)ctx->pid;
    struct task_rq_state *st = bpf_map_lookup_elem(&task_state, &pid);
    if (st && st->runnable)
        rq_depth_dec(st->cpu);
    del_task_state(pid);
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

    /* if parent was allowed, allow the child */
    u8 one = 1;
    u8 *ok = bpf_map_lookup_elem(&allow_pids, &parent);
    if (ok && *ok == 1)
        bpf_map_update_elem(&allow_pids, &child, &one, BPF_ANY);

    return 0;
}
