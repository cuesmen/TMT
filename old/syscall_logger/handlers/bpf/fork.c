@include

@data

@fillfromtask

@common_maps

BPF_RINGBUF_OUTPUT(fork_output, 1);

/*
 * Trace sched:sched_process_fork to capture parent/child pids.
 * This is a tracepoint (not kprobe) and already provides both pids.
 */
int trace_fork(struct tracepoint__sched__sched_process_fork *ctx)
{
    if (!producer_enabled())
        return 0;

    struct data_t data = {};

    // parent/child pids come from the tracepoint args
    data.pid       = ctx->parent_pid;
    data.child_pid = ctx->child_pid;

    // enrich with current task info (comm, pgid/tgid, etc.)
    fill_task_data(&data);

    // timestamp for ordering/correlation
    data.timestamp = bpf_ktime_get_ns();

    int ret = fork_output.ringbuf_output(&data, sizeof(data), 0);
    if (ret == 0) inc_ev_count();
    return 0;
}
