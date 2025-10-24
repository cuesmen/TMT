@include

@data

@fillfromtask

@common_maps

BPF_RINGBUF_OUTPUT(exit_group_output, 1);

/*
 * Trace the exit_group(2) syscall (process-wide termination).
 * We hook the entry tracepoint and just record the event.
 */
int trace_exit_group(struct tracepoint__syscalls__sys_enter_exit_group *ctx)
{
    if (!producer_enabled())
        return 0;

    struct data_t data = {};
    fill_task_data(&data);

    // caller pid/tid
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // event timestamp
    data.timestamp = bpf_ktime_get_ns();

    int ret = exit_group_output.ringbuf_output(&data, sizeof(data), 0);
    if (ret == 0) inc_ev_count();
    return 0;
}
