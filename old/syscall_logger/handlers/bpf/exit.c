@include

@data

@fillfromtask

@common_maps

BPF_RINGBUF_OUTPUT(exit_output, 1);

/*
 * Trace the exit(2) syscall. We hook the entry tracepoint.
 * No return value is needed; we just record that the task is exiting.
 */
int trace_exit(struct tracepoint__syscalls__sys_enter_exit *ctx)
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

    int ret = exit_output.ringbuf_output(&data, sizeof(data), 0);
    if (ret == 0) inc_ev_count();
    return 0;
}
