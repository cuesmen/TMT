@include

@data

@fillfromtask

@common_maps

// Ring buffers for execve entry and exit events
BPF_RINGBUF_OUTPUT(execve_output_in, 1);
BPF_RINGBUF_OUTPUT(execve_output_out, 1);

struct tracepoint__syscall__sys_enter_execve;
struct tracepoint__syscall__sys_exit_execve;

/*
 * Trace sys_enter_execve to capture process start.
 */
int trace_execve(struct tracepoint__syscall__sys_enter_execve * ctx){
    if (!producer_enabled())
        return 0;

    struct data_t data = {};
    fill_task_data(&data);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.timestamp = bpf_ktime_get_ns();

    // Emit entry event
    int ret = execve_output_in.ringbuf_output(&data, sizeof(data), 0);
    if (ret == 0) inc_ev_count();
    return 0;
}

/*
 * Trace sys_exit_execve to capture process exit result.
 */
int trace_execve_exit(struct tracepoint__syscall__sys_exit_execve * ctx){
    if (!producer_enabled())
        return 0;

    struct data_t data = {};
    fill_task_data(&data);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.timestamp = bpf_ktime_get_ns();

    // Emit exit event
    int ret = execve_output_out.ringbuf_output(&data, sizeof(data), 0);
    if (ret == 0) inc_ev_count();
    return 0;
}
