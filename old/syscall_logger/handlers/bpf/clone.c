@include

@data

@fillfromtask

@common_maps

// Ring buffer to send clone events to user space
BPF_RINGBUF_OUTPUT(clone_output, 1);

/*
 * clone must be traced with kretprobe to capture the return value,
 * which contains the child PID (negative if clone fails).
 */
int trace_clone_ret(struct pt_regs *ctx) {
    if (!producer_enabled())
        return 0;

    struct data_t data = {};
    fill_task_data(&data);

    // Calling process identifiers
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Return value = child PID (or negative if error)
    long rc = PT_REGS_RC(ctx);
    if (rc < 0)
        return 0; // clone failed

    data.child_pid = (int)rc;
    data.timestamp = bpf_ktime_get_ns();

    // Emit event to ring buffer and update counter
    int ret = clone_output.ringbuf_output(&data, sizeof(data), 0);
    if (ret == 0) inc_ev_count();

    return 0;
}
