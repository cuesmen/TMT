@include

@data

@fillfromtask

@common_maps

BPF_RINGBUF_OUTPUT(clone3_output, 1);

/*
 * clone3: use kretprobe to read the return value (child_pid).
 * The return value is only available on syscall exit.
 */
int trace_clone3_ret(struct pt_regs *ctx) {
    if (!producer_enabled())
        return 0;

    struct data_t data = {};
    fill_task_data(&data);

    // caller pid/tid
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // return value: child pid (negative on error)
    long rc = PT_REGS_RC(ctx);
    if (rc < 0)
        return 0; // failed clone3

    data.child_pid = (int)rc;
    data.timestamp = bpf_ktime_get_ns();

    int ret = clone3_output.ringbuf_output(&data, sizeof(data), 0);
    if (ret == 0) inc_ev_count();
    return 0;
}
