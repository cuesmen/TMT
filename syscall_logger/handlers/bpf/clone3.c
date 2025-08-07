@include

@data

@fillfromtask

BPF_RINGBUF_OUTPUT(clone3_output, 1);

/*
 * clone and clone3 must use kprobe
 */
int trace_clone3(struct pt_regs *ctx) {

    struct data_t data = {};
    fill_task_data(&data);

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.child_pid = PT_REGS_RC(ctx);  // Return value of clone
    data.tid = ((struct task_struct *)bpf_get_current_task())->pid;

	clone3_output.ringbuf_output(&data, sizeof(data), 0);

    return 0;
}