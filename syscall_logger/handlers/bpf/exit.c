@include

@data

@fillfromtask

BPF_RINGBUF_OUTPUT(exit_output, 1);

int trace_exit(struct tracepoint__syscalls__sys_enter_exit * ctx){

    struct data_t data = {};
    fill_task_data(&data);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    exit_output.ringbuf_output(&data, sizeof(data), 0);
    return 0;

}