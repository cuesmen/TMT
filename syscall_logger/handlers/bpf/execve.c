@include

@data

@fillfromtask

BPF_RINGBUF_OUTPUT(execve_output_in, 1);
BPF_RINGBUF_OUTPUT(execve_output_out, 1);

struct tracepoint__syscall__sys_enter_execve;
struct tracepoint__syscall__sys_exit_execve;

int trace_execve(struct tracepoint__syscall__sys_enter_execve * ctx){

    struct data_t data = {};
    fill_task_data(&data);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    execve_output_in.ringbuf_output(&data, sizeof(data), 0);
    return 0;

}

int trace_execve_exit(struct tracepoint__syscall__sys_exit_execve * ctx){

	struct data_t data = {};
    fill_task_data(&data);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    execve_output_out.ringbuf_output(&data, sizeof(data), 0);
    return 0;
}