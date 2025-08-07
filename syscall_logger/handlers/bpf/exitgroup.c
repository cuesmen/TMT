@include

@data

@fillfromtask

BPF_RINGBUF_OUTPUT(exit_group_output, 1);

struct tracepoint__syscall__sys_enter_exit_group;

int trace_exit_group(struct tracepoint__syscall__sys_enter_exit_group *ctx){

    struct data_t data = {};
    fill_task_data(&data);
    exit_group_output.ringbuf_output(&data, sizeof(data), 0);
    return 0;

}