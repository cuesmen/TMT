@include

@data

@fillfromtask

BPF_RINGBUF_OUTPUT(fork_output, 1);

int trace_fork(struct tracepoint__sched__sched_process_fork *ctx) {
    struct data_t data = {};

    data.pid = ctx->parent_pid;
    data.child_pid = ctx->child_pid;

    fill_task_data(&data);

    fork_output.ringbuf_output(&data, sizeof(data), 0);
    return 0;

}