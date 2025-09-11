@include
@data

struct run_event_t {
    u64 ts;
    u32 cpu;
    u32 pid;
    u32 type;
    u32 reason;
    char comm[TASK_COMM_LEN];

    // dummy fields just to satisfy BaseHandler
    u32 parent_pid;
    u32 child_pid;
    u32 pgid;
    u32 tid;
    u32 tgid;
    char command[TASK_COMM_LEN];
    u64 timestamp;
};

BPF_RINGBUF_OUTPUT(sched_output, 1);
BPF_HASH(allow_pids, u32, u8);
BPF_ARRAY(cfg_useFilter, u32, 1);   // index 0: 0 = no filter, 1 = use filter

static __always_inline bool should_emit(u32 pid) {
    u32 *flag = cfg_useFilter.lookup(&((u32){0}));
    if (flag && *flag == 0) {
        // filter disabled
        return true;
    }
    // filter enbaled -> allow_pids
    u8 *v = allow_pids.lookup(&pid);
    return v && *v == 1;
    //TODO!! Corretta gestione dei allow pids -> (cgroup v2 e filtro per cgroup nel probe?)
}
 
int trace_sched_switch(struct tracepoint__sched__sched_switch *args)
{
    u64 ts = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();
    u32 prev = args->prev_pid;
    u32 next = args->next_pid;

    if (should_emit(prev)) {
        struct run_event_t e = {};
        e.ts = ts; 
        e.cpu = cpu; 
        e.pid = prev; 
        e.type = 2;
        e.reason = args->prev_state == 0 ? 0 : 1;
    
        // Fill mandatory fields
        bpf_probe_read_kernel_str(e.comm, sizeof(e.comm), args->prev_comm);
    
        // Fill dummy fields for BaseHandler compatibility
        e.tid = prev;
        e.tgid = prev;   
        e.pgid = 0;
        e.parent_pid = 0;
        e.child_pid = 0;
        __builtin_memcpy(e.command, e.comm, sizeof(e.comm));
        e.timestamp = e.ts;
    
        sched_output.ringbuf_output(&e, sizeof(e), 0);
    }
    
    if (should_emit(next)) {
        struct run_event_t e = {};
        e.ts = ts; 
        e.cpu = cpu; 
        e.pid = next; 
        e.type = 1;
        e.reason = 0;
    
        // Fill mandatory fields
        bpf_probe_read_kernel_str(e.comm, sizeof(e.comm), args->next_comm);
    
        // Fill dummy fields for BaseHandler compatibility
        e.tid = next;
        e.tgid = next;
        e.pgid = 0;
        e.parent_pid = 0;
        e.child_pid = 0;
        __builtin_memcpy(e.command, e.comm, sizeof(e.comm));
        e.timestamp = e.ts;
    
        sched_output.ringbuf_output(&e, sizeof(e), 0);
    }    
    return 0;
}
