#ifndef COMMON_H
#define COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct data_t {
    __u32 parent_pid;
    __u32 pid;
    __u32 child_pid;     // ->! 0 on execve
    __u32 pgid;        
    __u32 tid;
    __u32 tgid;
    char  command[TASK_COMM_LEN];
    __u64 timestamp;     // ns
};

static __always_inline int producer_enabled(void *cfg_map)
{
    /* 0: 1 => enabled, else disabled */
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(cfg_map, &key);
    return val && (*val == 1);
}

static __always_inline void inc_ev_count(void *ev_percpu_arr)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(ev_percpu_arr, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    }
}

static __always_inline void fill_task_data(struct data_t *d)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    d->pid  = (__u32)(pid_tgid >> 32);
    d->tid  = (__u32)(pid_tgid & 0xFFFFFFFFu);
    d->tgid = d->pid;

    /* Retrieve parent tgid via CO-RE read */
    struct task_struct *parent = NULL;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    __u32 ppid = 0;
    if (parent)
        bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
    d->parent_pid = ppid;

    d->pgid = d->tgid; 

    bpf_get_current_comm(&d->command, sizeof(d->command));
    d->timestamp = bpf_ktime_get_ns();
    d->child_pid = 0;  
}

#endif
