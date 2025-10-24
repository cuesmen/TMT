#include "ExitHandler.hpp"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <iostream>

#pragma pack(push,1)
struct data_t {
    uint32_t parent_pid;
    uint32_t pid;
    uint32_t child_pid;
    uint32_t pgid;
    uint32_t tid;
    uint32_t tgid;
    char     command[16];
    uint64_t timestamp;
};
#pragma pack(pop)

ExitHandler::ExitHandler(int poll_timeout_ms)
: BaseHandler("exit", poll_timeout_ms) {}

ExitHandler::~ExitHandler() {
    stop();
    detach();
    if (obj_) bpf_object__close(obj_);
}

std::string ExitHandler::resolve_bpf_obj_path() const {
    char exe_path[PATH_MAX]{};
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (n <= 0) return "./bin/exit.bpf.o"; 
    exe_path[n] = '\0';
    char* dir = dirname(exe_path);
    return std::string(dir) + "/exit.bpf.o";
}

static int sample_cb(void *ctx, void *data, size_t len) {
    auto *c = reinterpret_cast<ExitHandler::RbCtx*>(ctx);
    return c->self->on_sample_with_tag(c->tag, data, len);
}

bool ExitHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    bpf_object_open_opts opts{};
    opts.sz = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    std::string objp = resolve_bpf_obj_path();
    obj_ = bpf_object__open_file(objp.c_str(), &opts);
    if (!obj_) {
        fprintf(stderr, "[exit] open_file failed: %s\n", objp.c_str());
        return false;
    }
    int err = bpf_object__load(obj_);
    if (err) {
        const char *libbpf_err = strerror(-err);
        fprintf(stderr, "[exit] load failed: %s (err=%d)\n",
                libbpf_err?libbpf_err:"unknown", err);
        return false;
    }

    map_cfg_        = bpf_object__find_map_fd_by_name(obj_, "cfg_enabled");
    map_ev_         = bpf_object__find_map_fd_by_name(obj_, "ev_count");
    map_rb_exit_    = bpf_object__find_map_fd_by_name(obj_, "exit_output");
    map_rb_exitgrp_ = bpf_object__find_map_fd_by_name(obj_, "exit_group_output");
    if (map_cfg_ < 0 || map_ev_ < 0 || map_rb_exit_ < 0 || map_rb_exitgrp_ < 0) {
        fprintf(stderr, "[exit] missing maps (cfg_enabled/ev_count/exit_output/exit_group_output)\n");
        return false;
    }

    bpf_program *exit_prog  = bpf_object__find_program_by_name(obj_, "trace_exit_enter");
    bpf_program *exitg_prog = bpf_object__find_program_by_name(obj_, "trace_exit_group_enter");
    if (!exit_prog || !exitg_prog) {
        fprintf(stderr, "[exit] programs not found in obj\n");
        return false;
    }

    link_exit_ = bpf_program__attach_tracepoint(exit_prog, "syscalls", "sys_enter_exit");
    if (!link_exit_) {
        fprintf(stderr, "[exit] attach sys_enter_exit failed: %s\n", strerror(errno));
        return false;
    }
    link_exitgrp_ = bpf_program__attach_tracepoint(exitg_prog, "syscalls", "sys_enter_exit_group");
    if (!link_exitgrp_) {
        fprintf(stderr, "[exit] attach sys_enter_exit_group failed: %s\n", strerror(errno));
        return false;
    }

    set_cfg_enabled_map(map_cfg_);

    rb_exit_ctx_    = { this, "exit" };
    rb_exitgrp_ctx_ = { this, "exit_group" };
    rb1_ = ring_buffer__new(map_rb_exit_,    sample_cb, &rb_exit_ctx_,    NULL);
    rb2_ = ring_buffer__new(map_rb_exitgrp_, sample_cb, &rb_exitgrp_ctx_, NULL);
    if (!rb1_ || !rb2_) {
        fprintf(stderr, "[exit] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void ExitHandler::detach() {
    if (link_exit_)    { bpf_link__destroy(link_exit_);    link_exit_    = nullptr; }
    if (link_exitgrp_) { bpf_link__destroy(link_exitgrp_); link_exitgrp_ = nullptr; }
}

void ExitHandler::freeze_producer() {
    freeze_cfg_enabled_map(map_cfg_);
}

uint64_t ExitHandler::snapshot_total() {
    return snapshot_evcount_percpu(map_ev_);
}

int ExitHandler::on_sample(void *data, size_t len) {
    return on_sample_with_tag("exit", data, len);
}

int ExitHandler::on_sample_with_tag(const char* tag, void *data, size_t len) {
    if (len < sizeof(data_t)) return 0;
    read_events_.fetch_add(1, std::memory_order_relaxed);
    auto* ev = (const data_t*)data;

    Event e;
    e.event = tag ? std::string(tag) : std::string("exit");
    e.parent_pid = ev->parent_pid;
    e.pid = ev->pid;
    e.child_pid = ev->child_pid;
    e.pgid = ev->pgid;
    e.tid = ev->tid;
    e.tgid = ev->tgid;
    e.command = std::string(ev->command);
    e.timestamp = ev->timestamp;
    e.timestamp_human = BaseHandler::human_ts(ev->timestamp);

    std::lock_guard<std::mutex> lk(mtx_);
    events_.push_back(std::move(e));
    return 0;
}
