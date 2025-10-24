#include "ExitGroupHandler.hpp"
#include "BaseHandler.hpp"
#include <bpf/bpf.h>
#include <libgen.h>
#include <unistd.h>
#include <limits.h>
#include <cstring>
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

static int sample_cb(void *ctx, void *data, size_t len) {
    ExitGroupHandler* self = reinterpret_cast<ExitGroupHandler*>(ctx);
    return self->on_sample(data, len);
}

ExitGroupHandler::ExitGroupHandler(int poll_timeout_ms)
: BaseHandler("exit_group", poll_timeout_ms)
{}

ExitGroupHandler::~ExitGroupHandler() {
    stop();
    detach();
    if (obj_) bpf_object__close(obj_);
}

std::string ExitGroupHandler::resolve_bpf_obj_path() const {
    char exe_path[PATH_MAX]{};
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (n <= 0) return "./bin/exit_group.bpf.o";
    exe_path[n] = '\0';
    char* dir = dirname(exe_path);
    return std::string(dir) + "/exit_group.bpf.o";
}

bool ExitGroupHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    bpf_object_open_opts opts{};
    opts.sz = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    std::string objp = resolve_bpf_obj_path();
    obj_ = bpf_object__open_file(objp.c_str(), &opts);
    if (!obj_) {
        fprintf(stderr, "[exit_group] open_file failed: %s\n", objp.c_str());
        return false;
    }

    int err = bpf_object__load(obj_);
    if (err) {
        fprintf(stderr, "[exit_group] load failed: %s\n", strerror(-err));
        return false;
    }

    map_cfg_ = bpf_object__find_map_fd_by_name(obj_, "cfg_enabled");
    map_ev_  = bpf_object__find_map_fd_by_name(obj_, "ev_count");
    map_rb_  = bpf_object__find_map_fd_by_name(obj_, "exit_group_output");

    if (map_cfg_ < 0 || map_ev_ < 0 || map_rb_ < 0) {
        fprintf(stderr, "[exit_group] missing maps\n");
        return false;
    }

    bpf_program *prog = bpf_object__find_program_by_name(obj_, "trace_exit_group");
    if (!prog) {
        fprintf(stderr, "[exit_group] program not found\n");
        return false;
    }

    link_ = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_exit_group");
    if (!link_) {
        fprintf(stderr, "[exit_group] attach failed: %s\n", strerror(errno));
        return false;
    }

    set_cfg_enabled_map(map_cfg_);

    rb1_ = ring_buffer__new(map_rb_, sample_cb, this, nullptr);
    if (!rb1_) {
        fprintf(stderr, "[exit_group] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void ExitGroupHandler::detach() {
    if (link_) { bpf_link__destroy(link_); link_ = nullptr; }
}

void ExitGroupHandler::freeze_producer() {
    freeze_cfg_enabled_map(map_cfg_);
}

uint64_t ExitGroupHandler::snapshot_total() {
    return snapshot_evcount_percpu(map_ev_);
}

int ExitGroupHandler::on_sample(void *data, size_t len) {
    if (len < sizeof(data_t)) return 0;
    read_events_.fetch_add(1, std::memory_order_relaxed);
    const data_t* ev = reinterpret_cast<const data_t*>(data);

    Event e;
    e.event = "exit_group";
    e.parent_pid = ev->parent_pid;
    e.pid = ev->pid;
    e.child_pid = ev->child_pid;
    e.pgid = ev->pgid;
    e.tid = ev->tid;
    e.tgid = ev->tgid;
    e.command = std::string(ev->command);
    e.timestamp = ev->timestamp;
    e.timestamp_human = human_ts(ev->timestamp);

    std::lock_guard<std::mutex> lk(mtx_);
    events_.push_back(std::move(e));
    return 0;
}
