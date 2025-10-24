#include "ForkHandler.hpp"
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

ForkHandler::ForkHandler(int poll_timeout_ms)
: BaseHandler("fork", poll_timeout_ms) {}

ForkHandler::~ForkHandler() {
    stop();
    detach();
    if (obj_) bpf_object__close(obj_);
}

std::string ForkHandler::resolve_bpf_obj_path() const {
    char exe_path[PATH_MAX]{};
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (n <= 0) return "./bin/fork.bpf.o";
    exe_path[n] = '\0';
    char* dir = dirname(exe_path);
    return std::string(dir) + "/fork.bpf.o";  
}

static int sample_cb(void *ctx, void *data, size_t len) {
    auto *c = reinterpret_cast<ForkHandler::RbCtx*>(ctx);
    return c->self->on_sample_with_tag(c->tag, data, len);
}

bool ForkHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    bpf_object_open_opts opts{};
    opts.sz = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    std::string objp = resolve_bpf_obj_path();
    obj_ = bpf_object__open_file(objp.c_str(), &opts);
    if (!obj_) {
        fprintf(stderr, "[fork] open_file failed: %s\n", objp.c_str());
        return false;
    }
    int err = bpf_object__load(obj_);
    if (err) {
        const char *libbpf_err = strerror(-err);
        fprintf(stderr, "[fork] load failed: %s (err=%d)\n",
                libbpf_err?libbpf_err:"unknown", err);
        return false;
    }

    map_cfg_     = bpf_object__find_map_fd_by_name(obj_, "cfg_enabled");
    map_ev_      = bpf_object__find_map_fd_by_name(obj_, "ev_count");
    map_rb_fork_ = bpf_object__find_map_fd_by_name(obj_, "fork_output");
    if (map_cfg_ < 0 || map_ev_ < 0 || map_rb_fork_ < 0) {
        fprintf(stderr, "[fork] missing maps (cfg_enabled/ev_count/fork_output)\n");
        return false;
    }

    bpf_program *fork_prog = bpf_object__find_program_by_name(obj_, "handle_sched_fork");
    if (!fork_prog) {
        fprintf(stderr, "[fork] program trace_fork_exit not found in obj\n");
        return false;
    }
    link_fork_exit_ = bpf_program__attach_tracepoint(fork_prog, "sched", "sched_process_fork");
    if (!link_fork_exit_) {
        fprintf(stderr, "[fork] attach sys_exit_fork failed: %s\n", strerror(errno));
        return false;
    }

    set_cfg_enabled_map(map_cfg_);

    rb_fork_ctx_ = { this, "fork" };
    rb1_ = ring_buffer__new(map_rb_fork_, sample_cb, &rb_fork_ctx_, NULL);
    if (!rb1_) {
        fprintf(stderr, "[fork] ring_buffer__new failed\n");
        return false;
    }

    fprintf(stderr, "[fork] Handler installed successfully!\n");
    start();
    return true;
}

void ForkHandler::detach() {
    if (link_fork_exit_) { bpf_link__destroy(link_fork_exit_); link_fork_exit_ = nullptr; }
}

void ForkHandler::freeze_producer() {
    freeze_cfg_enabled_map(map_cfg_);
}

uint64_t ForkHandler::snapshot_total() {
    return snapshot_evcount_percpu(map_ev_);
}

int ForkHandler::on_sample(void *data, size_t len) {
    return on_sample_with_tag("fork", data, len);
}

int ForkHandler::on_sample_with_tag(const char* tag, void *data, size_t len) {
    if (len < sizeof(data_t)) return 0;
    read_events_.fetch_add(1, std::memory_order_relaxed);
    auto* ev = (const data_t*)data;

    Event e;
    e.event = tag ? std::string(tag) : std::string("fork");
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
