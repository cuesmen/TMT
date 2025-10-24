#include "ExecveHandler.hpp"
#include "BaseHandler.hpp"
#include <bpf/bpf.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <cstring>
#include <cstdlib>
#include <sys/sysinfo.h>
#include <ctime>
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

struct RbCtx {
    class ExecveHandler* self;
    const char* tag;
};

static int sample_cb(void *ctx, void *data, size_t len) {
    RbCtx* c = reinterpret_cast<RbCtx*>(ctx);
    return c->self->on_sample_with_tag(c->tag, data, len);
}

ExecveHandler::ExecveHandler(int poll_timeout_ms)
: BaseHandler("execve", poll_timeout_ms)
{}

ExecveHandler::~ExecveHandler() {
    stop();
    detach();
    if (obj_) bpf_object__close(obj_);
}

std::string ExecveHandler::resolve_bpf_obj_path() const {
    char exe_path[PATH_MAX]{};
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (n <= 0) return "./bin/execve.bpf.o";
    exe_path[n] = '\0';
    char* dir = dirname(exe_path);
    return std::string(dir) + "/execve.bpf.o";
}

bool ExecveHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    bpf_object_open_opts opts{};
    opts.sz = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    std::string objp = resolve_bpf_obj_path();
    obj_ = bpf_object__open_file(objp.c_str(), &opts);
    if (!obj_) {
        fprintf(stderr, "[execve] open_file failed: %s\n", objp.c_str());
        return false;
    }
    int err = bpf_object__load(obj_);
    if (err) {
        const char *libbpf_err = strerror(-err);
        fprintf(stderr, "[execve] load failed: %s (err=%d)\n",
                libbpf_err?libbpf_err:"unknown", err);
        return false;
    }

    map_cfg_    = bpf_object__find_map_fd_by_name(obj_, "cfg_enabled");
    map_ev_     = bpf_object__find_map_fd_by_name(obj_, "ev_count");
    map_rb_in_  = bpf_object__find_map_fd_by_name(obj_, "execve_output_in");
    map_rb_out_ = bpf_object__find_map_fd_by_name(obj_, "execve_output_out");
    if (map_cfg_ < 0 || map_ev_ < 0 || map_rb_in_ < 0 || map_rb_out_ < 0) {
        fprintf(stderr, "[execve] missing maps\n");
        return false;
    }

    bpf_program *enter_prog = bpf_object__find_program_by_name(obj_, "trace_execve");
    bpf_program *exit_prog  = bpf_object__find_program_by_name(obj_, "trace_execve_exit");
    if (!enter_prog || !exit_prog) {
        fprintf(stderr, "[execve] program not found by name\n");
        return false;
    }
    link_enter_ = bpf_program__attach_tracepoint(enter_prog, "syscalls", "sys_enter_execve");
    if (!link_enter_) {
        fprintf(stderr, "[execve] attach enter failed: %s\n", strerror(errno));
        return false;
    }
    link_exit_ = bpf_program__attach_tracepoint(exit_prog, "syscalls", "sys_exit_execve");
    if (!link_exit_) {
        fprintf(stderr, "[execve] attach exit failed: %s\n", strerror(errno));
        return false;
    }

    set_cfg_enabled_map(map_cfg_);

    rb_in_ctx_  = { this, "execve-entry" };
    rb_out_ctx_ = { this, "execve-exit"  };

    rb1_ = ring_buffer__new(map_rb_in_,  sample_cb, &rb_in_ctx_,  /*opts*/NULL);
    rb2_ = ring_buffer__new(map_rb_out_, sample_cb, &rb_out_ctx_, /*opts*/NULL);
    if (!rb1_ || !rb2_) {
        fprintf(stderr, "[execve] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void ExecveHandler::detach() {
    if (link_enter_) { bpf_link__destroy(link_enter_); link_enter_ = nullptr; }
    if (link_exit_)  { bpf_link__destroy(link_exit_);  link_exit_  = nullptr; }
}

void ExecveHandler::freeze_producer() {
    freeze_cfg_enabled_map(map_cfg_);
}

uint64_t ExecveHandler::snapshot_total() {
    return snapshot_evcount_percpu(map_ev_);
}

int ExecveHandler::on_sample_with_tag(const char* tag, void *data, size_t len) {
    if (len < sizeof(data_t)) return 0;
    read_events_.fetch_add(1, std::memory_order_relaxed);
    auto* ev = (const data_t*)data;

    Event e;
    e.event = tag ? std::string(tag) : std::string("execve");
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

// not used
int ExecveHandler::on_sample(void *data, size_t len) {
    return on_sample_with_tag("execve", data, len);
}
