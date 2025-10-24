#include "Clone3Handler.hpp"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <cstring>
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

Clone3Handler::Clone3Handler(int poll_timeout_ms)
: BaseHandler("fork", poll_timeout_ms) {}

Clone3Handler::~Clone3Handler() {
    stop();
    detach();
    if (obj_) bpf_object__close(obj_);
}

std::string Clone3Handler::resolve_bpf_obj_path() const {
    char exe_path[PATH_MAX]{};
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (n <= 0) return "./bin/clone3.bpf.o";
    exe_path[n] = '\0';
    return std::string(dirname(exe_path)) + "/clone3.bpf.o";
}

int Clone3Handler::sample_cb(void *ctx, void *data, size_t len) {
    auto *c = reinterpret_cast<Clone3Handler::RbCtx*>(ctx);
    return c->self->on_sample_with_tag(c->tag, data, len);
}

bool Clone3Handler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    bpf_object_open_opts opts{};
    opts.sz = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    std::string objp = resolve_bpf_obj_path();
    obj_ = bpf_object__open_file(objp.c_str(), &opts);
    if (!obj_) {
        fprintf(stderr, "[clone3] open_file failed: %s\n", objp.c_str());
        return false;
    }
    int err = bpf_object__load(obj_);
    if (err) {
        const char *libbpf_err = strerror(-err);
        fprintf(stderr, "[clone3] load failed: %s (err=%d)\n",
                libbpf_err?libbpf_err:"unknown", err);
        return false;
    }

    map_cfg_ = bpf_object__find_map_fd_by_name(obj_, "cfg_enabled");
    map_ev_  = bpf_object__find_map_fd_by_name(obj_, "ev_count");
    map_rb_  = bpf_object__find_map_fd_by_name(obj_, "clone3_output");
    if (map_cfg_ < 0 || map_ev_ < 0 || map_rb_ < 0) {
        fprintf(stderr, "[clone3] missing maps (cfg_enabled/ev_count/clone3_output)\n");
        return false;
    }

    auto *prog = bpf_object__find_program_by_name(obj_, "trace_clone3_exit");
    if (!prog) {
        fprintf(stderr, "[clone3] program trace_clone3_exit not found\n");
        return false;
    }
    link_ = bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_clone3");
    if (!link_) {
        fprintf(stderr, "[clone3] attach sys_exit_clone3 failed: %s\n", strerror(errno));
        return false;
    }

    set_cfg_enabled_map(map_cfg_);

    rb_ctx_ = { this, "fork" };
    rb_ = ring_buffer__new(map_rb_, sample_cb, &rb_ctx_, NULL);
    if (!rb_) {
        fprintf(stderr, "[clone3] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void Clone3Handler::detach() {
    if (link_) { bpf_link__destroy(link_); link_ = nullptr; }
    if (rb_) { ring_buffer__free(rb_); rb_ = nullptr; }
}

void Clone3Handler::freeze_producer() {
    freeze_cfg_enabled_map(map_cfg_);
}

uint64_t Clone3Handler::snapshot_total() {
    return snapshot_evcount_percpu(map_ev_);
}

int Clone3Handler::on_sample(void *data, size_t len) {
    return on_sample_with_tag("fork", data, len);
}

int Clone3Handler::on_sample_with_tag(const char* tag, void *data, size_t len) {
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
