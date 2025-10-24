#include "SwitchHandler.hpp"
#include "BaseHandler.hpp"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>

#pragma pack(push,1)
struct run_event_t {
    uint64_t ts;
    uint32_t cpu;
    uint32_t pid;
    uint32_t type;
    uint32_t reason;
    char     comm[16];
    uint32_t parent_pid, child_pid, pgid, tid, tgid;
    char     command[16];
    uint64_t timestamp;
};
#pragma pack(pop)

static int sample_cb(void *ctx, void *data, size_t len) {
    return reinterpret_cast<SwitchHandler*>(ctx)->on_sample(data, len);
}

static uint32_t read_pid_file(const char* path) {
    FILE* f = fopen(path, "re");
    if (!f) return 0;
    unsigned long x = 0;
    if (fscanf(f, "%lu", &x) != 1) { fclose(f); return 0; }
    fclose(f);
    return (uint32_t)x;
}

static void add_tid_if_any(int map_allow_fd, uint32_t tid) {
    if (!tid) return;
    uint8_t one = 1;
    bpf_map_update_elem(map_allow_fd, &tid, &one, BPF_ANY);
}

static void add_all_threads_of_pid(int map_allow_fd, uint32_t pid) {
    if (!pid) return;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/task", pid);
    DIR* d = opendir(path);
    if (!d) {
        add_tid_if_any(map_allow_fd, pid);
        return;
    }
    struct dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        unsigned long tid = strtoul(de->d_name, nullptr, 10);
        if (tid > 0 && tid <= 0xfffffffful)
            add_tid_if_any(map_allow_fd, (uint32_t)tid);
    }
    closedir(d);
}

SwitchHandler::SwitchHandler(int poll_timeout_ms)
: BaseHandler("switch", poll_timeout_ms) {}

SwitchHandler::~SwitchHandler() {
    stop();
    detach();
    if (obj_) bpf_object__close(obj_);
}

std::string SwitchHandler::resolve_bpf_obj_path() const {
    char exe_path[PATH_MAX]{};
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (n <= 0) return "./bin/sched_switch.bpf.o";
    exe_path[n] = '\0';
    char* slash = strrchr(exe_path, '/');
    if (!slash) return "./bin/sched_switch.bpf.o";
    *slash = '\0';
    return std::string(exe_path) + "/sched_switch.bpf.o";
}

bool SwitchHandler::install() {
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    bpf_object_open_opts opts{};
    opts.sz = sizeof(opts);
    opts.btf_custom_path = "/sys/kernel/btf/vmlinux";

    std::string objp = resolve_bpf_obj_path();
    obj_ = bpf_object__open_file(objp.c_str(), &opts);
    if (!obj_) {
        fprintf(stderr, "[switch] open_file failed: %s\n", objp.c_str());
        return false;
    }
    int err = bpf_object__load(obj_);
    if (err) {
        fprintf(stderr, "[switch] load failed: %s\n", strerror(-err));
        return false;
    }

    map_cfg_ = bpf_object__find_map_fd_by_name(obj_, "cfg_enabled");
    map_ev_  = bpf_object__find_map_fd_by_name(obj_, "ev_count");
    map_rb_  = bpf_object__find_map_fd_by_name(obj_, "sched_output");
    
    int map_allow_ = bpf_object__find_map_fd_by_name(obj_, "allow_pids");
    int map_usef_  = bpf_object__find_map_fd_by_name(obj_, "cfg_useFilter");
    if (map_cfg_ < 0 || map_ev_ < 0 || map_rb_ < 0 || map_allow_ < 0 || map_usef_ < 0) {
        fprintf(stderr, "[switch] missing maps\n");
        return false;
    }

    {
        uint32_t k = 0, on = 1;
        if (bpf_map_update_elem(map_usef_, &k, &on, BPF_ANY) != 0)
            fprintf(stderr, "[switch] failed to enable pid filter\n");
    }

    uint32_t shell_pid = read_pid_file("/tmp/tmt_shell.pid");
    uint32_t cmd_pid   = read_pid_file("/tmp/tmt_cmd.pid");
    if (shell_pid) add_tid_if_any(map_allow_, shell_pid);
    if (cmd_pid) {
        add_tid_if_any(map_allow_, cmd_pid);
        add_all_threads_of_pid(map_allow_, cmd_pid); 
        fprintf(stderr, "[switch] allow tgid=%u and its threads\n", cmd_pid);
    } else {
        fprintf(stderr, "[switch] /tmp/tmt_cmd.pid not found or empty\n");
    }

    bpf_program *prog = bpf_object__find_program_by_name(obj_, "trace_sched_switch");
    if (!prog) {
        fprintf(stderr, "[switch] program not found\n");
        return false;
    }
    link_ = bpf_program__attach_tracepoint(prog, "sched", "sched_switch");
    if (!link_) {
        fprintf(stderr, "[switch] attach failed: %s\n", strerror(errno));
        return false;
    }

    set_cfg_enabled_map(map_cfg_);

    rb1_ = ring_buffer__new(map_rb_, sample_cb, this, nullptr);
    if (!rb1_) {
        fprintf(stderr, "[switch] ring_buffer__new failed\n");
        return false;
    }

    start();
    return true;
}

void SwitchHandler::detach() {
    if (link_) {
        bpf_link__destroy(link_);
        link_ = nullptr;
    }
}

void SwitchHandler::freeze_producer() {
    freeze_cfg_enabled_map(map_cfg_);
}

uint64_t SwitchHandler::snapshot_total() {
    return snapshot_evcount_percpu(map_ev_);
}

int SwitchHandler::on_sample(void *data, size_t len) {
    if (len < sizeof(run_event_t)) return 0;
    read_events_.fetch_add(1, std::memory_order_relaxed);
    const run_event_t* ev = reinterpret_cast<const run_event_t*>(data);

    Event e;
    e.event = (ev->type == 1) ? "run" : "desched";
    e.pid   = ev->pid;
    e.cpu   = ev->cpu;
    e.reason = (ev->reason == 1) ? "preempt" : "sleep";
    e.command = std::string(ev->comm);
    e.timestamp = ev->ts;
    e.timestamp_human = human_ts(ev->ts);

    std::lock_guard<std::mutex> lk(mtx_);
    events_.push_back(std::move(e));
    return 0;
}
