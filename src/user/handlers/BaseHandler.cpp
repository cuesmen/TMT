#include "BaseHandler.hpp"
#include <bpf/bpf.h>
#include <sys/sysinfo.h>
#include <ctime>
#include <unistd.h>
#include <cstdio>

void BaseHandler::start() {
    running_.store(true);
    poll_thread_ = std::thread([this](){
        while (running_.load(std::memory_order_relaxed)) {
            if (rb1_) {
                int ret = ring_buffer__poll(rb1_, timeout_ms_);
                if (ret < 0 && ret != -EINTR)
                    fprintf(stderr, "[%s] rb1 poll err=%d\n", name_.c_str(), ret);
            }
            if (rb2_) {
                int ret = ring_buffer__poll(rb2_, timeout_ms_);
                if (ret < 0 && ret != -EINTR)
                    fprintf(stderr, "[%s] rb2 poll err=%d\n", name_.c_str(), ret);
            }
        }
    });
}

void BaseHandler::stop() {
    if (!running_.exchange(false)) return;
    if (poll_thread_.joinable()) poll_thread_.join();
    if (rb1_) { ring_buffer__free(rb1_); rb1_ = nullptr; }
    if (rb2_) { ring_buffer__free(rb2_); rb2_ = nullptr; }
}

void BaseHandler::drain_until(uint64_t total_expected) {
    const int MAX_IDLE = 5000;
    int idle = 0;
    while (read_events_.load() < total_expected) {
        if (rb1_) ring_buffer__poll(rb1_, 0);
        if (rb2_) ring_buffer__poll(rb2_, 0);
        if (++idle > MAX_IDLE) break;
        usleep(1000); 
    }
}

std::vector<Event> BaseHandler::collect() {
    std::lock_guard<std::mutex> lk(mtx_);
    return events_;
}

void BaseHandler::set_ring_buffers(struct ring_buffer* rb1, struct ring_buffer* rb2) {
    rb1_ = rb1;
    rb2_ = rb2;
}

int BaseHandler::set_cfg_enabled_map(int fd) {
    uint32_t key = 0, one = 1;
    return bpf_map_update_elem(fd, &key, &one, BPF_ANY);
}

int BaseHandler::freeze_cfg_enabled_map(int fd) {
    uint32_t key = 0, zero = 0;
    return bpf_map_update_elem(fd, &key, &zero, BPF_ANY);
}

uint64_t BaseHandler::snapshot_evcount_percpu(int fd) {
    int n = libbpf_num_possible_cpus();
    std::vector<uint64_t> vals(n);
    uint32_t key = 0;
    if (bpf_map_lookup_elem(fd, &key, vals.data()) != 0)
        return read_events_.load();
    uint64_t tot = 0;
    for (auto v : vals) tot += v;
    return tot;
}

std::string BaseHandler::human_ts(uint64_t ts_ns) {
    struct sysinfo si; sysinfo(&si);
    time_t now = time(NULL), boot = now - si.uptime;
    time_t sec = boot + (time_t)(ts_ns / 1000000000ULL);
    struct tm tmv; localtime_r(&sec, &tmv);
    char buf[64]; strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    char out[96]; snprintf(out, sizeof(out), "%s.%06lu", buf,
                           (unsigned long)((ts_ns / 1000ULL) % 1000000ULL));
    return std::string(out);
}
