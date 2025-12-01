#pragma once
#include <bpf/libbpf.h>
#include <atomic>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include "common.hpp"

class BaseHandler {
public:
    explicit BaseHandler(std::string name, int poll_timeout_ms = 100)
      : name_(std::move(name)), timeout_ms_(poll_timeout_ms) {}
    virtual ~BaseHandler() { stop(); }

    virtual bool install() = 0;
    virtual void detach() {}
    virtual void freeze_producer() {}
    virtual uint64_t snapshot_total() { return read_events_.load(); }

    void start();
    void stop();
    void drain_until(uint64_t total_expected);
    std::vector<Event> collect();

    const std::string& name() const { return name_; }

    static std::string human_ts(uint64_t ts_ns);

protected:
    virtual int on_sample(void *data, size_t len) = 0;

    void set_ring_buffers(struct ring_buffer* rb1, struct ring_buffer* rb2);
    int set_cfg_enabled_map(int fd);
    int freeze_cfg_enabled_map(int fd);
    uint64_t snapshot_evcount_percpu(int fd);

protected:
    std::string name_;
    int timeout_ms_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> read_events_{0};
    struct ring_buffer* rb1_{nullptr};
    struct ring_buffer* rb2_{nullptr};
    std::thread poll_thread_;
    std::mutex mtx_;
    std::vector<Event> events_;
};
