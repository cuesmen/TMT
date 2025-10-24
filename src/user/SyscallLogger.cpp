#include "SyscallLogger.hpp"
#include <unistd.h>
#include <sys/wait.h>
#include <iostream>
#include <algorithm>
#include <cstdlib>
#include <sys/stat.h>
#include <fstream>


SyscallLogger::SyscallLogger(int timeout_ms)
: timeout_ms_(timeout_ms)
{
    handlers_.emplace_back(std::make_unique<ExecveHandler>(timeout_ms_));
    handlers_.emplace_back(std::make_unique<ForkHandler>(timeout_ms_));
    handlers_.emplace_back(std::make_unique<ExitHandler>(timeout_ms_));
    handlers_.emplace_back(std::make_unique<ExitGroupHandler>(timeout_ms_));
    handlers_.emplace_back(std::make_unique<SwitchHandler>(timeout_ms_));
    handlers_.emplace_back(std::make_unique<CloneHandler>(timeout_ms_));
    handlers_.emplace_back(std::make_unique<Clone3Handler>(timeout_ms_));
}

bool SyscallLogger::install_all() {
    bool ok = false;
    for (auto& h : handlers_) {
        if (h->install()) ok = true;
        else std::cerr << "Install failed for handler: " << h->name() << "\n";
    }
    return ok;
}

void SyscallLogger::coordinated_stop() {
    for (auto& h : handlers_) h->freeze_producer();

    std::vector<uint64_t> totals;
    totals.reserve(handlers_.size());
    for (auto& h : handlers_) totals.push_back(h->snapshot_total());

    for (size_t i = 0; i < handlers_.size(); ++i)
        handlers_[i]->drain_until(totals[i]);

    for (auto& h : handlers_) { h->detach(); h->stop(); }

    events_.clear();
    for (auto& h : handlers_) {
        auto v = h->collect();
        events_.insert(events_.end(), v.begin(), v.end());
    }
    std::sort(events_.begin(), events_.end(),
              [](const Event& a, const Event& b) { return a.timestamp < b.timestamp; });

    if (!events_.empty()) {
        uint64_t t0 = events_.front().timestamp;
        for (auto& e : events_) e.timestamp -= t0;
    }
}

void SyscallLogger::run_command(const std::string& cmd, bool print_raw) {
    const std::string cgpath = "/sys/fs/cgroup/tmt_trace";
    mkdir(cgpath.c_str(), 0755);

    std::string wrapped_cmd =
        "echo $$ > /tmp/tmt_shell.pid; "
        + cmd + " & echo $! > /tmp/tmt_cmd.pid; "
        "wait $!";

    system(("/bin/sh -c 'echo $$ > /tmp/tmt_shell.pid; " +
            cmd + " & echo $! > /tmp/tmt_cmd.pid; exit 0'").c_str());

    if (!install_all()) {
        std::cerr << "No handler installed successfully; aborting.\n";
        return;
    }

    int ret = system("/bin/sh -c 'if [ -f /tmp/tmt_cmd.pid ]; then "
                     " read pid < /tmp/tmt_cmd.pid; "
                     " if [ -n \"$pid\" ]; then wait \"$pid\"; fi; "
                     "fi'");
    (void)ret;

    coordinated_stop();

    if (print_raw) {
        for (auto& e : events_) {
            std::cout << e.timestamp << " " << e.event
                      << " pid=" << e.pid
                      << " child=" << e.child_pid
                      << " comm=" << e.command
                      << "\n";
        }
    }
}
