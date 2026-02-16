#include "SyscallLogger.hpp"
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <iostream>
#include <algorithm>
#include <cstdlib>
#include <sys/stat.h>
#include <fstream>
#include <sstream>

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

static std::vector<std::string> split_args(const std::string& cmd) {
    std::istringstream iss(cmd);
    std::vector<std::string> out;
    std::string tok;
    while (iss >> tok) out.push_back(tok);
    return out;
}

void SyscallLogger::run_command(const std::string& cmd, bool print_raw) {
    pid_t cmd_pid = fork();
    if (cmd_pid < 0) {
        std::cerr << "fork() failed: " << strerror(errno) << "\n";
        return;
    }

    if (cmd_pid == 0) {
        // Stop early to let the parent install BPF handlers before exec/spawn.
        raise(SIGSTOP);
        auto args = split_args(cmd);
        if (args.empty()) {
            std::cerr << "Empty command\n";
            _exit(127);
        }

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto& s : args)
            argv.push_back(const_cast<char*>(s.c_str()));
        argv.push_back(nullptr);

        if (execvp(argv[0], argv.data()) < 0) {
            std::cerr << "execvp failed: " << strerror(errno) << "\n";
            _exit(127);
        }
    }

    // wait for child to stop so we can attach before it execs/spawns
    int st = 0;
    if (waitpid(cmd_pid, &st, WUNTRACED) < 0) {
        std::cerr << "waitpid (WUNTRACED) failed: " << strerror(errno) << "\n";
        return;
    }
    if (!WIFSTOPPED(st)) {
        std::cerr << "child did not stop as expected; continuing\n";
    }

    // pass cmd_pid to the Event Processor
    root_pid_ = static_cast<uint32_t>(cmd_pid);

    // pass the cmd_pid to the SwitchHandler
    for (auto& h : handlers_) {
        if (auto* sh = dynamic_cast<SwitchHandler*>(h.get())) {
            sh->set_root_pids(/*shell_pid=*/0, static_cast<uint32_t>(cmd_pid));
        }
    }

    if (!install_all()) {
        std::cerr << "No handler installed successfully; aborting.\n";
        kill(cmd_pid, SIGCONT);
        return;
    }

    // resume the child once handlers are installed
    kill(cmd_pid, SIGCONT);

    // wait the cmd end
    if (waitpid(cmd_pid, nullptr, 0) < 0) {
        std::cerr << "waitpid failed: " << strerror(errno) << "\n";
    }

    coordinated_stop();

    if (print_raw) {
        for (auto& e : events_) {
            std::cout << e.timestamp << " " << e.event
                      << " pid=" << e.pid
                      << " child=" << e.child_pid
                      << " comm=" << e.command << "\n";
        }
    }
}
