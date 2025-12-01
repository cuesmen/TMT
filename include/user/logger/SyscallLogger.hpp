#pragma once
#include <vector>
#include <memory>
#include <string>
#include "common.hpp"
#include "BaseHandler.hpp"
#include "ExecveHandler.hpp"
#include "ForkHandler.hpp"
#include "ExitHandler.hpp"
#include "CloneHandler.hpp"
#include "Clone3Handler.hpp"
#include "ExitGroupHandler.hpp"
#include "SwitchHandler.hpp"

class SyscallLogger {
public:
    explicit SyscallLogger(int timeout_ms = 100);

    bool install_all();
    void coordinated_stop();

    void run_command(const std::string& cmd, bool print_raw = false);

    const std::vector<Event>& events() const { return events_; }
    uint32_t root_pid() const { return root_pid_; }

private:
    std::vector<std::unique_ptr<BaseHandler>> handlers_;
    std::vector<Event> events_;
    int timeout_ms_{100};
    uint32_t root_pid_ = 0;
};
