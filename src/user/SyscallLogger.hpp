#pragma once
#include <vector>
#include <memory>
#include <string>
#include "include/common.hpp"
#include "handlers/BaseHandler.hpp"
#include "handlers/ExecveHandler.hpp"
#include "handlers/ForkHandler.hpp"
#include "handlers/ExitHandler.hpp"
#include "handlers/CloneHandler.hpp"
#include "handlers/Clone3Handler.hpp"
#include "handlers/ExitGroupHandler.hpp"
#include "handlers/SwitchHandler.hpp"

class SyscallLogger {
public:
    explicit SyscallLogger(int timeout_ms = 100);

    bool install_all();
    void coordinated_stop();

    void run_command(const std::string& cmd, bool print_raw = false);

    const std::vector<Event>& events() const { return events_; }

private:
    std::vector<std::unique_ptr<BaseHandler>> handlers_;
    std::vector<Event> events_;
    int timeout_ms_{100};
};
