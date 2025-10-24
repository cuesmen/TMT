#include "SyscallLogger.hpp"
#include "EventProcessor.hpp"
#include "SwitchProcessor.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>

static void usage(const char* prog) {
    std::cerr
        << "Usage:\n"
        << "  sudo " << prog << " --cmd \"<command to trace>\" [--print-raw]\n\n"
        << "Examples:\n"
        << "  sudo " << prog << " --cmd \"sleep 1\"\n"
        << "  sudo " << prog << " --cmd \"python3 thread_test.py\" --print-raw\n";
}

int main(int argc, char** argv) {
    std::string cmd;
    bool print_raw = false;

    // TODO!! parse args
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--cmd") && i + 1 < argc) {
            cmd = argv[++i];
        } else if (!strcmp(argv[i], "--print-raw")) {
            print_raw = true;
        } else {
            std::cerr << "Unknown arg: " << argv[i] << "\n";
            usage(argv[0]);
            return 1;
        }
    }
    if (cmd.empty()) {
        usage(argv[0]);
        return 1;
    }

    SyscallLogger logger(100);
    logger.run_command(cmd, print_raw);

    const auto& evs = logger.events();
    if (evs.empty()) {
        std::cerr << "No events collected.\n";
        return 0;
    }

    EventProcessor ep(evs);
    ep.build_tree(false);
    ep.compute_intervals(false);

    ep.store_to_csv("out/alive_series.csv");

    SwitchProcessor sp(evs);
    sp.build_slices(false);
    sp.store_csv("out/oncpu_slices.csv");
    sp.plot_top_runtime_per_cpu(10, "ms", "out/top_runtime_cpu_");

    std::cout << "Done. Events: " << evs.size()
              << " | alive series written to out/alive_series.csv\n";
    return 0;
}
