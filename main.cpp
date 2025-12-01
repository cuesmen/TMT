#include "SyscallLogger.hpp"
#include "EventProcessor.hpp"
#include "SwitchProcessor.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>

#include <args.hxx>

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

    args::ArgumentParser parser(
        "TMT: Thread Monitoring Tool",
        "Trace threads and scheduling behavior of a target program using eBPF."
    );

    args::HelpFlag help(
        parser,
        "help",
        "Show this help message and exit",
        {'h', "help"}
    );

    args::ValueFlag<std::string> cmd_flag(
        parser,
        "command",
        "Command to execute and trace (required)",
        {"cmd"}
    );

    args::Flag print_raw_flag(
        parser,
        "print-raw",
        "Print raw kernel events as they are received",
        {"print-raw"}
    );

    try {
        parser.ParseCLI(argc, argv);
    } catch (const args::Help&) {
        std::cout << parser << std::endl;
        return 0;
    } catch (const args::ParseError& e) {
        std::cerr << e.what() << "\n\n";
        std::cerr << parser << std::endl;
        return 1;
    }

    if (!cmd_flag) {
        usage(argv[0]);
        std::cerr << "\nError: --cmd is required.\n";
        return 1;
    }

    cmd = args::get(cmd_flag);
    print_raw = print_raw_flag; 

    SyscallLogger logger(100);
    logger.run_command(cmd, print_raw);

    const auto& evs = logger.events();
    if (evs.empty()) {
        std::cerr << "No events collected.\n";
        return 0;
    }

    EventProcessor ep(logger.events(), logger.root_pid());
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
