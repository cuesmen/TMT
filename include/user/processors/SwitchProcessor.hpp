#pragma once
#include "common.hpp"
#include <vector>
#include <string>

struct Slice {
    uint32_t pid;
    uint32_t cpu;
    std::string command;
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t delta_ns;
    std::string reason;
};

class SwitchProcessor {
public:
    explicit SwitchProcessor(const std::vector<Event>& events);

    void build_slices(bool debug = false);
    void store_csv(const std::string& filename = "out/oncpu_slices.csv") const;
    void plot_top_runtime_per_cpu(int top_n = 10,
                                  const std::string& time_unit = "ms",
                                  const std::string& outfile_prefix = "out/top_runtime_cpu_") const;

private:
    std::vector<Event> events_;
    std::vector<Slice> slices_;
};
