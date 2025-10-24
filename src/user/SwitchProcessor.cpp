#include "SwitchProcessor.hpp"
#include <iostream>
#include <fstream>
#include <map>
#include <algorithm>
#include <cmath>

static double unit_scale(const std::string& u) {
    /* convert unit string to ns scale factor */
    if (u == "ns") return 1.0;
    if (u == "us") return 1e3;
    if (u == "ms") return 1e6;
    if (u == "s")  return 1e9;
    throw std::invalid_argument("invalid time unit: " + u);
}

SwitchProcessor::SwitchProcessor(const std::vector<Event>& evs)
: events_(evs) {
    /* keep only run/desched events */
    events_.erase(std::remove_if(events_.begin(), events_.end(),
                                 [](const Event& e) {
                                     return !(e.event == "run" || e.event == "desched");
                                 }),
                  events_.end());
}

void SwitchProcessor::build_slices(bool debug) {
    std::cerr << "[SwitchProcessor] Processing " << events_.size() << " events\n";

    /* pid -> (start_ts, cpu, command) for open running intervals */
    std::map<uint32_t, std::tuple<uint64_t, uint32_t, std::string>> open;
    slices_.clear();

    for (const auto& e : events_) {
        if (debug)
            std::cerr << "[SwitchProcessor] Event: "
                      << e.event << " pid=" << e.pid
                      << " cpu=" << e.cpu
                      << " ts=" << e.timestamp << "\n";

        uint32_t pid = e.pid;
        uint64_t ts  = e.timestamp;

        if (e.event == "run") {
            /* task scheduled in: start (or overwrite) slice */
            open[pid] = {ts, e.cpu, e.command};
        } else if (e.event == "desched") {
            /* task scheduled out: close slice if present */
            auto it = open.find(pid);
            if (it != open.end()) {
                auto [start, cpu0, cmd0] = it->second;
                if (ts > start) {
                    Slice s{
                        pid, cpu0, cmd0,
                        start, ts, ts - start,
                        e.reason
                    };
                    slices_.push_back(std::move(s));
                }
                open.erase(it);
            }
        }
    }

    /* close any pending slices at the end of trace */
    if (!open.empty()) {
        uint64_t end_ts = 0;
        for (const auto& e : events_)
            if (e.timestamp > end_ts) end_ts = e.timestamp;

        for (auto& [pid, tup] : open) {
            auto [start, cpu0, cmd0] = tup;
            Slice s{
                pid, cpu0, cmd0,
                start, end_ts, end_ts - start,
                "end_of_trace"             // slice truncated at trace end
            };
            slices_.push_back(std::move(s));
            std::cerr << "[SwitchProcessor] Closing pending slice for pid=" << pid << "\n";
        }
        open.clear();
    }

    std::cerr << "[SwitchProcessor] Built " << slices_.size() << " slices\n";
}

void SwitchProcessor::store_csv(const std::string& filename) const {
    std::ofstream f(filename);
    f << "pid,cpu,command,start_ns,end_ns,delta_ns,reason\n";
    for (const auto& s : slices_) {
        f << s.pid << "," << s.cpu << "," << s.command << ","
          << s.start_ns << "," << s.end_ns << ","
          << s.delta_ns << "," << s.reason << "\n";
    }
    std::cerr << "[SwitchProcessor] Stored " << slices_.size()
              << " slices into " << filename << "\n";
}

void SwitchProcessor::plot_top_runtime_per_cpu(int top_n,
                                               const std::string& time_unit,
                                               const std::string& outfile_prefix) const {
    if (slices_.empty()) {
        std::cerr << "[SwitchProcessor] No slices; nothing to plot\n";
        return;
    }

    double scale = unit_scale(time_unit);
    /* aggregate total runtime per (cpu,pid,command) */
    std::map<std::tuple<uint32_t, uint32_t, std::string>, uint64_t> agg;

    for (const auto& s : slices_) {
        auto key = std::make_tuple(s.cpu, s.pid, s.command);
        agg[key] += s.delta_ns;
    }

    // top per CPU
    std::map<uint32_t, std::vector<std::pair<std::string, double>>> per_cpu;
    for (const auto& [k, tot_ns] : agg) {
        auto [cpu, pid, cmd] = k;
        std::string label = cmd + ":" + std::to_string(pid);
        per_cpu[cpu].push_back({label, tot_ns / scale}); // convert to requested unit
    }

    std::cerr << "[SwitchProcessor] Top per-CPU runtime (unit=" << time_unit << ")\n";
    for (auto& [cpu, vec] : per_cpu) {
        std::sort(vec.begin(), vec.end(),
                  [](auto& a, auto& b){ return a.second > b.second; });
        std::cerr << "CPU " << cpu << ":\n";
        int n = std::min<int>(top_n, vec.size());
        for (int i = 0; i < n; ++i) {
            std::cerr << "  " << vec[i].first << " -> " << vec[i].second << " " << time_unit << "\n";
        }
    }
}
