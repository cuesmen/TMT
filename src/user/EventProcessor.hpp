#pragma once
#include "include/common.hpp"
#include <vector>
#include <string>
#include <memory>

struct Node;

struct TimeInterval {
    uint64_t time;
    int alive;
};

class EventProcessor {
public:
    explicit EventProcessor(const std::vector<Event>& evs);
    ~EventProcessor();

    void build_tree(bool print_tree = false);
    void compute_intervals(bool print_intervals = false);
    void store_to_csv(const std::string& filename = "out/alive_series.csv") const;

private:
    void print_tree_rec(const Node& n, int depth) const;

    std::vector<Event> events_;
    std::unique_ptr<Node> root_;
    std::vector<TimeInterval> time_intervals_;
};
