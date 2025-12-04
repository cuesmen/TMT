#include "EventProcessor.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <set>
#include <map>
#include <vector>
#include <string>

#if TMT_DEBUG_INTERVALS
#define DBG_PRINT(x) do { std::cerr << x << std::endl; } while(0)
#else
#define DBG_PRINT(x) do {} while(0)
#endif


struct Node {
    uint32_t pid;
    std::string command;
    bool alive{false};
    std::vector<Node> children;

    Node(uint32_t pid_, const std::string& cmd_, bool alive_ = false)
        : pid(pid_), command(cmd_), alive(alive_) {}

    int size() const {
        int total = 1;
        for (const auto& c : children)
            total += c.size();
        return total;
    }

    int compute_alive() const {
        if (!alive) return 0;
        int total = 1;
        for (const auto& c : children)
            total += c.compute_alive();
        return total;
    }

    void set_alive(uint32_t target_pid) {
        if (pid == target_pid) {
            alive = true;
            return;
        }
        for (auto& c : children)
            c.set_alive(target_pid);
    }

    void kill_all() {
        alive = false;
        for (auto& c : children)
            c.kill_all();
    }

    void set_dead(uint32_t target_pid) {
        if (pid == target_pid) {
            kill_all();
        } else {
            for (auto& c : children)
                c.set_dead(target_pid);
        }
    }

    bool add_child(const Event& e) {
        if (e.event == "fork" || e.event == "clone" || e.event == "clone3") {
            if (e.pid == pid) {
                children.emplace_back(e.child_pid, e.command);
                return true;
            } else {
                for (auto& c : children)
                    if (c.add_child(e))
                        return true;
            }
        }
        return false;
    }
};


EventProcessor::~EventProcessor() = default;

EventProcessor::EventProcessor(const std::vector<Event>& evs, uint32_t root_pid)
: events_(evs), root_pid_hint_(root_pid)
{
    if (events_.empty())
        return;

    root_pid = root_pid_hint_;
    std::string root_comm = "[unknown]";

    if (root_pid == 0) {
        root_pid  = events_.front().pid;
        root_comm = events_.front().command;
    } else {
        for (const auto& e : events_) {
            if (e.pid == root_pid) {
                root_comm = e.command;
                break;
            }
        }
    }

    root_ = std::make_unique<Node>(root_pid, root_comm, true);
}


void EventProcessor::build_tree(bool print_tree) {
    std::cerr << "[WARN] Building process tree...\n";
    if (!root_) return;

    for (const auto& e : events_)
        root_->add_child(e);

    std::cerr << "[INFO] Tree built successfully.\n";

    if (print_tree) {
        print_tree_rec(*root_, 0);
    }
}

void EventProcessor::print_tree_rec(const Node& n, int depth) const {
    for (int i = 0; i < depth; ++i) std::cerr << "  ";
    std::cerr << n.command << " (" << n.pid << ")";
    if (n.alive) std::cerr << " [ALIVE]";
    std::cerr << "\n";
    for (const auto& c : n.children)
        print_tree_rec(c, depth + 1);
}

void EventProcessor::compute_intervals(bool print_intervals) {
    std::cerr << "[WARN] Computing timestamp intervals...\n";
    if (!root_) return;

    std::vector<const Event*> evp;
    evp.reserve(events_.size());
    for (auto& e : events_) evp.push_back(&e);

    std::sort(evp.begin(), evp.end(),
              [](const Event* a, const Event* b){ return a->timestamp < b->timestamp; });

    time_intervals_.clear();

    uint64_t max_ts = 0;

    for (const auto* e : evp) {
        if (e->timestamp > max_ts)
            max_ts = e->timestamp;

        if (e->event == "fork" || e->event == "clone" || e->event == "clone3") {
            root_->set_alive(e->child_pid);
        }
        else if (e->event == "exit") {
            root_->set_dead(e->pid);
        }
        else if (e->event == "exit_group") {
            root_->set_dead(e->parent_pid);
        }

        int old_alive = time_intervals_.empty() ? -1 : time_intervals_.back().alive;
        int alive = root_->compute_alive();

        if (time_intervals_.empty() || time_intervals_.back().alive != alive) {
            DBG_PRINT(
                "[DBG] ts=" << e->timestamp
                << " event=" << e->event
                << " pid=" << e->pid
                << " parent_pid=" << e->parent_pid
                << " alive=" << old_alive << " -> " << alive
            );            
            time_intervals_.push_back({ e->timestamp, alive });
        }

    }

    if (!time_intervals_.empty() && time_intervals_.back().time < max_ts) {
        int last_alive = time_intervals_.back().alive;
        time_intervals_.push_back({ max_ts, last_alive });

        int old_alive = time_intervals_.empty() ? -1 : time_intervals_.back().alive;
    }

    std::cerr << "[INFO] Computed " << time_intervals_.size() << " time intervals.\n";
    if (print_intervals) {
        std::cerr << "time,alive\n";
        for (const auto& t : time_intervals_)
            std::cerr << t.time << "," << t.alive << "\n";
    }
}


void EventProcessor::store_to_csv(const std::string& filename) const {
    std::ofstream f(filename);
    f << "time,alive\n";
    for (auto& p : time_intervals_) {
        f << p.time << "," << p.alive << "\n";
    }
    f.close();
    std::cerr << "[INFO] Saved CSV to " << filename << "\n";
}
