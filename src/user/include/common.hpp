#pragma once
#include <string>
#include <cstdint>

struct Event {
    std::string event;           
    uint32_t parent_pid{0};
    uint32_t pid{0};
    uint32_t child_pid{0};
    uint32_t pgid{0};
    uint32_t tid{0};
    uint32_t tgid{0};
    uint32_t cpu{0};          
    std::string command;
    uint64_t timestamp{0};
    std::string timestamp_human;
    std::string reason;
};
