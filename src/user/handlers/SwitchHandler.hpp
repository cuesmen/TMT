#pragma once
#include "BaseHandler.hpp"
#include <string>

class SwitchHandler : public BaseHandler {
public:
    explicit SwitchHandler(int poll_timeout_ms = 100);
    ~SwitchHandler();

    bool install() override;
    void detach() override;
    void freeze_producer() override;
    uint64_t snapshot_total() override;

    int on_sample(void *data, size_t len) override;

private:
    bpf_object* obj_{nullptr};
    bpf_link* link_{nullptr};

    int map_cfg_{-1};
    int map_ev_{-1};
    int map_rb_{-1};

    std::string resolve_bpf_obj_path() const;
};
