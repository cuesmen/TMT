#pragma once
#include "BaseHandler.hpp"
#include <string>

class ForkHandler : public BaseHandler {
public:
    explicit ForkHandler(int poll_timeout_ms = 100);
    ~ForkHandler();

    bool install() override;
    void detach() override;
    void freeze_producer() override;
    uint64_t snapshot_total() override;

    int on_sample(void *data, size_t len) override; 
    int on_sample_with_tag(const char* tag, void *data, size_t len);

    struct RbCtx { ForkHandler* self; const char* tag; };

private:
    struct bpf_object* obj_{nullptr};
    struct bpf_link*   link_fork_exit_{nullptr};

    int map_cfg_{-1};
    int map_ev_{-1};
    int map_rb_fork_{-1};

    RbCtx rb_fork_ctx_{};

    std::string resolve_bpf_obj_path() const;
};
