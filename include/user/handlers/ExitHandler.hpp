#pragma once
#include "BaseHandler.hpp"
#include <string>

class ExitHandler : public BaseHandler {
public:
    explicit ExitHandler(int poll_timeout_ms = 100);
    ~ExitHandler();

    bool install() override;
    void detach() override;
    void freeze_producer() override;
    uint64_t snapshot_total() override;

    int on_sample(void *data, size_t len) override;
    int on_sample_with_tag(const char* tag, void *data, size_t len);

    struct RbCtx { ExitHandler* self; const char* tag; };

private:
    struct bpf_object* obj_{nullptr};
    struct bpf_link*   link_exit_{nullptr};
    struct bpf_link*   link_exitgrp_{nullptr};

    int map_cfg_{-1};
    int map_ev_{-1};
    int map_rb_exit_{-1};
    int map_rb_exitgrp_{-1};

    RbCtx rb_exit_ctx_{}, rb_exitgrp_ctx_{};

    std::string resolve_bpf_obj_path() const;
};
