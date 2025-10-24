#pragma once
#include "BaseHandler.hpp"
#include <string>

class ExecveHandler : public BaseHandler {
public:
    ExecveHandler(int poll_timeout_ms = 100);
    ~ExecveHandler();

    bool install() override;
    void detach() override;
    void freeze_producer() override;
    uint64_t snapshot_total() override;

    int on_sample(void *data, size_t len) override;
    int on_sample_with_tag(const char* tag, void *data, size_t len);

private:
    bpf_object* obj_{nullptr};
    bpf_link* link_enter_{nullptr};
    bpf_link* link_exit_{nullptr};

    int map_cfg_{-1};
    int map_ev_{-1};
    int map_rb_in_{-1};
    int map_rb_out_{-1};

    struct RbCtx { ExecveHandler* self; const char* tag; } rb_in_ctx_{}, rb_out_ctx_{};

    std::string resolve_bpf_obj_path() const;
};
