#pragma once
#include "BaseHandler.hpp"
#include <string>

class Clone3Handler : public BaseHandler {
public:
    explicit Clone3Handler(int poll_timeout_ms);
    ~Clone3Handler();

    bool install() override;
    void detach() override;
    void freeze_producer() override;
    uint64_t snapshot_total() override;

    int on_sample(void *data, size_t len) override;

protected:
    int on_sample_with_tag(const char* tag, void *data, size_t len);

private:
    std::string resolve_bpf_obj_path() const;

    int map_cfg_{-1};
    int map_ev_{-1};
    int map_rb_{-1};

    bpf_object *obj_{nullptr};
    bpf_link   *link_{nullptr};
    ring_buffer *rb_{nullptr};

    struct RbCtx { Clone3Handler* self; const char* tag; } rb_ctx_{};
    static int sample_cb(void *ctx, void *data, size_t len);
};
