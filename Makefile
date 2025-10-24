CC       = clang
CXX      = clang++

CFLAGS_BPF  = -O2 -g -target bpf -D__TARGET_ARCH_x86
CXXFLAGS    = -O2 -g -std=c++17

# Struct
SRC_DIR   := src
BPF_DIR   := $(SRC_DIR)/bpf
USER_DIR  := $(SRC_DIR)/user
BIN_DIR   := bin
OUT_DIR   := out

# BPF
BPF_SRCS := $(BPF_DIR)/execve.bpf.c \
            $(BPF_DIR)/fork.bpf.c \
            $(BPF_DIR)/exit.bpf.c \
            $(BPF_DIR)/clone.bpf.c \
            $(BPF_DIR)/clone3.bpf.c \
            $(BPF_DIR)/exit_group.bpf.c \
            $(BPF_DIR)/sched_switch.bpf.c 
BPF_OBJS := $(patsubst $(BPF_DIR)/%.bpf.c,$(BIN_DIR)/%.bpf.o,$(BPF_SRCS))

BPF_INCLUDES = -Isrc/bpf/include -I/usr/include/$(shell uname -m)-linux-gnu

# Userland
USER_SRCS := \
  $(USER_DIR)/main.cpp \
  $(USER_DIR)/SyscallLogger.cpp \
  $(USER_DIR)/EventProcessor.cpp \
  $(USER_DIR)/SwitchProcessor.cpp \
  $(USER_DIR)/handlers/BaseHandler.cpp \
  $(USER_DIR)/handlers/ExecveHandler.cpp \
  $(USER_DIR)/handlers/ForkHandler.cpp \
  $(USER_DIR)/handlers/ExitHandler.cpp \
  $(USER_DIR)/handlers/CloneHandler.cpp \
  $(USER_DIR)/handlers/Clone3Handler.cpp \
  $(USER_DIR)/handlers/ExitGroupHandler.cpp \
  $(USER_DIR)/handlers/SwitchHandler.cpp
USER_BIN  := $(BIN_DIR)/tmt_logger

# -BPF Libs-
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs   libbpf 2>/dev/null)
ifeq ($(LIBBPF_LIBS),)
  LIBBPF_LIBS := -lbpf -lelf -lz
endif
LDLIBS := $(LIBBPF_LIBS) -pthread
LDFLAGS += -Wl,-rpath,/usr/lib64:/usr/local/lib -L/usr/lib64


all: $(BPF_OBJS) $(USER_BIN)

$(BIN_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS_BPF) $(BPF_INCLUDES) -c $< -o $@

$(USER_BIN): $(USER_SRCS)
	@mkdir -p $(BIN_DIR) $(OUT_DIR)
	$(CXX) $(CXXFLAGS) -Isrc/user -Isrc/user/include $(USER_SRCS) -o $@ $(LDFLAGS) $(LDLIBS)

run: all
	sudo -E $(USER_BIN) --cmd "sleep 1" --print-raw

clean:
	rm -rf $(BIN_DIR)/* $(OUT_DIR)/*
