from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import ctypes as ct
import os

from utils.logger import print_info, err_exit, print_warn


class ExitGroupHandler(BaseHandler):
    def _handle(self, cpu, data, size):
        BaseHandler._handle_template(self, data, self.program["exit_group_output"].event(data))

    def __init__(self, timeout=10):
        super(ExitGroupHandler, self).__init__(timeout, "exit_group")

        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/exitgroup.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling exit_group filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled exit_group filter program")

    def install(self):
        # open ring buffer
        self.program["exit_group_output"].open_ring_buffer(self._handle)

        # attach tracepoint
        try:
            self.program.attach_tracepoint(tp="syscalls:sys_enter_exit_group", fn_name="trace_exit_group")
            print_info("Installed exit_group handler (sys_enter_exit_group)")
        except Exception as e:
            err_exit(f"Tracepoint sys_enter_exit_group not connected or not found: {e}")

        # enable producer
        try:
            self.program["cfg_enabled"][ct.c_uint(0)] = ct.c_uint(1)
            print_info("Enabled producer for exit_group")
        except KeyError:
            print_warn("cfg_enabled map not present (producer always-on)")

    def detach(self):
        # clean detach
        try:
            self.program.detach_tracepoint(tp="syscalls:sys_enter_exit_group")
        except Exception:
            pass
