from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import ctypes as ct
import os

from utils.logger import print_info, err_exit, print_warn


class ExitHandler(BaseHandler):
    def _handle(self, cpu, data, size):
        BaseHandler._handle_template(self, data, self.program["exit_output"].event(data))

    def __init__(self, timeout=10):
        super(ExitHandler, self).__init__(timeout, "exit")

        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/exit.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling exit filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled exit filter program")

    def install(self):
        # open ring buffer
        self.program["exit_output"].open_ring_buffer(self._handle)

        # attach tracepoint (sys_enter_exit)
        try:
            self.program.attach_tracepoint(tp="syscalls:sys_enter_exit", fn_name="trace_exit")
            print_info("Installed exit handler (sys_enter_exit)")
        except Exception as e:
            err_exit(f"Tracepoint sys_enter_exit not connected or not found: {e}")

        # enable producer
        try:
            self.program["cfg_enabled"][ct.c_uint(0)] = ct.c_uint(1)
            print_info("Enabled producer for exit")
        except KeyError:
            print_warn("cfg_enabled map not present (producer always-on)")

    def detach(self):
        # clean detach
        try:
            self.program.detach_tracepoint(tp="syscalls:sys_enter_exit")
        except Exception:
            pass
