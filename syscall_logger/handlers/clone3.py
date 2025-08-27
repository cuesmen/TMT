from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import ctypes as ct
import os

from utils.logger import err_exit, print_info, print_warn


class Clone3Handler(BaseHandler):
    def _handle(self, cpu, data, size):
        BaseHandler._handle_template(self, data, self.program["clone3_output"].event(data))

    def __init__(self, timeout=10):
        super(Clone3Handler, self).__init__(timeout, "clone3")  # fix name

        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/clone3.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling clone3 filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled clone3 filter program")

    def install(self):
        # open ring buffer
        self.program["clone3_output"].open_ring_buffer(self._handle)

        # attach kretprobe: we need the return value (child pid)
        try:
            fn = self.program.get_syscall_fnname("clone3")
            self.program.attach_kretprobe(event=fn, fn_name="trace_clone3_ret")
            print_info("Installed clone3 kretprobe")
        except Exception as e:
            err_exit(f"Kretprobe trace clone3 not connected: {e}")

        # enable producer
        try:
            self.program["cfg_enabled"][ct.c_uint(0)] = ct.c_uint(1)
            print_info("Enabled producer for clone3")
        except KeyError:
            print_warn("cfg_enabled map not present (producer always-on)")

    def detach(self):
        # clean detach
        try:
            fn = self.program.get_syscall_fnname("clone3")
            self.program.detach_kretprobe(event=fn)
        except Exception:
            pass
