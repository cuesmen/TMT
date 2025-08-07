from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import os

from utils.logger import err_exit, print_info, print_warn


class Clone3Handler(BaseHandler):

    def _handle(self, cpu, data, size):
        BaseHandler._handle_template(self, data, self.program["clone3_output"].event(data))

    def __init__(self, timeout=10):
        super(Clone3Handler, self).__init__(timeout, "clone2")

        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/clone3.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling clone3 filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled clone3 filter program")

    def install(self):
        self.program["clone3_output"].open_ring_buffer(self._handle)

        _clone3_ = self.program.get_syscall_fnname("clone3")
        if not self.program.attach_kprobe(event=_clone3_, fn_name="trace_clone3"):
            err_exit("Kprobe trace clone not connected or not founded")
        print_info("Installed clone3 handler")