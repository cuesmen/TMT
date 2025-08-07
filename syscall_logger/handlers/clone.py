from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import os
from utils.logger import print_info, err_exit, print_warn


class CloneHandler(BaseHandler):

    def _handle(self, cpu, data, size):
        BaseHandler._handle_template(self, data, self.program["clone_output"].event(data))

    def __init__(self, timeout=10):
        super(CloneHandler, self).__init__(timeout, "clone")

        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/clone.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling clone filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled clone filter program")

    def install(self):

        self.program["clone_output"].open_ring_buffer(self._handle)

        _clone_ = self.program.get_syscall_fnname("clone")
        if not self.program.attach_kprobe(event=_clone_, fn_name="trace_clone"):
            err_exit("Kprobe trace clone not connected or not founded")
        print_info(f"Installed clone handler")