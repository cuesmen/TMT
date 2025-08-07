from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import os

from utils.logger import print_info, err_exit, print_warn


class ForkHandler(BaseHandler):

    def _handle(self, cpu, data, size):
        BaseHandler._handle_template(self, data, self.program["fork_output"].event(data))

    def __init__(self, timeout=10):
        super(ForkHandler, self).__init__(timeout, "fork")

        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/fork.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling fork filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled fork filter program")

    def install(self):
        self.program["fork_output"].open_ring_buffer(self._handle)
        if not self.program.attach_tracepoint(tp="sched:sched_process_fork", fn_name="trace_fork"):
            err_exit("Error: unable to attach fork tracepoint")

        print_info("Installed fork handler")