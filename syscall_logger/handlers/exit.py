from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
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
        self.program["exit_output"].open_ring_buffer(self._handle)

        if not self.program.attach_tracepoint(tp="syscalls:sys_enter_exit", fn_name="trace_exit"):
            err_exit("Tracepoint enter_exit not connected or not founded")
        print_info("Installed exit handler")