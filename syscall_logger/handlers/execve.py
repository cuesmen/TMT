from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import os

from utils.logger import print_info, err_exit, print_warn


class ExecveHandler(BaseHandler):
    def _handle_in(self, cpu, data, size):
        BaseHandler._handle_template(self, data, self.program["execve_output_in"].event(data), "-entry")

    def _handle_out(self, cpu, data, size):
        BaseHandler._handle_template(self, data, self.program["execve_output_out"].event(data), "-exit")

    def __init__(self, timeout=10):
        super(ExecveHandler, self).__init__(timeout, "execve")

        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/execve.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling execve filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled execve filter program")

    def install(self):
        self.program["execve_output_in"].open_ring_buffer(self._handle_in)
        self.program["execve_output_out"].open_ring_buffer(self._handle_out)

        if not self.program.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve"):
            err_exit("Unable to attach fork tracepoint")
        print_info("Installed execve_entry handler")

        if not self.program.attach_tracepoint(tp="syscalls:sys_exit_execve", fn_name="trace_execve_exit"):
            err_exit("Tracepoint exit_execve not connected or not founded")
        print_info("Installed execve_exit handler")