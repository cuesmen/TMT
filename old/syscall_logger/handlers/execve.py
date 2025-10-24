from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import ctypes as ct
import os

from utils.logger import print_info, err_exit, print_warn


class ExecveHandler(BaseHandler):
    def _handle_in(self, cpu, data, size):
        # Handle sys_enter_execve events
        BaseHandler._handle_template(self, data, self.program["execve_output_in"].event(data), "-entry")

    def _handle_out(self, cpu, data, size):
        # Handle sys_exit_execve events
        BaseHandler._handle_template(self, data, self.program["execve_output_out"].event(data), "-exit")

    def __init__(self, timeout=10):
        # Initialize base handler with the name used in the output events
        super(ExecveHandler, self).__init__(timeout, "execve")

        # Load eBPF C source (with your @include/@data/@common_maps preprocessing)
        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/execve.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling execve filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled execve filter program")

    def install(self):
        # Open ring buffers and register callbacks
        self.program["execve_output_in"].open_ring_buffer(self._handle_in)
        self.program["execve_output_out"].open_ring_buffer(self._handle_out)

        # Attach tracepoints (use try/except; BCC raises on error instead of returning False)
        try:
            self.program.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_execve")
            print_info("Installed execve_entry handler")
        except Exception as e:
            err_exit(f"Unable to attach sys_enter_execve: {e}")

        try:
            self.program.attach_tracepoint(tp="syscalls:sys_exit_execve", fn_name="trace_execve_exit")
            print_info("Installed execve_exit handler")
        except Exception as e:
            err_exit(f"Unable to attach sys_exit_execve: {e}")

        # Enable producer (cfg_enabled[0] = 1) if the map exists
        try:
            self.program["cfg_enabled"][ct.c_uint(0)] = ct.c_uint(1)
            print_info("Enabled producer for execve")
        except KeyError:
            print_warn("cfg_enabled map not present (producer always-on)")

    def detach(self):
        # Cleanly detach both tracepoints (ignore errors on shutdown)
        try:
            self.program.detach_tracepoint(tp="syscalls:sys_enter_execve")
        except Exception:
            pass
        try:
            self.program.detach_tracepoint(tp="syscalls:sys_exit_execve")
        except Exception:
            pass
