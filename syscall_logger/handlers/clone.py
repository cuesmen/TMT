from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import ctypes as ct
import os
from utils.logger import print_info, err_exit, print_warn

class CloneHandler(BaseHandler):
    def _handle(self, cpu, data, size):
        # Decode the event from the ring buffer and push it through the common formatter
        BaseHandler._handle_template(self, data, self.program["clone_output"].event(data))

    def __init__(self, timeout=10):
        # Initialize base handler with the name used in the output events
        super(CloneHandler, self).__init__(timeout, "clone")

        # Load eBPF C source (with your @include/@data/@common_maps preprocessing)
        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/clone.c")
        with open(self.source_path, "r") as source:
            self.program_text = source.read()
            self._preprocess()

        print_warn("Compiling clone filter program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled clone filter program")

    def install(self):
        # Open the ring buffer and register the callback
        self.program["clone_output"].open_ring_buffer(self._handle)

        # Attach kretprobe to clone (we need the return value to get child_pid)
        try:
            fn = self.program.get_syscall_fnname("clone")
            self.program.attach_kretprobe(event=fn, fn_name="trace_clone_ret")
            print_info("Installed clone kretprobe")
        except Exception as e:
            err_exit(f"Kretprobe trace clone not connected: {e}")

        # Enable producer (cfg_enabled[0] = 1) if the map exists
        try:
            self.program["cfg_enabled"][ct.c_uint(0)] = ct.c_uint(1)
            print_info("Enabled producer for clone")
        except KeyError:
            print_warn("cfg_enabled map not present (producer always-on)")

    def detach(self):
        # Cleanly detach the kretprobe (ignore errors on shutdown)
        try:
            fn = self.program.get_syscall_fnname("clone")
            self.program.detach_kretprobe(event=fn)
        except Exception:
            pass
