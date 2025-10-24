from syscall_logger.handlers.utils.basehandler import BaseHandler
from bcc import BPF
import ctypes as ct, os
from utils.logger import print_info, print_warn, err_exit

class RunEvt(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("cpu", ct.c_uint),
        ("pid", ct.c_uint),
        ("type", ct.c_uint),
        ("reason", ct.c_uint),
        ("comm", ct.c_char * 16),
        # dummy fields to satisfy BaseHandler
        ("parent_pid", ct.c_uint),
        ("child_pid", ct.c_uint),
        ("pgid", ct.c_uint),
        ("tid", ct.c_uint),
        ("tgid", ct.c_uint),
        ("command", ct.c_char * 16),
        ("timestamp", ct.c_ulonglong),
    ]

class SwitchHandler(BaseHandler):
    def _handle(self, cpu, data, size):
        e = self.program["sched_output"].event(data)
        evt = {
            "event": "run" if e.type == 1 else "desched",
            "timestamp": int(e.ts),
            "cpu": int(e.cpu),
            "pid": int(e.pid),
            "reason": "preempt" if (e.type == 2 and e.reason == 0) else
                    "sleep" if (e.type == 2 and e.reason == 1) else None,
            "command": e.comm.decode("utf-8", "replace"),
        }
        self.events.append(evt) 


    def __init__(self, timeout=10, allow_pids=None):
        super(SwitchHandler, self).__init__(timeout, "switch")
        self.source_path = os.path.join(os.path.dirname(__file__), "bpf/switch.c")
        with open(self.source_path, "r") as f:
            self.program_text = f.read()
            self._preprocess()

        print_warn("Compiling sched_switch program...")
        self.program = BPF(text=self.program_text)
        print_info("Compiled sched_switch program")

        self.allow_pids = allow_pids or []

    def install(self):
        # attach tracepoint
        try:
            self.program.attach_tracepoint(tp="sched:sched_switch", fn_name="trace_sched_switch")
            print_info("Installed handler (sched:sched_switch)")
        except Exception as e:
            err_exit(f"Unable to attach sched_switch: {e}")

        # open ring buffer
        self.program["sched_output"].open_ring_buffer(self._handle)

        # set useFilter = 0
        try:
            self.program["cfg_useFilter"][ct.c_uint(0)] = ct.c_uint(0)
            print_info("Scheduler handler: filter disabled (all PIDs)")
        except Exception:
            print_warn("cfg_useFilter map non presente")


    def detach(self):
        try:
            self.program.detach_tracepoint(tp="sched:sched_switch")
        except Exception:
            pass
