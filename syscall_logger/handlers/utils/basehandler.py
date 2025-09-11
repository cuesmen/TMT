import os, threading, datetime, psutil, re
import time
import ctypes as ct

from tabulate import tabulate

from syscall_logger.handlers.utils.pids import pids, tgid, tids, register_new

def _format_timestamp(timestamp):
    boot_time = psutil.boot_time()
    seconds = boot_time + (timestamp / 1e9)
    return datetime.datetime.fromtimestamp(seconds).strftime('%Y-%m-%d %H:%M:%S.%f')


class BaseHandler:
    def __init__(self, timeout, eventName):
        self.events = []
        self.name = eventName
        self.pid = os.getpid()
        self.pgid = os.getpgid(self.pid)
        self.tgid = os.getgid()  
        self.timeout = timeout
        self.terminate = False
        self.read_events = 0             # <-- new
        self.total_expected = 0          # <-- new
        self.thread = threading.Thread(target=self._poll)

    def _preprocess(self):
        keys = [ t.replace("@", "") for t in self.program_text.split() if t.startswith('@') ]
        for key in keys:
            with open(os.path.join(os.path.dirname(__file__), f"../bpf/TEMPLATE/{key}"), "r") as src:
                self.program_text = self.program_text.replace(f"@{key}", src.read())

    def _handle_template(self, data, event, event_modifier=""):
        # Count every event delivered by the ring buffer (filtered or not),
        # so drain_until() can converge to snapshot(ev_count)
        self.read_events += 1

        # Apply your filter only for storing/printing
        if event.pid in pids or event.tid in tids or event.tgid in tgid:
            register_new(event)
            self.events.append({
                "event": self.name + event_modifier,
                "parent_pid": event.parent_pid,
                "pid": event.pid,
                "child_pid": event.child_pid,
                "pgid": event.pgid,
                "tid": event.tid,
                "tgid": event.tgid,
                "command": event.command.decode('utf-8', 'replace'),
                "timestamp": event.timestamp,
                "timestamp_human_format": _format_timestamp(event.timestamp),
            })

    def _poll(self):
        while not self.terminate:
            self.program.ring_buffer_poll(self.timeout)

    def start(self):
        self.thread.start()

    def stop(self):
        self.terminate = True
        self.thread.join()

    def collect(self):
        return self.events

    def __str__(self):
        return tabulate(self.events, headers="keys") + "\n\n"

    def freeze_producer(self):
        """cfg_enabled = 0 (se presente), altrimenti no-op."""
        try:
            m = self.program["cfg_enabled"]
            m[ct.c_uint(0)] = ct.c_uint(0)
        except Exception:
            pass

    def snapshot_total(self):
        """Sum ev_count per-CPU. Fallback: read_events."""
        total = 0
        try:
            tbl = self.program.get_table("ev_count")
            total = int(tbl.sum(ct.c_uint(0)).value)  # BCC sum per-CPU
        except Exception:
            total = self.read_events
        self.total_expected = total
        return total

    def drain_until(self, total_expected):
        idle = 0
        while self.read_events < total_expected:
            processed = 0
            try:
                processed = self.program.ring_buffer_poll(0)
            except Exception:
                break
            if not processed:
                idle += 1
                if idle > 5000:  # < 5ms exit with timeout
                    print_warn(f"[{self.name}] drain_until timeout: read={self.read_events}, expected={total_expected}")
                    break
                time.sleep(0.001) # 1ms
            else:
                idle = 0


    def detach(self):
        # default: no-op; (see Handler.detach)
        pass

