import os, threading, datetime, psutil, re
import time

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
        self.thread = threading.Thread(target=self._poll)

    def _preprocess(self):
        keys = [ t.replace("@", "") for t in self.program_text.split() if t.startswith('@') ]
        for key in keys:
            with open(os.path.join(os.path.dirname(__file__), f"../bpf/TEMPLATE/{key}"), "r") as src:
                self.program_text = self.program_text.replace(f"@{key}", src.read())

    def _handle_template(self, data, event, event_modifier=""):
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
        #todo: give enough time to empty queues. FIX: find a better way to do this
        time.sleep(2)

        self.terminate = True
        self.thread.join()

    def collect(self):
        return self.events

    def __str__(self):
        return tabulate(self.events, headers="keys") + "\n\n"
