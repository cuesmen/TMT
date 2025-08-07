import subprocess, time
from tabulate import tabulate

from syscall_logger.handlers.clone import CloneHandler
from syscall_logger.handlers.clone3 import Clone3Handler
from syscall_logger.handlers.exit import ExitHandler
from syscall_logger.handlers.exitgroup import ExitGroupHandler
from syscall_logger.handlers.fork import ForkHandler
from syscall_logger.handlers.execve import ExecveHandler
from utils.logger import print_info


class SyscallLogger:

    def _install(self):
        print_info("Installing handlers...")
        for h in self.handlers:
            h.install()
            h.start()

    def _stop(self):
        print_info("Stopping handlers...")
        for h in self.handlers:
            h.stop()

    def _log(self):
        if self.command is None:
            raise Exception("Command not set")
        print("\n\n")
        pid = subprocess.Popen(self.command, shell=True)
        while pid.poll() is None:
            time.sleep(1)
        print("\n\n")
        self._stop()

    def __init__(self, handlers=[], timeout=10, user="root"):
        self.events = None
        self.command = None
        self.user = user
        self.handlers = []
        for handler in handlers:
            if handler == "exit":
                self.handlers.append(ExitHandler(timeout))
                self.handlers.append(ExitGroupHandler(timeout))
            elif handler == "fork":
                self.handlers.append(ForkHandler(timeout))
            elif handler == "execve":
                self.handlers.append(ExecveHandler(timeout))
            elif handler == "clone":
                self.handlers.append(CloneHandler(timeout))
                self.handlers.append(Clone3Handler(timeout))
            else:
                raise Exception("Unknown handler: " + handler)

    def set_command(self, command):
        print_info(f"Setting command to: {command}")
        self.command = command

    def run(self, print_events=False):
        print_info("Starting installation...")
        self._install()
        print_info("Starting log collection...")
        self._log()
        self.events = sorted([item for e in self.handlers for item in e.collect()], key=lambda x: x["timestamp"])
        event_zero = int(self.events[0]["timestamp"])
        for event in self.events:
            event["timestamp"] = int(event["timestamp"]) - event_zero
        print_info("Completed collection of events...")

        if print_events:
            print(self)

    def __str__(self):
        return "\n\nTRACED EVENTS:\n" + tabulate(self.events, headers="keys")

    def print(self):
        print(self)
