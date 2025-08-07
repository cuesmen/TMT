import os
import threading

global pids
pids = [os.getpid(), os.getppid()]
tgid = [os.getgid()]
tids = [threading.get_ident()]


def register_new(event):
    if event.pid not in pids:
        pids.append(event.pid)
    if event.tid not in tids:
        tids.append(event.tid)
    if event.tgid not in tgid:
        tgid.append(event.tgid)
    if event.child_pid > 0:
        pids.append(event.child_pid)