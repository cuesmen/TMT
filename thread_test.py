import threading
import subprocess
import os
import time
import argparse
import math
import random
from typing import List

def busy_cpu(seconds: float):
    end = time.time() + seconds
    x = 0.0
    while time.time() < end:
        x = math.sqrt(x * x + 1.23456789)

def worker_sleep(seconds: float):
    time.sleep(seconds)

def make_threads(n: int, lifetime: float, stagger: float = 0.0, cpu_ratio: float = 0.0) -> List[threading.Thread]:
    threads = []
    cpu_count = int(n * cpu_ratio)
    for i in range(n):
        if i < cpu_count:
            t = threading.Thread(target=busy_cpu, args=(lifetime,))
        else:
            t = threading.Thread(target=worker_sleep, args=(lifetime,))
        t.start()
        threads.append(t)
        if stagger > 0:
            time.sleep(stagger)
    return threads

def wait_threads(threads: List[threading.Thread]):
    for t in threads:
        t.join()

def fork_children(n: int, lifetime: float):
    pids = []
    for _ in range(n):
        pid = os.fork()
        if pid == 0:
            try:
                time.sleep(lifetime)
            finally:
                os._exit(0)
        else:
            pids.append(pid)
    for pid in pids:
        os.waitpid(pid, 0)

def execve_storm(n: int, cmd: List[str]):
    procs = []
    for _ in range(n):
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
    for p in procs:
        p.wait()

def phase_threads(args):
    print(f"[A] Threads bursts: {args.t1} then {args.t2} then {args.t3}")
    threads = []
    threads += make_threads(n=args.t1, lifetime=args.t_life, stagger=args.t_stagger, cpu_ratio=args.t_cpu_ratio)
    time.sleep(args.pause1)
    threads += make_threads(n=args.t2, lifetime=args.t_life, stagger=args.t_stagger, cpu_ratio=args.t_cpu_ratio)
    time.sleep(args.pause2)
    threads += make_threads(n=args.t3, lifetime=args.t_life, stagger=args.t_stagger, cpu_ratio=args.t_cpu_ratio)
    wait_threads(threads)
    print("[A] Threads done.")

def phase_fork(args):
    print(f"[B] Fork storm: {args.f1} then {args.f2}")
    fork_children(n=args.f1, lifetime=args.f_life)
    time.sleep(args.f_pause)
    fork_children(n=args.f2, lifetime=args.f_life)
    print("[B] Forks done.")

def phase_execve(args):
    print(f"[C] Execve storm: {args.e1} + {args.e2} processes")
    execve_storm(n=args.e1, cmd=args.exec_cmd)
    time.sleep(args.e_pause)
    execve_storm(n=args.e2, cmd=args.exec_cmd)
    print("[C] Execve done.")

def phase_mix(args):
    print(f"[D] Mixed: interleave threads/forks quickly (rounds={args.mix_rounds})")
    threads = []
    for _ in range(args.mix_rounds):
        threads += make_threads(n=args.mix_tn, lifetime=args.t_life, stagger=args.mix_t_stagger, cpu_ratio=args.t_cpu_ratio)
        fork_children(n=args.mix_fn, lifetime=args.f_life)
        time.sleep(args.mix_pause)
    wait_threads(threads)
    print("[D] Mixed done.")

def parse_args():
    p = argparse.ArgumentParser(description="Stress generator for eBPF tracer (threads, fork, execve).")
    p.add_argument("--t1", type=int, default=60)
    p.add_argument("--t2", type=int, default=30)
    p.add_argument("--t3", type=int, default=40)
    p.add_argument("--t-life", type=float, default=0.5)
    p.add_argument("--t-stagger", type=float, default=0.0005)
    p.add_argument("--t-cpu-ratio", type=float, default=0.2)
    p.add_argument("--pause1", type=float, default=0.05)
    p.add_argument("--pause2", type=float, default=0.05)
    p.add_argument("--f1", type=int, default=60)
    p.add_argument("--f2", type=int, default=40)
    p.add_argument("--f-life", type=float, default=0.05)
    p.add_argument("--f-pause", type=float, default=0.05)
    p.add_argument("--e1", type=int, default=80)
    p.add_argument("--e2", type=int, default=80)
    p.add_argument("--exec-cmd", nargs="+", default=["/bin/true"])
    p.add_argument("--e-pause", type=float, default=0.05)
    p.add_argument("--mix-rounds", type=int, default=3)
    p.add_argument("--mix-tn", type=int, default=10)
    p.add_argument("--mix-fn", type=int, default=5)
    p.add_argument("--mix-t-stagger", type=float, default=0.0002)
    p.add_argument("--mix-pause", type=float, default=0.02)
    p.add_argument("--no-threads", action="store_true")
    p.add_argument("--no-fork", action="store_true")
    p.add_argument("--no-execve", action="store_true")
    p.add_argument("--no-mix", action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    start = time.time()
    if not args.no_threads:
        phase_threads(args)
    if not args.no_fork:
        phase_fork(args)
    if not args.no_execve:
        phase_execve(args)
    if not args.no_mix:
        phase_mix(args)
    print(f"All phases done in {time.time() - start:.2f}s")

if __name__ == "__main__":
    main()
