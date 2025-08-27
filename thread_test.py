# stress_test.py
import threading
import subprocess
import os
import time
import argparse
import math
import random
from typing import List

def busy_cpu(seconds: float):
    """Spin-CPU for 'seconds' to create runnable load."""
    end = time.time() + seconds
    x = 0.0
    while time.time() < end:
        x = math.sqrt(x * x + 1.23456789)  # silly math to keep CPU busy

def worker_sleep(seconds: float):
    time.sleep(seconds)

def make_threads(n: int, lifetime: float, stagger: float = 0.0, cpu_ratio: float = 0.0) -> List[threading.Thread]:
    """
    Create 'n' threads.
    - lifetime: seconds each thread lives (sleep or cpu)
    - stagger: delay between thread starts
    - cpu_ratio: fraction [0..1] of threads that run busy-CPU instead of sleep
    """
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
    """
    Fork 'n' short-lived children.
    Children sleep 'lifetime' and then _exit(0).
    Parent waits all.
    """
    pids = []
    for _ in range(n):
        pid = os.fork()
        if pid == 0:  # child
            try:
                time.sleep(lifetime)
            finally:
                os._exit(0)
        else:
            pids.append(pid)

    for pid in pids:
        os.waitpid(pid, 0)

def execve_storm(n: int, cmd: List[str]):
    """
    Spawn 'n' very short processes via execve (hits execve enter/exit).
    """
    procs = []
    for _ in range(n):
        # Avoid shell to keep it lightweight and clear
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
    # Reap
    for p in procs:
        p.wait()

def phase_threads(args):
    print(f"[A] Threads bursts: {args.t1} then {args.t2} then {args.t3}")
    threads = []
    # Burst 1: larger, moderate stagger to make a visible ramp
    threads += make_threads(n=args.t1, lifetime=args.t_life, stagger=args.t_stagger, cpu_ratio=args.t_cpu_ratio)
    time.sleep(args.pause1)
    # Burst 2: smaller, shorter pause to create overlap
    threads += make_threads(n=args.t2, lifetime=args.t_life, stagger=args.t_stagger, cpu_ratio=args.t_cpu_ratio)
    time.sleep(args.pause2)
    # Burst 3: mid
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
        # small batch of threads with tiny stagger
        threads += make_threads(n=args.mix_tn, lifetime=args.t_life, stagger=args.mix_t_stagger, cpu_ratio=args.t_cpu_ratio)
        # small fork burst
        fork_children(n=args.mix_fn, lifetime=args.f_life)
        # very tiny sleep to shuffle timestamps
        time.sleep(args.mix_pause)
    wait_threads(threads)
    print("[D] Mixed done.")

def parse_args():
    p = argparse.ArgumentParser(description="Stress generator for eBPF tracer (threads, fork, execve).")
    # Threads phase
    p.add_argument("--t1", type=int, default=150, help="threads in burst 1")
    p.add_argument("--t2", type=int, default=60, help="threads in burst 2")
    p.add_argument("--t3", type=int, default=100, help="threads in burst 3")
    p.add_argument("--t-life", type=float, default=2.0, help="lifetime (s) of each thread")
    p.add_argument("--t-stagger", type=float, default=0.003, help="delay (s) between thread starts")
    p.add_argument("--t-cpu-ratio", type=float, default=0.2, help="fraction of threads doing busy CPU [0..1]")
    p.add_argument("--pause1", type=float, default=0.3, help="pause between burst1 and burst2")
    p.add_argument("--pause2", type=float, default=0.3, help="pause between burst2 and burst3")
    # Fork phase
    p.add_argument("--f1", type=int, default=120, help="forks in storm 1")
    p.add_argument("--f2", type=int, default=80, help="forks in storm 2")
    p.add_argument("--f-life", type=float, default=0.2, help="child lifetime (s)")
    p.add_argument("--f-pause", type=float, default=0.2, help="pause between fork storms")
    # Execve phase
    p.add_argument("--e1", type=int, default=200, help="execve processes in wave 1")
    p.add_argument("--e2", type=int, default=200, help="execve processes in wave 2")
    p.add_argument("--exec-cmd", nargs="+", default=["/bin/true"], help="command to exec for the storm")
    p.add_argument("--e-pause", type=float, default=0.2, help="pause between exec waves")
    # Mixed phase
    p.add_argument("--mix-rounds", type=int, default=5, help="how many interleaved rounds")
    p.add_argument("--mix-tn", type=int, default=20, help="threads per round in mix")
    p.add_argument("--mix-fn", type=int, default=10, help="forks per round in mix")
    p.add_argument("--mix-t-stagger", type=float, default=0.001, help="thread stagger in mix")
    p.add_argument("--mix-pause", type=float, default=0.05, help="pause between interleaved actions")
    # Phases toggle
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
