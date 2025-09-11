#!/usr/bin/python3
import os, argparse

from processor.Processor import EventProcessor
from processor.SwitchProcessor import SwitchProcessor
from syscall_logger.logger import SyscallLogger
from utils.logger import err_exit

parser = argparse.ArgumentParser(description="Syscall logger")
parser.add_argument("command", nargs="+", help="Command to execute")
parser.add_argument("--filters", help="Specify eBPF filters")
parser.add_argument("--print-raw", action='store_true', default=False,
                    help="Print to stdout raw tracepoint events")
parser.add_argument("--print-tree", action='store_true', default=False,
                    help="Print to stdout process tree")
parser.add_argument("--print-intervals", action='store_true', default=False,
                    help="Print to stdout alive process count time intervals")
parser.add_argument("--user", help="Username to launch the program")
args = parser.parse_args()

if not os.geteuid() == 0:
    err_exit("This script must be run as root.")

ebpf_filters = ["exit", "fork", "execve", "clone", "switch"] if not args.filters or args.filters == "ALL" else args.filters.split(
    ",")

logger = SyscallLogger(ebpf_filters, timeout=10, user=args.user)
logger.set_command(args.command)
logger.run(args.print_raw)

proc = EventProcessor(logger.events)
proc.build_tree(print_tree=args.print_tree)
proc.compute_intervals(print_intervals=args.print_intervals)
proc.store_to_csv()
proc.plot(title=f"Alive processes for: {args.command}")

sp = SwitchProcessor(logger.events)
sp.build_slices()
sp.store_csv("oncpu_slices.csv")
sp.plot_top_runtime_per_cpu(top_n=10, time_unit="ms", outfile_prefix="top_runtime_cpu_")

exit(0)
