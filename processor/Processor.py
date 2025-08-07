import os
from PrettyPrint import PrettyPrintTree
from colorama import Back
from utils.logger import print_warn, print_info
from tabulate import tabulate
import matplotlib.pyplot as plt
import csv


class Node:
    def __init__(self, pid, command, alive=False):
        self.children = []
        self.pid = pid
        self.alive = alive
        self.command = command

    def __str__(self, level=0):
        ret = "  " * level + repr(self.pid) + "\n"
        for child in self.children:
            ret += child.__str__(level + 1)
        return ret

    def size(self):
        return 1 + sum([x.size() for x in self.children])

    def compute_alive(self):
        if not self.alive:
            return 0
        alive = 1
        for child in self.children:
            alive += child.compute_alive()
        return alive

    def set_alive(self, pid):
        if self.pid == pid:
            self.alive = True
            return

        for child in self.children:
            child.set_alive(pid)

    def _killall(self):
        self.alive = False
        for child in self.children:
            child._killall()

    def set_dead(self, pid):
        if self.pid == pid:
            self._killall()

        else:
            for child in self.children:
                child.set_dead(pid)

    def add_child(self, event):
        if event["event"] == "fork":
            if event["pid"] == self.pid:
                self.children.append(Node(event["child_pid"], event["command"]))
                return True
            else:
                added = False
                for child in self.children:
                    added = added or child.add_child(event)
                    if added:
                        break
                return added

        return False


class EventProcessor:

    def __init__(self, events):
        self.events = events
        self.tree = Node(events[0]["pid"], events[0]["command"], alive=True)
        self.time_intervals = []

    def build_tree(self, print_tree=False):
        print_warn("Building tree...")

        for e in self.events:
            self.tree.add_child(e)

        print_info("Tree completed")
        if print_tree:
            pt = PrettyPrintTree(lambda x: x.children, lambda x: f"{x.command}\n({x.pid})",
                                 orientation=PrettyPrintTree.Horizontal, trim_symbol=' ' + Back.GREEN)
            print_info("Event Process tree:\n")
            pt(self.tree)
            print("\n")

    def compute_intervals(self, print_intervals=False):
        print_warn("Computing timestamp intervals...")
        for event in self.events:
            if event["event"] == "fork":
                self.tree.set_alive(event["child_pid"])
            elif event["event"] == "exit":
                self.tree.set_dead(event["pid"])
            elif event["event"] == "exit_group":
                self.tree.set_dead(event["parent_pid"])

            alive_processes = self.tree.compute_alive()
            if len(self.time_intervals) == 0:
                self.time_intervals.append(
                    {"time": event["timestamp"], "alive": alive_processes, "graph": "*" * alive_processes})
            elif alive_processes != int(self.time_intervals[-1]["alive"]):
                self.time_intervals.append(
                    {"time": event["timestamp"], "alive": alive_processes, "graph": "*" * alive_processes})
        print_info("Computed timestamp intervals")
        if print_intervals:
            print(tabulate(self.time_intervals, headers="keys"))

    def _plot_uniform(self, title):
        x = [i for i in range(0, len(self.time_intervals))]
        y = [item["alive"] for item in self.time_intervals]
        plt.figure(figsize=(15, 10))
        plt.plot(x, y, marker='o')
        plt.xticks(ticks=x, labels=[item["time"] for item in self.time_intervals])
        plt.xlabel("Time (nanoseconds from beginning of execution)")
        plt.ylabel("Alive process")
        plt.title(title)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("graph_uniformed.png")
        print_info("Saved uniformed graph")

    def _plot_real(self, title):
        x = [item["time"] for item in self.time_intervals]
        y = [item["alive"] for item in self.time_intervals]
        plt.figure(figsize=(15, 10))
        plt.plot(x, y, marker='o')
        plt.xticks(ticks=x, labels=x)
        plt.xlabel("Time (nanoseconds from beginning of execution)")
        plt.ylabel("Alive process")
        plt.title(title)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("graph_real.png")
        print_info("Saved real timestamp graph")

    def store_to_csv(self, filename="raw_data.csv"):
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['time', 'alive'])  # Optional header
            x = [item["time"] for item in self.time_intervals]
            y = [item["alive"] for item in self.time_intervals]
            for time_val, alive_val in zip(x, y):
                writer.writerow([time_val, alive_val])

    def plot(self, title="Alive process over time"):
        self._plot_uniform(f"{title} - uniformed intervals")
        self._plot_real(f"{title} - real intervals")
