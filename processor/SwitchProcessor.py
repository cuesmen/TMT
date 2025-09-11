import csv
import matplotlib.pyplot as plt

class SwitchProcessor:
    def __init__(self, events):
        # keep only run/desched
        self.events = [e for e in events if e.get("event") in ("run", "desched")]
        self.open = {}
        self.slices = []

    def build_slices(self):
        print(f"[SwitchProcessor] Processing {len(self.events)} events")

        for e in self.events:
            print(f"[SwitchProcessor] Event: {e}")  # DEBUG
            pid = e["pid"]
            ts = int(e["timestamp"])

            if e["event"] == "run":
                self.open[pid] = (ts, e.get("cpu"), e.get("command", ""))
            elif e["event"] == "desched":
                if pid in self.open:
                    start, cpu0, cmd0 = self.open.pop(pid)
                    if ts > start:
                        self.slices.append({
                            "pid": pid,
                            "cpu": cpu0,
                            "command": cmd0,
                            "start_ns": start,
                            "end_ns": ts,
                            "delta_ns": ts - start,
                            "reason": e.get("reason")
                        })

        # close remaining open slices
        if self.open:
            end_ts = max(e["timestamp"] for e in self.events)
            for pid, (start, cpu0, cmd0) in self.open.items():
                print(f"[SwitchProcessor] Closing pending slice for pid={pid}")
                self.slices.append({
                    "pid": pid,
                    "cpu": cpu0,
                    "command": cmd0,
                    "start_ns": start,
                    "end_ns": end_ts,
                    "delta_ns": end_ts - start,
                    "reason": "end_of_trace"
                })
            self.open.clear()

        print(f"[SwitchProcessor] Built {len(self.slices)} slices")

    def store_csv(self, filename="oncpu_slices.csv"):
        with open(filename, "w", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=["pid","cpu","command","start_ns","end_ns","delta_ns","reason"]
            )
            w.writeheader()
            for s in self.slices:
                w.writerow(s)
        print(f"[SwitchProcessor] Stored {len(self.slices)} slices into {filename}")

    def plot_top_runtime_per_cpu(
        self,
        top_n=10,
        time_unit="ms",              # "ns" | "us" | "ms" | "s"
        outfile_prefix="top_runtime_cpu_"
    ):
        """
        Build per-CPU toplists of total on-CPU runtime aggregated by (cpu, pid, command)
        and save one horizontal bar chart per CPU.

        - top_n: number of top entries to plot per CPU
        - time_unit: unit for plotting ("ns", "us", "ms", "s")
        - outfile_prefix: output file prefix; files are named like "<prefix><cpu>.png"
        """
        if not self.slices:
            print("[SwitchProcessor] No slices; nothing to plot")
            return

        # --- unit conversion ---
        unit_scale = {"ns": 1.0, "us": 1e3, "ms": 1e6, "s": 1e9}
        if time_unit not in unit_scale:
            raise ValueError("time_unit must be one of: ns, us, ms, s")
        scale = unit_scale[time_unit]

        # --- aggregate total runtime per (cpu, pid, command) ---
        agg = {}  # key=(cpu,pid,command) -> total_delta_ns
        for s in self.slices:
            key = (int(s["cpu"]), int(s["pid"]), str(s["command"]))
            agg[key] = agg.get(key, 0) + int(s["delta_ns"])

        # --- regroup per CPU and pick top-N ---
        per_cpu = {}  # cpu -> list of (label, total_in_unit)
        for (cpu, pid, cmd), tot_ns in agg.items():
            label = f"{cmd}:{pid}"
            per_cpu.setdefault(cpu, []).append((label, tot_ns / scale))

        # --- plot one chart per CPU ---
        import matplotlib.pyplot as plt

        for cpu, items in sorted(per_cpu.items()):
            # sort desc and take top-N
            items.sort(key=lambda x: x[1], reverse=True)
            top = items[:top_n]
            if not top:
                continue

            labels = [lbl for lbl, _ in top]
            values = [val for _, val in top]

            plt.figure(figsize=(12, 6))
            # horizontal bars
            y = range(len(top))
            plt.barh(y, values)
            plt.yticks(y, labels)
            plt.xlabel(f"Total on-CPU time [{time_unit}]")
            plt.ylabel("comm:pid")
            plt.title(f"Top {top_n} runtime by PID/comm on CPU {cpu}")
            plt.gca().invert_yaxis()  # highest on top
            plt.tight_layout()
            out = f"{outfile_prefix}{cpu}.png"
            plt.savefig(out)
            plt.close()
            print(f"[SwitchProcessor] Saved per-CPU toplist to {out}")
