```
████████╗ ███╗   ███╗ ████████╗
╚══██╔══╝ ████╗ ████║ ╚══██╔══╝
   ██║    ██╔████╔██║    ██║   
   ██║    ██║╚██╔╝██║    ██║   
   ██║    ██║ ╚═╝ ██║    ██║   
   ╚═╝    ╚═╝     ╚═╝    ╚═╝   
 T h r e a d   M o n i t o r i n g   T o o l
 ```

# TMT: Thread Monitoring Tool

**TMT** is a lightweight **C++ tool** that leverages **eBPF** to trace and analyze how many threads a target application creates and uses during its execution.

It captures scheduling and process events directly from the kernel and exports structured data for post-processing and visualization.

---

## Build

Make sure you have:

- Linux kernel with eBPF support  
- `clang`
- `libbpf` development files
- `cmake`
- *(optional, for plots)* `gnuplot`

To build the logger:

```bash
cmake -S . -B build
cmake --build build
```

This will produce the `tmt_logger` binary under:

```
build/bin/tmt_logger
```

and all compiled eBPF programs under:

```
build/bin/*.bpf.o
```

---

## Usage

To monitor an application with **TMT**, run:

```bash
sudo build/bin/tmt_logger --cmd "<command to trace>" [--print-raw]
```

### Examples

```bash
sudo build/bin/tmt_logger --cmd "sleep 1"

sudo build/bin/tmt_logger --cmd "python3 thread_test.py" --print-raw
```

### Options

- `--cmd "<program>"` — command to execute and trace (**required**)
- `--print-raw` — print raw kernel events as they are received

---

## Output

By default, TMT will generate several files under the `out/` directory in the project root:

- `out/alive_series.csv` — timeline of active threads per process  
- `out/oncpu_slices.csv` — CPU scheduling slices  

On the terminal, you will also see a **"Top runtime per CPU"** summary.

---

## Plots & Visualization

TMT can generate ready-to-use plots using **gnuplot** (if available).

### Requirements

- `gnuplot` installed and visible in `PATH`
- CMake option `TMT_ENABLE_PLOTS` enabled (ON by default)

If you want to be explicit:

```bash
cmake -S . -B build -DTMT_ENABLE_PLOTS=ON
cmake --build build
```

### Generating plots

After you have run `tmt_logger` at least once (so that `out/alive_series.csv` and `out/oncpu_slices.csv` exist), you can generate the plots via CMake custom targets.

From the build directory:

```bash
cmake --build build --target plot_threads_over_time
```

This will run gnuplot with the script under `plots/threads_over_time.gp` and produce:

- `out/threads_over_time.png` — visual summary of:
  - thread activity over time (alive threads)
  - CPU scheduling slices aggregated over the timeline

To generate **all** available plots:

```bash
cmake --build build --target plots_all
```

If `gnuplot` is not installed, the `plots_all` target will simply print a message reminding you to install it and reconfigure.

---

## Quickstart

1. **Configure & build**

   ```bash
   cmake -S . -B build -DTMT_ENABLE_PLOTS=ON
   cmake --build build
   ```

2. **Run a trace**

   ```bash
   sudo build/bin/tmt_logger --cmd "python3 thread_test.py"
   ```

3. **Generate plots**

   ```bash
   cmake --build build --target plots_all
   ```

   Then open `out/threads_over_time.png` with your favorite image viewer.

---

## Acknowledgements

TMT was originally developed by  
[**Stefano Monaldi**](https://www.linkedin.com/in/stefano-monaldi-0a9553296/)  
and is now maintained by  
[**Marco Edoardo Santimaria**](https://alpha.di.unito.it/marco-santimaria/),  
[**Robert Birke**](https://alpha.di.unito.it/robert-rene-maria-birke/) and  
[**Cosmin Stoica**](https://www.linkedin.com/in/cosmin-stoica-037331296/).
