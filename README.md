# TMT: Thread Monitoring Tool

**TMT** is a lightweight **C++ tool** that leverages **eBPF** to trace and analyze how many threads a target application creates and uses during its execution.

It captures scheduling and process events directly from the kernel and exports structured data for post-processing and visualization.

---

### Build

Make sure you have:
- Linux kernel with eBPF support
- `clang`
- `libbpf` development files
- `make`

To build:

    make clean && make all

This will produce the `tmt` binary.

---

### Usage

To monitor an application with **TMT**, run:

    sudo bin/tmt_logger --cmd "<command to trace>" [--print-raw]

#### Examples

    sudo bin/tmt_logger --cmd "sleep 1"
    sudo bin/tmt_logger --cmd "python3 thread_test.py" --print-raw

#### Options
- `--cmd "<program>"` — command to execute and trace (required)
- `--print-raw` — print raw kernel events as they are received

---

### Output

By default, TMT will generate several files under the `out/` directory:

- **out/alive_series.csv** — timeline of active threads per process
- **out/oncpu_slices.csv** — CPU scheduling slices
- **Top runtime per CPU** summary printed on screen

---

### Acknowledgements

TMT was originally developed by [**Stefano Monaldi**](https://www.linkedin.com/in/stefano-monaldi-0a9553296/)  
and is now maintained by [**Marco Edoardo Santimaria**](https://alpha.di.unito.it/marco-santimaria/) and  
[**Robert Birke**](https://alpha.di.unito.it/robert-rene-maria-birke/).
