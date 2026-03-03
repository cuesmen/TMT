# ============================================================
# Runnable Depth Timeline per CPU (Binned / Readable)
# Uses oncpu_slices.csv:
#   x = start_ns (col 5)
#   y = rq_depth (col 4)
# ============================================================

if (ARGC < 2) {
    print "Usage: gnuplot -c rq_depth_all_cpus.gp <oncpu_slices.csv> <output.png>"
    exit
}

input_file  = ARG1
output_file = ARG2

set datafile separator ","

# Build a temporary, CPU-sorted numeric stream:
#   col1=cpu, col2=time_s, col3=rq_depth
tmpfile = "/tmp/rq_depth_plot.dat"
prep_cmd = sprintf("awk -F, 'NR>1{printf \"%%u %%.9f %%u\\n\", $2, $5/1e9, $4}' '%s' | sort -n -k1,1 -k2,2 > '%s'", input_file, tmpfile)
system(prep_cmd)

# Detect CPU range and rq_depth range
stats input_file skip 1 using 2 nooutput
cpu_min = int(STATS_min)
cpu_max = int(STATS_max)
if (cpu_max < cpu_min) {
    cpu_min = 0
    cpu_max = 0
}

stats input_file skip 1 using 4 nooutput
rq_max = int(STATS_max)
if (rq_max < 1) rq_max = 1
ymax = int(rq_max * 1.10) + 2

stats input_file skip 1 using ($5/1e9) nooutput
tmin = STATS_min
tmax = STATS_max
if (tmax <= tmin) tmax = tmin + 1.0

# From here we read tmpfile (space-separated).
set datafile separator whitespace

# Time binning for trend readability.
# Coarser bins remove high-frequency scheduler jitter.
target_bins = 30.0
bin_w = (tmax - tmin) / target_bins
if (bin_w < 0.001) bin_w = 0.001
bin(x) = tmin + bin_w * floor((x - tmin) / bin_w) + bin_w/2.0

# Build binned maxima stream:
#   col1=cpu, col2=bin_time_s(center), col3=max_rq_depth_in_bin
tmpbin = "/tmp/rq_depth_plot_binned_max.dat"
prep_bin_cmd = sprintf("awk 'BEGIN{bw=%.12f; t0=%.12f} {cpu=$1; t=$2; rq=$3; b=int((t-t0)/bw); key=cpu\":\"b; if(!(key in mx) || rq>mx[key]) mx[key]=rq} END{for(k in mx){split(k,a,\":\"); cpu=a[1]+0; b=a[2]+0; tc=t0 + bw*b + bw/2.0; printf \"%%d %%.9f %%d\\n\", cpu, tc, mx[k]}}' '%s' | sort -n -k1,1 -k2,2 > '%s'", bin_w, tmin, tmpfile, tmpbin)
system(prep_bin_cmd)

ncpus = cpu_max - cpu_min + 1
img_h = 260 * ncpus
if (img_h < 400) img_h = 400

set terminal pngcairo size 1700,img_h enhanced font "Verdana,10"
set output output_file

set multiplot layout ncpus,1 title "Estimated runnable threads per CPU"

set xrange [tmin:tmax]
set yrange [0:ymax]
set grid lc rgb "#DDDDDD"
set tics out
set key top right
set border lw 1.0

do for [c=cpu_min:cpu_max] {
    set ylabel sprintf("CPU %d", c)
    set xtics format "%g"
    set xlabel "Time (s)"

    plot tmpbin using \
        (($1 == c) ? $2 : 1/0) : \
        (($1 == c) ? $3 : 1/0) \
        with lines lw 2.8 lc rgb "#1f77b4" title sprintf("CPU %d rq_depth (max/bin)", c)
}

unset multiplot
