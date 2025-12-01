# ARG1: oncpu_slices.csv
# ARG2: alive_series.csv
# ARG3: output PNG

if (ARGC < 3) {
    print "Usage: gnuplot -c threads_over_time.gp <oncpu.csv> <alive.csv> <output.png>"
    exit
}

oncpu_file = ARG1
alive_file = ARG2
outfile    = ARG3

set datafile separator ","

# 1600x800
set terminal pngcairo size 1600,800 enhanced
set output outfile

# Global time range (from alive_series), in seconds
stats alive_file using ($1/1e9) nooutput
tmin = STATS_min
tmax = STATS_max
if (tmax <= tmin) tmax = tmin + 1.0

# Binning for scheduling activity
nbins     = 50.0
binwidth  = (tmax - tmin)/nbins
bin(x)    = tmin + binwidth * floor((x - tmin)/binwidth)

# MULTIPLOT: 2 rows, 1 column
# left, right, bottom, top
set multiplot layout 2,1 title "Existing vs Scheduling Activity Over Time" \
    margins 0.06,0.90,0.12,0.96 spacing 0.02,0.00

# TOP PANEL: alive threads (step function)
set xrange [tmin:tmax]
set xlabel ""
set xtics format ""
set ylabel "Alive threads"
set grid
set key top left

plot alive_file using ($1/1e9):2 \
    with steps lw 3 lc rgb "#ff9900" title "Existing (alive)"

# BOTTOM PANEL: per-CPU scheduling activity
set xrange [tmin:tmax]
set xlabel "Time (s)"
set xtics format "%g"
set ylabel "Scheduling events"
set grid

set style data boxes
set style fill solid 0.55 border rgb "black"
set boxwidth binwidth

set key outside right top

# CPU colors
cpu0_color = "#1f77b4"
cpu1_color = "#2ca02c"
cpu2_color = "#ff7f0e"
cpu3_color = "#d62728"

plot \
    oncpu_file using (bin($4/1e9)):(($2==0)?1:1/0) smooth freq with boxes lc rgb cpu0_color title "CPU 0", \
    oncpu_file using (bin($4/1e9)):(($2==1)?1:1/0) smooth freq with boxes lc rgb cpu1_color title "CPU 1", \
    oncpu_file using (bin($4/1e9)):(($2==2)?1:1/0) smooth freq with boxes lc rgb cpu2_color title "CPU 2", \
    oncpu_file using (bin($4/1e9)):(($2==3)?1:1/0) smooth freq with boxes lc rgb cpu3_color title "CPU 3"

unset multiplot
