# ============================================================
# Threads & CPU Activity - Multi-Color Palette Version
# ============================================================

if (ARGC < 3) {
    print "Usage: gnuplot -c threads_over_time.gp <oncpu.csv> <alive.csv> <output.png>"
    exit
}

oncpu_file = ARG1
alive_file = ARG2
outfile    = ARG3

set datafile separator ","
set terminal pdfcairo size 16cm,8cm enhanced font "Verdana,10"
set output outfile

# --- ANALISI DATI PER RANGE ---
stats alive_file using ($1/1e9) nooutput
tmin = STATS_min
tmax = STATS_max
if (tmax <= tmin) tmax = tmin + 1.0

stats oncpu_file skip 1 using ($2) nooutput
maxcpu = int(STATS_max)
if (maxcpu < 0) maxcpu = 0

# --- CONFIGURAZIONE BINNING ---
nbins     = 80.0  # Aumentato un po' per unire meglio i dati in base alla densità
binwidth  = (tmax - tmin)/nbins
bin(x)    = tmin + binwidth * floor((x - tmin)/binwidth) + binwidth/2.0

# --- CONFIGURAZIONE MULTIPLOT ---
set multiplot layout 2,1 title "{/:Bold Existing vs Scheduling Activity Over Time}" \
    margins 0.08,0.85,0.12,0.92 spacing 0.05

# 1. TOP PANEL: Alive Threads
set xrange [tmin:tmax]
set xlabel ""
set xtics format ""
set ylabel "Alive threads"
set grid lc rgb "#DDDDDD"
set key top left

plot alive_file using ($1/1e9):2 \
    with steps lw 3 lc rgb "#FF9900" title "Existing (alive)"

# 2. BOTTOM PANEL: Scheduling Activity (Palette per CPU)
set xrange [tmin:tmax]
set xlabel "Time (s)"
set xtics format "%g"
set ylabel "Scheduling events"
set grid lc rgb "#DDDDDD"

# Definizione Palette Discreta (Colori distinti per CPU)
# Questa palette assegna colori netti invece di sfumature
set palette defined ( \
    0 "#1f77b4", \
    1 "#ff7f0e", \
    2 "#2ca02c", \
    3 "#d62728", \
    4 "#9467bd", \
    5 "#8c564b", \
    6 "#e377c2", \
    7 "#7f7f7f" )
set cbrange [0:maxcpu > 0 ? maxcpu : 1]
unset colorbox

set style fill solid 0.7 noborder # 'noborder' per unire meglio i blocchi vicini
set boxwidth binwidth * 0.9      # Un pizzico di spazio tra i bin per chiarezza

set key outside right center font ",9"

# Plot con ciclo per CPU usando colori della palette
plot for [c=0:maxcpu] \
    oncpu_file skip 1 using (bin($5/1e9)):(($2==c)?1:1/0) smooth freq \
    with boxes lc palette cb c title sprintf("CPU %d", c)

unset multiplot
