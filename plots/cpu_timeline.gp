# ============================================================
# CPU Load Heatmap - High Aggregation & Deep Merge
# ============================================================

if (ARGC < 2) {
    print "Usage: gnuplot -c cpu_timeline.gp <data.csv> <output.png>"
    exit
}

input_file = ARG1
output_file = ARG2

set datafile separator ","
set terminal pdfcairo size 12cm,4cm enhanced font "Verdana,10"
set output output_file

# --- AGGREGAZIONE AGGRESSIVA ---
# Aumentando bin_width, unisci più dati nello stesso rettangolo.
# 0.1s è ottimo per "pulire" grafici con troppi micro-eventi.
bin_width = 0.1
to_s(x) = x / 1e9
bin(x) = bin_width * floor(to_s(x)/bin_width)

# Palette Azzurro -> Rosso
set palette defined (0 "#ADD8E6", 1 "#FF0000")
set cbrange [0:1]
set cblabel "CPU Load"

set title "CPU Load Heatmap" font ",14,Bold"
set xlabel "Time (s)"
set ylabel "CPU"

# Detect max CPU id from data (skip header)
stats input_file skip 1 using ($2) nooutput
maxcpu = int(STATS_max)
if (maxcpu < 0) maxcpu = 0

set yrange [-0.5:maxcpu+0.5]
set ytics 1
set format y "CPU %g"

# Style: noborder rimuove i distacchi verticali tra i blocchi
set style fill solid 1.0 noborder

# --- LOGICA DI PLOT ---
# Aggiungiamo un piccolo delta alla coordinata xhigh per forzare i rettangoli
# a "mordere" quello successivo, eliminando le micro-linee bianche.
# ------------------------------------------------------------

plot \
    for [c=0:maxcpu] c with lines lc rgb "#EEEEEE" lw 2 notitle, \
    for [c=0:maxcpu] input_file skip 1 using \
    ( $2 == c ? bin($5) + bin_width/2.0 : 1/0 ) : \
    ( c ) : \
    ( bin($5) ) : \
    ( bin($5) + bin_width + (bin_width * 0.005) ) : \
    ( c - 0.2 ) : \
    ( c + 0.2 ) : \
    ( to_s($7) / bin_width ) \
    with boxxyerror lc palette notitle
