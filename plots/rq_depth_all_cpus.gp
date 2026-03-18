# ============================================================
# CPU Load Heatmap - Pixel-Perfect Tracks
# ============================================================

if (ARGC < 2) {
    print "Usage: gnuplot -c heatmap_rq.gp <oncpu_slices.csv> <output.png>"
    exit
}

input_file  = ARG1
output_file = ARG2

set terminal pdfcairo size 12cm,4cm enhanced font "Verdana,10"
set output output_file
set datafile separator ","

# --- Palette Professionale ---
set palette defined (0 "#ADD8E6", 1 "#FF0000")
set cblabel "CPU Load"
set cbrange [0:*]

set title "CPU Load Heatmap (Based on RQ Depth)"
set xlabel "Time (s)"
set ylabel "CPU"
set yrange [-0.6:3.6] # Leggermente più ampio per non tagliare i bordi
set ytics ("CPU 0" 0, "CPU 1" 1, "CPU 2" 2, "CPU 3" 3)
set grid xtics lc rgb "#eeeeee"

time_scale = 1000000000.0
# Spessore fisso matematico
thickness = 0.25 

# --- BINARI FISSI ---
# Disegniamo i binari azzurri con precisione assoluta
do for [i=0:3] {
    set object (i+10) rectangle from graph 0, first (i-thickness) \
                          to graph 1, first (i+thickness) \
                          behind fillcolor rgb "#ADD8E6" fillstyle solid 1.0 noborder
}

# --- PLOT DATI ---
# Usiamo 'nooutliers' implicito e forziamo le coordinate Y 
# per evitare variazioni di altezza dovute all'arrotondamento dei pixel
plot input_file using ($5/time_scale):2:($5/time_scale):($6/time_scale):\
     (column(2)-thickness):(column(2)+thickness):4 \
     with boxxyerror lc palette notitle
