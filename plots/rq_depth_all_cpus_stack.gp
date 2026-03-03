# ============================================================
# High-Density RQ_DEPTH Area Plot (Professional Thesis Style)
# ============================================================

if (ARGC < 2) {
    print "Usage: gnuplot -c rq_depth_all_cpus.gp <oncpu_slices.csv> <output.png>"
    exit
}

input_file  = ARG1
output_file = ARG2

set terminal pngcairo size 1200, 1000 enhanced font "Verdana,10"
set output output_file
set datafile separator ","

unset key

# Stile: Riempimento solido con un po' di trasparenza
set style fill solid 0.6 border

set multiplot layout 4, 1 title "Distribuzione Carico Runqueue (RQ Depth)"

# Palette colori coerente
colors = "#CC0000 #00AA00 #0000CC #CCAA00"

do for [c=0:3] {
    set ylabel sprintf("CPU %d", c)
    set yrange [0:*]
    set grid xtics ytics lc rgb "#eeeeee"
    
    # 'with impulses' disegna una linea verticale per ogni dato
    # È perfetto per 500k righe perché satura l'area visiva correttamente
    plot input_file using ($5/1e9):($2==c ? $4 : NaN) \
         with impulses lc rgb word(colors, c+1)
}

unset multiplot