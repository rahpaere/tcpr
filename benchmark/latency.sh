#! /bin/sh

cut -f3 tcpr-raw-latency.dat | ./analyze.5c "Raw" > latency.dat
cut -f3 tcpr-pass-latency.dat | ./analyze.5c "Passthrough" >> latency.dat
cut -f3 tcpr-nocheck-latency.dat | ./analyze.5c "Uncheckpointed" >> latency.dat
cut -f3 tcpr-latency.dat | ./analyze.5c "TCPR" >> latency.dat

gnuplot <<EOF
set terminal postscript eps monochrome "Times-Roman" size 3,2
set output "latency.eps"
set datafile separator ","
set style data histogram
set style histogram errorbars gap 1
set bars large
set boxwidth 0.5 relative
set xtics scale 0
set xtics rotate by -30
set yrange [0:]
set ylabel "Seconds"
unset key
plot "latency.dat" using 2:3:xtic(1)
EOF

epstopdf latency.eps
