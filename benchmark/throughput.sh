#! /bin/sh

cut -f3 tcpr-raw-send.dat | ./analyze.5c "Raw" > send.dat
cut -f3 tcpr-pass-send.dat | ./analyze.5c "Passthrough" >> send.dat
cut -f3 tcpr-nocheck-send.dat | ./analyze.5c "Uncheckpointed" >> send.dat
cut -f3 tcpr-send.dat | ./analyze.5c "TCPR" >> send.dat

cut -f3 tcpr-raw-receive.dat | ./analyze.5c "Raw" > receive.dat
cut -f3 tcpr-pass-receive.dat | ./analyze.5c "Passthrough" >> receive.dat
cut -f3 tcpr-nocheck-receive.dat | ./analyze.5c "Uncheckpointed" >> receive.dat
cut -f3 tcpr-receive.dat | ./analyze.5c "TCPR" >> receive.dat

gnuplot <<EOF
set terminal postscript eps monochrome "Times-Roman" size 3,2
set output "throughput.eps"
set datafile separator ","
set style data histogram
set style histogram errorbars gap 1
set bars large
set boxwidth 0.5 relative
set xtics scale 0
set xtics rotate by -30
#set yrange [0:]
set ylabel "Mbit / s"
plot "send.dat" using 2:3:xtic(1) title "Send", \
     "receive.dat" using 2:3:xtic(1) title "Receive"
EOF

epstopdf throughput.eps
