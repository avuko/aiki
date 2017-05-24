#!/usr/bin/gnuplot
reset
set terminal png
set terminal png size 1300,600
set xtics rotate by 90
set xtics offset 0,-5,0
set bmargin 10
set datafile separator ","
set xdata time
set timefmt "%Y/%m/%d"
set format x "%Y/%m/%d"
set xlabel "Date"
set xlabel offset 0,-5,0


set ylabel "Activities (Log 10)"
set logscale y 10
set yrange [1:7000]

set title "number of attempts per day"
set key reverse Left outside
set grid

set style data linespoints

plot "jar.dat.csv" using 1:2 title "109.201.152.246", \
"" using 1:3 title "109.201.154.170", \
"" using 1:4 title "109.201.154.205", \
"" using 1:5 title "178.162.199.142", \
"" using 1:6 title "178.162.211.216", \
"" using 1:7 title "185.100.85.132", \
"" using 1:8 title "31.168.172.147", \
"" using 1:9 title "46.166.190.223", \
"" using 1:10 title "5.153.233.58", \
"" using 1:11 title "60.12.119.222", \
"" using 1:12 title "92.240.253.181"
#
