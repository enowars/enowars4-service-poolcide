#!/bin/sh 

while :
do
	echo "Placing flag $FLAG"
	# wget http://poolcide:9001
	./checker.py run putflag -f "$FLAG" -a poolcide -x 100000
	sleep 2m
	./checker.py run putnoise -f "$FLAG" -a poolcide -x 100000
	sleep 2m
done
