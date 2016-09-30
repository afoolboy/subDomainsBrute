#!/bin/bash

if [ $# -eq 0 ]; then
	# echo "please write the filename"
	# exit 0
	fname="subnames"
else
	fname=$1	
fi


file="$fname.txt"
filebak="$fname.txt.bak"

if [ ! -f $file ]; then
	echo "$file not exist"
	exit 0
fi


if [ ! -f $filebak ]; then
	echo "$filebak not exist"
	exit 0
fi



mv $file "$file.old"
mv $filebak $file

echo "[+] Good Job"