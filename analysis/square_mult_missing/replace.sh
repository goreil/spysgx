#!/bin/bash

filename="results.csv"
number=3307

line_count="$(wc -l < "$filename")"
line_nums_to_delete="$(shuf -i "1-$line_count" -n "$number")"
sed_script="$(printf '%dd;' $line_nums_to_delete)"

sed -i.bak -e "$sed_script" "$filename"
