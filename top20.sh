#!/bin/sh

xmllint --format dump.xml | grep "<url>\|<dns>" | sed -s 's/^.*<url>https\:\/\///' | sed -s 's/^.*<url>http\:\/\///' | sed -s 's/^.*<url>//'| sed -s 's/^.*<dns>//' | sed -s 's/[ \t]*//' | sed -s 's/\/.*$//' | sed -s 's/<$//' | sort | uniq -c | sort -k 1 -n -r | head -n 20

