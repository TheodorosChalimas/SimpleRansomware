#!/usr/bin/env bash

dir=$1


LD_PRELOAD=./logger.so ./test_aclog -c $2

for file in "$dir"/*
do
     echo "$file"
     LD_PRELOAD=./logger.so ./test_aclog -e "$file.encrypt"
     openssl enc -aes-256-ecb -pbkdf2 -in "$file" -out "$file.encrypt" -k 1234
     rm "$file"
done
echo files encrypted and original files removed
exit
