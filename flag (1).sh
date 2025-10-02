#!/bin/bash
input=$1
if [[ $flag == $input ]]
then
    echo "This is the flag"
else
    echo "no"
fi