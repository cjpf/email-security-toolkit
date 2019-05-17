#!/bin/bash
[[ $# -ne 1 ]] && echo "No Address Provided - Exiting" && exit 1

pattern="^((1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})\.){3}(1\d{2}|2[0-4]\d|25[0-5]|\d{1,2})$"

echo "Testing $1"
if [[ -n `echo "${1}" | grep -Poi $pattern` ]]; then
    echo Pass
else
    echo Fail
fi
