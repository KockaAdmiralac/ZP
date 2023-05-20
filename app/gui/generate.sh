#!/bin/bash

cd $(realpath $(dirname $0))

IFS=$'\n'
for ui_file in $(find . -name "*.ui")
do
    py_file="${ui_file%.ui}.py"
    pyuic6 -o "$py_file" -x "$ui_file"
done
