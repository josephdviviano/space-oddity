#!/usr/bin/env bash
# process_log.py runs as a daemon and must be killed by the user

# for demonstration purposes, removes the logs with each iteration
rm ./log_output/*.txt
# NB: can be run with --debug for lots of fun output :)
python ./src/process_log.py -v ./log_input/log.txt ./log_output/

