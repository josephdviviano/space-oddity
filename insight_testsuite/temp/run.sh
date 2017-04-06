#!/usr/bin/env bash
# process_log.py runs as a daemon and must be killed by the user

python ./src/process_log.py -vv ./log_input/log.txt ./log_output/

