#!/usr/bin/env bash
# process_log.py runs as a daemon and must be killed by the user

# -v for debugging information, -vv for lots of debugging information :)
python ./src/process_log.py -v ./log_input/log.txt ./log_output/

