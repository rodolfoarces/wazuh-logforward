#!/usr/bin/env python3

# Notes
# Running as service
# https://oxylabs.io/blog/python-script-service-guide
# List files and directories, TO-DO, currently using find command
# https://realpython.com/get-all-files-in-directory-python/

# Requirements
import sys
import subprocess
from pathlib import Path

# Variables
file_list = list()
# Log directory
log_dir = Path(sys.argv[1]).resolve()
#Script directory
script_dir = Path(__file__).resolve().parent

# Functions and additional processing
def findFiles(directory=sys.argv[-1]):
    files_in_dir = subprocess.run(['find', directory , '-type', 'f'], stdout=subprocess.PIPE)
    files = files_in_dir.stdout.decode('utf-8').splitlines()
    for item in files:
        file_list.append(item)

    # print(file_list)

# Main program
findFiles(sys.argv[-1])
quit()
