#!/usr/bin/env python3

# Notes
# Running as service
# https://oxylabs.io/blog/python-script-service-guide
# List files and directories, TO-DO, currently using find command
# https://realpython.com/get-all-files-in-directory-python/

# Requirements
import sys
import subprocess
import argparse
from pathlib import Path

# Variables
file_list = list()
# Log directory
#log_dir = Path(sys.argv[1]).resolve()
#Script directory
script_dir = Path(__file__).resolve().parent

# Functions and additional processing
def printHelp():
    msg = "Usage:\n logforwarder [OPTIONS] DIR"
    print(msg)
    quit()

def findFiles(directory=sys.argv[-1]):
    files_in_dir = subprocess.run(['find', directory , '-type', 'f'], stdout=subprocess.PIPE)
    files = files_in_dir.stdout.decode('utf-8').splitlines()
    for item in files:
        file_list.append(item)

    # print(file_list)

# Read parameters using argparse

# Initialize parser
parser = argparse.ArgumentParser()

# Adding optional argument
parser.add_argument("-d", "--directory", help = "Log directory", action="store")
parser.add_argument("-o", "--output", help = "Log output to file")

# Read arguments from command line
args = parser.parse_args()

#Set the output log
try:
    if args.output:
        print("Logging to: % s" % args.output)
except AttributeError:
    print("Logging to stout")

#Set the output log
try:
    if args.directory:
        print("Processing: % s" % args.directory)
except AttributeError:
    print("Directory option is required, use -d | --directory")
    quit()

# Main program
#findFiles(sys.argv[-1])
quit()
