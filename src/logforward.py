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
#Script directory
script_dir = Path(__file__).resolve().parent

# Functions and additional processing
def findFiles(directory=sys.argv[-1]):
    files_in_dir = subprocess.run(['find', directory , '-type', 'f'], stdout=subprocess.PIPE)
    files = files_in_dir.stdout.decode('utf-8').splitlines()
    for item in files:
        file_list.append(item)

    # print(file_list)
def processFile(file):
    print("Processing file: %s" % file)
    if file.lower().endswith(('.zip', '.gz')):
        print("%s is a compressed file" % file)
    else:
        file_stream = open(file, 'r')
        count = 0
        # Strips the newline character
        for line in file_stream:
            count += 1
            print("Line{}: {}".format(count, line.strip()))
            if count >= 10:
                quit()

def processDirectory(directory):
    findFiles(directory)
    for file in file_list:
        processFile(file)
        

# Read parameters using argparse
## Initialize parser
parser = argparse.ArgumentParser()
## Adding optional argument
parser.add_argument("-d", "--directory", help = "Log directory (Required)", action="store")
parser.add_argument("-o", "--output", help = "Log output to file")
## Read arguments from command line
args = parser.parse_args()
## Set the log directory to process
if len([False for arg in vars(args) if vars(args)[arg]]) == 0:
        print("At least one parameter ( -d DIR | --directory DIR ) is needed") 
        parser.print_help()
        exit(1)
if args.directory and args.directory != None:
    print("Processing directory: %s" % args.directory)
else:
    print("Directory option is required, use -d | --directory")
    exit(1)
## Set the output log
if args.output:
    print("Logging to: % s" % args.output)

# Main program
#findFiles(sys.argv[-1])
processDirectory(args.directory)
exit(0)
