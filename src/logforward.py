#!/usr/bin/env python3

# Notes
# Running as service
# https://oxylabs.io/blog/python-script-service-guide
# List files and directories, TO-DO, currently using find command
# https://realpython.com/get-all-files-in-directory-python/
# Exit errors:
# 1 - Required parameter is missing
# 2 - Authentication error (Token)

# Requirements
import sys
import subprocess
import argparse
import requests
from pathlib import Path
# Disabling warning: /usr/lib/python3/dist-packages/urllib3/connectionpool.py:1100: InsecureRequestWarning: 
# Unverified HTTPS request is being made to host '10.1.1.3'. Adding certificate verification is strongly advised.
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Variables
token = None
username = "admin"
password = "admin"
manager = "https://localhost:55000"
file_list = list()
#Script directory
script_dir = Path(__file__).resolve().parent

# Functions and additional processing
## File tasks
def findFiles(directory=sys.argv[-1]):
    files_in_dir = subprocess.run(['find', directory , '-type', 'f'], stdout=subprocess.PIPE)
    files = files_in_dir.stdout.decode('utf-8').splitlines()
    for item in files:
        file_list.append(item)

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
    apiAuthenticate(manager,username,password)
    for file in file_list:
        processFile(file)
## API tasks
def apiAuthenticate(auth_manager,auth_username, auth_password):
    auth_endpoint = auth_manager + "/security/user/authenticate?raw=true"
    print("Starting authentication process")
    # api-endpoint
    auth_request = requests.get(auth_endpoint, auth=(auth_username, auth_password), verify=False)
    token = auth_request.content.decode("utf-8")
    if "Unauthorized" in token:
        print("Authentication error")
        exit(2)

# Read parameters using argparse
## Initialize parser
parser = argparse.ArgumentParser()
## Adding optional argument
parser.add_argument("-d", "--directory", help = "Log directory (Required)", action="store")
parser.add_argument("-u", "--username", help = "Username (Required)", action="store", default="admin")
parser.add_argument("-p", "--password", help = "Password", action="store", default="admin")
parser.add_argument("-m", "--manager", help = "Wazuh Manager Url (Required)", action="store", default="https://localhost:55000")
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
if args.username != "admin":
    print("Setting username")
    username = str(args.username)
else:
    print("Username not set, using: %s" % username)
if args.password != "admin":
    print("Setting password")
    password = str(args.password)
else:
    print("Password not set, using default value")
if args.manager != "https://localhost:55000":
    print("Setting url")
    manager = str(args.manager)
else:
    print("URl not set, using: https://localhost:55000")

## Set the output log
if args.output:
    print("Logging to: % s" % args.output)

# Main program
#findFiles(sys.argv[-1])
processDirectory(args.directory)
exit(0)
