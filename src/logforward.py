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
import json
from pathlib import Path
# Disabling warning: /usr/lib/python3/dist-packages/urllib3/connectionpool.py:1100: InsecureRequestWarning: 
# Unverified HTTPS request is being made to host '10.1.1.3'. Adding certificate verification is strongly advised.
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Variables
token = None
username = "admin"
password = "admin"
manager = "https://localhost:55000"
local_cli = False
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

def processFile(file, auth_manager=None, token=None):
    print("Processing file: %s" % file)
    if file.lower().endswith(('.zip', '.gz')):
        print("%s is a compressed file" % file)
    else:
        try: 
            file_stream = open(file, 'r')
            # Strips the newline character
            for line in file_stream:
                #count += 1
                # print("Line{}: {}".format(count, line.strip()))
                if token != None and auth_manager != None:
                   msg = { "token": token, "log_format": "syslog", "location": str(file), "event": line.strip() }
                   url = auth_manager + "/logtest" 
                   log_request = requests.put(url, msg)
                   r = log_request.content.decode('utf-8')
                   print (r)
        except IOError:
            print ("Error: File does not appear to exist.")
            exit(3)

## API tasks
def apiAuthenticate(auth_manager,auth_username, auth_password, tries):
    auth_endpoint = auth_manager + "/security/user/authenticate"
    print("Starting authentication process")
    auth_error = False
    # api-endpoint
    count = 0
    if auth_error == False:
        auth_request = requests.get(auth_endpoint, auth=(auth_username, auth_password), verify=False)
        r = auth_request.content.decode("utf-8")
        auth_response = json.loads(r)
        try:
            return auth_response["data"]["token"]
        except KeyError:
            # "title": "Unauthorized", "detail": "Invalid credentials"
            if auth_response["title"] == "Unauthorized":
                print("Authentication error")
                auth_error = True
                return None

# Read parameters using argparse
## Initialize parser
parser = argparse.ArgumentParser()
## Adding optional argument
parser.add_argument("-d", "--directory", help = "Log directory (Required)", action="store")
parser.add_argument("-u", "--username", help = "Username (Required)", action="store", default="admin")
parser.add_argument("-p", "--password", help = "Password", action="store", default="admin")
parser.add_argument("-m", "--manager", help = "Wazuh Manager Url (Required)", action="store", default="https://localhost:55000")
parser.add_argument("-t", "--tries", help = "Number of connection tries", action="store", default=3)
parser.add_argument("-l", "--local", help = "Use local CLI tools to test logs", action="store_true")
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
# Validate if local run or API call
if args.local == True:
    print("Starting local CLI testing")
    findFiles(args.directory)
else:
    print("Starting remote testing")
    # Authentication for remote connection
    ## Setting Parameters
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
    ## Setting Manager URL
    if args.manager != "https://localhost:55000":
        print("Setting url")
        manager = str(args.manager)
    else:
        print("URl not set, using: https://localhost:55000")
    
    # File processing
    findFiles(args.directory)
    print("Found %d files" % len(file_list))

    if token == None:
        token = apiAuthenticate(args.manager,args.username, args.password, args.tries)
        if token == None:
            exit(2)
        else:
            print("Token available")
            for file in file_list:
                processFile(file, args.manager, token)
        

        #for file in file_list:
        #    processFile(file)


exit(0)
