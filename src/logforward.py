#!/usr/bin/env python3

# Notes
# Running as service
# https://oxylabs.io/blog/python-script-service-guide
# List files and directories, TO-DO, currently using find command
# https://realpython.com/get-all-files-in-directory-python/
# Exit errors:
# 1 - Required parameter is missing
# 2 - Authentication error (Token)
# 3 - Error opening a file

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
username = "wazuh"
password = "wazuh"
manager = "https://localhost:55000"
local_cli = False
file_list = list()
#Script directory
script_dir = Path(__file__).resolve().parent

# Functions and additional processing
## File tasks
def findFiles(directory=sys.argv[-1]):
    if Path(directory).is_dir():
        print("%s is a directory, searching for files" % directory)
        # TO-DO using python rather than local tool to find files
        files_in_dir = subprocess.run(['find', directory , '-type', 'f'], stdout=subprocess.PIPE)
        files = files_in_dir.stdout.decode('utf-8').splitlines()
        for item in files:
            file_list.append(item)
    else:
        if Path(directory).is_file():
            print ("%s is a file" % directory)
            file_list.append(directory)

def processFile(file, auth_manager=None, token=None):
    test_token = None
    print("Processing file: %s" % file)
    if file.lower().endswith(('.zip', '.gz')):
        print("%s is a compressed file" % file)
    else:
        try: 
            file_stream = open(file, 'r')
            # Strips the newline character
        except IOError:
            print ("Error opening file")
            exit(3)
        for line in file_stream:
            # API processing
            if token != None and auth_manager != None:
                msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
                if test_token == None:
                    msg_data = { "token": "", "log_format": "syslog", "location": str(file), "event": json.dumps(line.split()) }
                else:
                    msg_data = { "token": test_token, "log_format": "syslog", "location": str(file), "event": json.dumps(line.split()) }
                msg_url = auth_manager + "/logtest?wait_for_complete=true" 
                log_request = requests.put(msg_url, json=msg_data, headers=msg_headers, verify=False)
                r = json.loads(log_request.content.decode('utf-8'))
                try:
                    test_token = r["data"]["token"]
                    print("Using test session token: %s" % test_token)
                except KeyError:
                    test_token == None
                print (json.dumps(r))
            # Local processing
            else:
               #TO-DO validate if binary exists, might not be present
               r = subprocess.run('/var/ossec/bin/wazuh-logtest', shell=True, stdout=subprocess.PIPE, input=line.encode('utf-8'))
               result = r.stdout.decode('utf-8')
        # Delete testing session after finishing with file
        if test_token != None:
            session_header = msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
            session_url = auth_manager + "logtest/sessions/" + test_token
            session_request = requests.delete(session_url, headers=session_header)
            if session_request.status_code != 200:
                print("There was an error closing the session")
        

## API tasks
def apiAuthenticate(auth_manager,auth_username, auth_password):
    auth_endpoint = auth_manager + "/security/user/authenticate"
    print("Starting authentication process")
    # api-endpoint
    auth_request = requests.get(auth_endpoint, auth=(auth_username, auth_password), verify=False)
    r = auth_request.content.decode("utf-8")
    auth_response = json.loads(r)
    try:
        return auth_response["data"]["token"]
    except KeyError:
        # "title": "Unauthorized", "detail": "Invalid credentials"
        if auth_response["title"] == "Unauthorized":
            print("Authentication error")
            return None

# Read parameters using argparse
## Initialize parser
parser = argparse.ArgumentParser()
## Adding optional argument
parser.add_argument("-f", "--forward", help = "Use remote API send logs, requires: -d DIR|FILE, -u USERNAME, -p PASSWORD, -m MANAGER", action="store_true")
parser.add_argument("-t", "--test", help = "Test logs against decoders and rules, requires -l (local) or -r (remote)", action="store_true")
parser.add_argument("-l", "--local", help = "Use local CLI tools to test logs, it is run on a Wazuh Manager node, requires -d DIR", action="store_true")
parser.add_argument("-r", "--remote", help = "Use remote API tools to test logs, requires: -d DIR|FILE, -u USERNAME, -p PASSWORD, -m MANAGER", action="store_true")
parser.add_argument("-d", "--directory", help = "Log directory|file (Required)", action="store")
parser.add_argument("-u", "--username", help = "Username, required for remote API", action="store", default="wazuh")
parser.add_argument("-p", "--password", help = "Password, required for remote API", action="store", default="wazuh")
parser.add_argument("-m", "--manager", help = "Wazuh Manager Url, required for remote API", action="store", default="https://localhost:55000")
parser.add_argument("-o", "--output", help = "Log output to file")
## Read arguments from command line
args = parser.parse_args()
## Set the log directory to process
## The minimal infomation is a directory to process with the local testing
if len([False for arg in vars(args) if vars(args)[arg]]) == 0:
    print("At least one parameter ( -d DIR | --directory DIR ) is needed") 
    parser.print_help()
    exit(1)
elif args.directory and args.directory != None :
    print("Processing directory: %s" % args.directory)
    print("Starting local CLI testing")
    findFiles(args.directory)
    for file in file_list:
        processFile(file)
else:
    print("Directory option is required, use -d | --directory")
    exit(1)

## Set the output log
if args.output:
    print("Logging to: % s" % args.output)

# Main program
# Validate if local run or API call
if args.local == True:
    print("Starting local CLI testing, ignoring -r, -f")
    findFiles(args.directory)
    for file in file_list:
        processFile(file)
elif args.remote == True:
    print("Starting remote testing, ignoring -f")
    # Authentication for remote connection
    ## Setting Parameters
    if args.username != "wazuh":
        print("Setting username")
        username = str(args.username)
    else:
        print("Username not set, using: %s" % username)
    if args.password != "wazuh":
        print("Setting password")
        password = str(args.password)
    else:
        print("Password not set, using default value")
    ## Setting Manager URL
    if args.manager != "https://localhost:55000":
        print("Setting url")
        manager = str(args.manager)
    else:
        print("URL not set, using: https://localhost:55000")
    
    # File processing
    findFiles(args.directory)
    print("Found %d files" % len(file_list))

    if token == None:
        token = apiAuthenticate(args.manager,args.username, args.password)
        if token == None:
            exit(2)
        else:
            print("Token available")
            for file in file_list:
                processFile(file, args.manager, token)
else:
    print("Something else was wrong")
    exit(3)

exit(0)
