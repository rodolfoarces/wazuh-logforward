#!/usr/bin/env python3
# Modules
import sys
import subprocess
import argparse
import requests
import json
from pathlib import Path
# Disabling warning: /usr/lib/python3/dist-packages/urllib3/connectionpool.py:1100: InsecureRequestWarning: 
# Unverified HTTPS request is being made to host '10.1.1.3'. Adding certificate verification is strongly advised.
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
# Exit errors:
# 1 - Required parameter is missing
# 2 - Authentication error (Token)
# 3 - Error opening file
# 4 - Wazuh logtest binary missing


# Variables
token = None
username = "wazuh"
password = "wazuh"
manager = "https://localhost:55000"
local_cli = False
file_list = list()
logtest_token = None
#Script directory
script_dir = Path(__file__).resolve().parent

# Functions
def findFiles(path=script_dir):
    if Path(path).is_dir():
        print("%s is a directory, searching for files" % path)
        for f in Path(path).iterdir():
            if f.is_file():
                file_list.append(f)
            elif f.is_dir():
                findFiles(f)
    elif Path(path).is_file():
        file_list.append(path)

def processFileLocal(file):
    print("Processing file: %s" % file)
    if str(file).lower().endswith(('.zip', '.gz')):
        print("%s is a compressed file" % file)
    else:
        try: 
            file_stream = open(file, 'r')
            # Strips the newline character
        except IOError:
            print ("Error opening file")
            exit(3)
        for line in file_stream:
            processLineLocal(line.split())

def processLineLocal(line):
    try:
        r = Path('/var/ossec/bin/wazuh-logtest').is_file()
    except PermissionError:
        print("Error accesing Wazuh logtest binary")
        exit(4)

    if Path('/var/ossec/bin/wazuh-logtest').is_file():
        r = subprocess.run('/var/ossec/bin/wazuh-logtest', shell=True, stdout=subprocess.PIPE, input=line.encode('utf-8'))
        result = r.stdout.decode('utf-8')
    else:
        print("Wazuh logtest binary missing")

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

def processFileRemote(file, token=None):
    print("Processing %s with remote tools" % file)
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
        processLineRemote(file, line, token, logtest_token)


def processLineRemote(file, line, token=None, session=None):
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
    if session == None:
        msg_data = { "token": "", "log_format": "syslog", "location": str(file), "event": json.dumps(line.split()) }
    else:
        msg_data = { "token": session, "log_format": "syslog", "location": str(file), "event": json.dumps(line.split()) }
    
    msg_url = manager + "/logtest?wait_for_complete=true" 
    log_request = requests.put(msg_url, json=msg_data, headers=msg_headers, verify=False)
    r = json.loads(log_request.content.decode('utf-8'))
    try:
        logtest_token = r["data"]["token"]
        print("Using test session token: %s" % logtest_token)
    except KeyError:
        logtest_token == None
        print (json.dumps(r))


# Read parameters using argparse
## Initialize parser
parser = argparse.ArgumentParser()
## Adding optional argument
parser.add_argument("-l", "--local", help = "Use local CLI tools to test logs, it is run on a Wazuh Manager node, requires -d DIR", action="store_true")
parser.add_argument("-r", "--remote", help = "Use remote API tools to test logs, requires: -d DIR|FILE, -u USERNAME, -p PASSWORD, -m MANAGER", action="store_true")
parser.add_argument("-d", "--directory", help = "Log directory|file (Required)", action="store")
parser.add_argument("-u", "--username", help = "Username, required for remote API", action="store", default="wazuh")
parser.add_argument("-p", "--password", help = "Password, required for remote API", action="store", default="wazuh")
parser.add_argument("-m", "--manager", help = "Wazuh Manager Url, required for remote API", action="store", default="https://localhost:55000")
#parser.add_argument("-o", "--output", help = "Log output to file")
## Read arguments from command line
args = parser.parse_args()
## Set the log directory to process
## The minimal infomation is a directory to process with the local testing        
if len([False for arg in vars(args) if vars(args)[arg]]) == 0:
    print("At least one parameter ( -d DIR | --directory DIR ) is needed") 
    parser.print_help()
    exit(1)
elif args.directory and args.directory != None :
    print("Processing directory or file: %s" % args.directory)
    findFiles(args.directory)
    # Validating if local testing using CLI
    if args.local == True:
        print("Starting local CLI testing")
        for file in file_list:
            processFileLocal(file)
    elif args.remote == True:
        print("Starting remote testing")
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
        # Set token
        token = apiAuthenticate(manager, username, password)
        if token != None:
            # Processing
            for file in file_list:
                processFileRemote(file, token)
else:
    print("Directory option is required, use -d | --directory")
    exit(1)


