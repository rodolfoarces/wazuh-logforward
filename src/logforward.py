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
import logging
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
def findFiles(path=script_dir):
    if Path(path).is_dir():
        logger.debug("%s is a directory, searching for files" % path)
        for f in Path(path).iterdir():
            if f.is_file():
                file_list.append(f)
            elif f.is_dir():
                findFiles(f)
    elif Path(path).is_file():
        file_list.append(path)

def processFileLocal(file):
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
            logger.debug("push line to file")
        
def processFileRemote(file, token=None):
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
            logger.debug("push line to file")
            # API processing
            msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
            msg_data = { "token": test_token, "log_format": "syslog", "location": str(file), "event": json.dumps(line.split()) }
            msg_url = manager + "/logtest?wait_for_complete=true" 
            forward_request = requests.put(msg_url, json=msg_data, headers=msg_headers, verify=False)
            r = json.loads(forward_request.content.decode('utf-8'))
            if forward_request.status_code != 200:
                    logger.error("There was an error closing the session")
        
def apiAuthenticate(auth_manager,auth_username, auth_password):
    auth_endpoint = auth_manager + "/security/user/authenticate"
    logger.debug("Starting authentication process")
    # api-endpoint
    auth_request = requests.get(auth_endpoint, auth=(auth_username, auth_password), verify=False)
    r = auth_request.content.decode("utf-8")
    auth_response = json.loads(r)
    try:
        return auth_response["data"]["token"]
    except KeyError:
        # "title": "Unauthorized", "detail": "Invalid credentials"
        if auth_response["title"] == "Unauthorized":
            logger.error("Authentication error")
            return None

# Read parameters using argparse
## Initialize parser
parser = argparse.ArgumentParser()
## Adding optional argument
parser.add_argument("-f", "--forward", help = "Use remote API send logs, requires: -d DIR|FILE, -u USERNAME, -p PASSWORD, -m MANAGER", action="store_true")
parser.add_argument("-l", "--local", help = "Use local CLI tools to test logs, it is run on a Wazuh Manager node, requires -d DIR", action="store_true")
parser.add_argument("-d", "--directory", help = "Log directory|file (Required)", action="store")
parser.add_argument("-u", "--username", help = "Username, required for remote API", action="store", default="wazuh")
parser.add_argument("-p", "--password", help = "Password, required for remote API", action="store", default="wazuh")
parser.add_argument("-m", "--manager", help = "Wazuh Manager Url, required for remote API", action="store", default="https://localhost:55000")
parser.add_argument("-o", "--output", help = "Log output to file")
parser.add_argument("-D", "--debug", help = "Enable debug", action="store_true")
## Read arguments from command line
args = parser.parse_args()

## Log to file or stdout
# https://docs.python.org/3/howto/logging-cookbook.html#logging-cookbook
# create file handler which logs even debug messages
logger = logging.getLogger("testlog")
if args.debug:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
# If file is set, everything goes there
if args.output:
    # create console handler with a higher log level
    fh = logging.FileHandler(args.output)
    # Define log level
    if args.debug == True:
        fh.setLevel(logging.DEBUG)
        fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        fh.setLevel(logging.INFO)
        fh_formatter = logging.Formatter('%(message)s')
    
    fh.setFormatter(fh_formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
else:
    # create console handler with a higher log level
    fh = logging.StreamHandler()
    # Define log level
    if args.debug == True:
        fh.setLevel(logging.DEBUG)
        fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        fh.setLevel(logging.INFO)
        fh_formatter = logging.Formatter('%(message)s')
    
    fh.setFormatter(fh_formatter)
    # add the handlers to the logger
    logger.addHandler(fh)


## Set the log directory to process
## The minimal infomation is a directory to process with the local testing
if len([False for arg in vars(args) if vars(args)[arg]]) == 0:
    print("At least one parameter ( -d DIR | --directory DIR ) is needed") 
    parser.print_help()
    exit(1)
elif args.directory and args.directory != None :
    logger.debug("Processing directory or file: %s" % args.directory)
    findFiles(args.directory)
    # Validating if local testing using CLI
    if args.local == True:
        logger.debug("Starting local CLI testing")
        for file in file_list:
            processFileLocal(file)
    elif args.remote == True:
        logger.debug("Starting remote testing")
        # Authentication for remote connection
        ## Setting Parameters
        if args.username != "wazuh":
            logger.debug("Setting username")
            username = str(args.username)
        else:
            logger.debug("Username not set, using: %s" % username)
        if args.password != "wazuh":
            logger.debug("Setting password")
            password = str(args.password)
        else:
            logger.debug("Password not set, using default value")
        ## Setting Manager URL
        if args.manager != "https://localhost:55000":
            logger.debug("Setting url")
            manager = str(args.manager)
        else:
            logger.debug("URL not set, using: https://localhost:55000")
        # Set token
        token = apiAuthenticate(manager, username, password)
        if token != None:
            # Processing
            for file in file_list:
                processFileRemote(file, token)
    exit(0)
else:
    logger.error("Directory option is required, use -d | --directory")
    exit(1)