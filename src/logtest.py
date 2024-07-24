#!/usr/bin/env python3
# Modules
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
#Script directory
script_dir = Path(__file__).resolve().parent

# Functions
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
    logger.debug("Processing file: %s" % file)
    if str(file).lower().endswith(('.zip', '.gz')):
        logger.debug("%s is a compressed file" % file)
    else:
        try: 
            file_stream = open(file, 'r')
            # Strips the newline character
        except IOError:
            logger.error("Error opening file")
            exit(3)
        for line in file_stream:
            try:
                r = Path('/var/ossec/bin/wazuh-logtest').is_file()
            except:
                logger.error("Error accesing Wazuh logtest binary")
                exit(4)

            if Path('/var/ossec/bin/wazuh-logtest').is_file():
                r = subprocess.run('/var/ossec/bin/wazuh-logtest', capture_output=True, check=True, text=True, input=str(line))
                logger.debug(r)
                logger.info(r.stderr)
            else:
                logger.error("Wazuh logtest binary missing")

## API tasks
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

def processFileRemote(file, token=None):
    # Local variables
    logtest_token = None
    # validate if compressed file
    # TO-DO add compressed file management
    logger.debug("Processing %s with remote tools" % file)
    if file.lower().endswith(('.zip', '.gz')):
        logger.debug("%s is a compressed file" % file)
    else:
        try: 
            file_stream = open(file, 'r')
            # Strips the newline character
        except IOError:
            logger.error("Error opening file")
            exit(3)
    for line in file_stream:
        # API processing
        msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
        if logtest_token == None:
            msg_data = { "token": "", "log_format": "syslog", "location": str(file), "event": json.dumps(line.split()) }
        else:
            msg_data = { "token": logtest_token, "log_format": "syslog", "location": str(file), "event": json.dumps(line.split()) }
        
        msg_url = manager + "/logtest?wait_for_complete=true" 
        log_request = requests.put(msg_url, json=msg_data, headers=msg_headers, verify=False)
        r = json.loads(log_request.content.decode('utf-8'))
        try:
            logtest_token = r["data"]["token"]
            logger.debug("Using test session token: %s" % logtest_token)
            logger.info(json.dumps(r))
        except KeyError:
            logtest_token == None
            logger.debug(json.dumps(r))
    
    # Delete testing session after finishing with file
    if logtest_token != None:
        session_header = msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + token}
        session_url = manager + "logtest/sessions/" + logtest_token
        session_request = requests.delete(session_url, headers=session_header)
        if session_request.status_code != 200:
            logger.debug("There was an error closing the session")


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
parser.add_argument("-o", "--output", help = "Log output to file", action="store")
parser.add_argument("-D", "--debug", help = "Enable debug", action="store_true")

## Read arguments from command line
args = parser.parse_args()
## Set the logging element

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
    else:
        fh.setLevel(logging.INFO)
    fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(fh_formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
else:
    # create console handler with a higher log level
    fh = logging.StreamHandler()
    # Define log level
    if args.debug == True:
        fh.setLevel(logging.DEBUG)
    else:
        fh.setLevel(logging.INFO)
    fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(fh_formatter)
    # add the handlers to the logger
    logger.addHandler(fh)

## Set the log directory to process
## The minimal infomation is a directory to process with the local testing        
if len([False for arg in vars(args) if vars(args)[arg]]) == 0:
    logger.error("At least one parameter ( -d DIR | --directory DIR ) is needed") 
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
else:
    logger.error("Directory option is required, use -d | --directory")
    exit(1)


