# logforward.py
Forward logs to Wazuh Manager

# logtest.py
Test logs with decoders and rules

Local mode (-l | --local) can only be executed on a Wazuh Server (uses wazuh-logtest binary)

```
usage: logtest.py [-h] [-l] [-r] [-d DIRECTORY] [-u USERNAME] [-p PASSWORD] [-m MANAGER] [-o OUTPUT] [-D]

options:
  -h, --help            show this help message and exit
  -l, --local           Use local CLI tools to test logs, it is run on a Wazuh Manager node, requires -d DIR
  -r, --remote          Use remote API tools to test logs, requires: -d DIR|FILE, -u USERNAME, -p PASSWORD, -m MANAGER
  -d DIRECTORY, --directory DIRECTORY
                        Log directory|file (Required)
  -u USERNAME, --username USERNAME
                        Username, required for remote API
  -p PASSWORD, --password PASSWORD
                        Password, required for remote API
  -m MANAGER, --manager MANAGER
                        Wazuh Manager Url, required for remote API
  -o OUTPUT, --output OUTPUT
                        Log output to file
  -D, --debug           Enable debug
```
