# Python Port Scanner

This repository contains a multi-threaded python port scanning script. The script can scan both TCP and UDP ports. The UDP scanning and ping scanning portions of the script use [Scapy](http://www.secdev.org/projects/scapy/) features, while the TCP scanning is done through python sockets. 

## Usage

___Please note:___ Running this script may require elevated privileges. If running the script doesn't work the first time, try running it with administrator permission or with sudo/root privileges.

The commandline syntax for the script is:

python port_scanner.py |options and flags| hosts(s) port(s)

For example, the command

python port_scanner.py 192.168.0.0 1024

would scan tcp port 1024 of 192.168.0.0, because the script defaults to scanning tcp.

___Please note:___ Scanning UDP ports takes much longer than scanning TCP ports. So, don't get impatient if you give the scanner a large list of UDP ports to scan. Just let the program finish.

### Flags

The following three port protocol flags are designed to be used along. In other words, the -t and -u flags should not be used at the same time.
-t The TCP flag. If included, the port scanner will scan TCP ports. (TCP scanning is the default if no -t, -u, or -tu flags are given)

-u The UDP flag. If included, the port scanner will scan UDP ports.

-tu - The TCP/UDP flag. If included, the port scanner will scan TCP and UDP ports.

-thc The thread count flag. Used to specify the maximum number of threads to use while scanning Usage: 

### Host Syntax

Hosts can be given by themselves, as a list, or as a range.

- Alone: python port_scanner.py 192.168.0.0 1024
- List: python port_scanner.py 192.168.0.0,192.168.0.55,192.168.0.110 1024
- Range: python port_scanner.py 192.168.0.0-255 1024

### Port Syntax

Ports can be given by themselves, as a list, or as a range.

- Alone: python port_scanner.py 192.168.0.0 1024
- List: python port_scanner.py 192.168.0.0 1024,1025,1026,1027
- Range: python port_scanner.py 192.168.0.0 1024-2024
