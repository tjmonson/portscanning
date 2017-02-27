import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
import time
import threading
import socket
from threading import Thread

# NOTE: You may need privileged access to run this script! So, if it doesn't work the first
# time, try running it with administrator privileges or with sudo or root priviliges.c

# Parses a file of hosts. Hosts in files should be listed as IP addresses, with
# each on a line of their own.
def read_hosts(file_name):
    f = open(file_name)
    lines = f.readlines()
    hosts = []
    for line in lines:
        hosts.append(line)
        f.close()
        return hosts

# Parses hosts given on the command line.
# Hosts can be listed as a range (192.168.0.0-255)
# or as a list (192.168.0.0,192.168.0.1,...)
# or just one host (192.168.0.1)
def parse_hosts(hosts_line):
    if "," in hosts_line:
        return hosts_line.split(",")
    elif "-" in hosts_line:
        hosts = []
        range_nums = hosts_line.split(".")[-1].split("-")
        base = ""
        for i in range(0,3):
            base += hosts_line.split(".")[i]
            base += "."
        for i in range(int(range_nums[0]), int(range_nums[1]) + 1):
            hosts.append(base + str(i))
        return hosts
    else:
        return [hosts_line]

# Parses ports given on the command line.
# Hosts can be listed as a range (100-200)
# or as a list (101,102,...)
# or just one host (53)
def parse_ports(ports_line):
    if "," in ports_line:
        ports = []
        lines = ports_line.split(",")
        for line in lines:
            ports.append(int(line))
    elif "-" in ports_line:
        ports = []
        range_nums = ports_line.split("-")
        for i in range(int(range_nums[0]), int(range_nums[1]) + 1):
            ports.append(i)
        return ports
    else:
        return [int(ports_line)]

# Do a ping discoerby of a list of hosts using scapy and return the hosts
# that are up.
def ping_discovery(hosts):
    #Discover if hosts are up before port scanning
    hosts_up = []
    for host in hosts:
        ip = IP(dst=host) # send ICMPs with scapy here
        ping = ICMP()
        resp = sr1(ip/ping,timeout=1,verbose=0)
        if resp != None:
            print "%s is up and will be scanned" % host
            hosts_up.append(host)
    return hosts_up #trimmed list of hosts

# A class that represents a host scanner thread. This class has funcationality for
# scanning tcp and udp ports.
class HostScannerThread(Thread):
    def __init__(self, host, scan_tcp, scan_udp, ports, pool):
        self.sTitle = None
        self.host = host
        self.scan_tcp = scan_tcp
        self.scan_udp = scan_udp
        self.ports = ports
        self.open_tcp = []
        self.open_udp = []
        self.pool = pool
        super(HostScannerThread, self).__init__()

    def run(self):
        if self.scan_tcp:
            self.open_tcp = self.scan_tcp_ports(self.host, self.ports)
        if self.scan_udp:
            self.open_udp = self.scan_udp_ports(self.host, self.ports)
        self.pool.thread_done(self)

    def print_results(self):
        if self.scan_tcp:
            print "\n%d TCP port scan results for %s:" % (len(self.open_tcp), self.host)
            for port in self.open_tcp:
                print "TCP port %d is open" % port
        if self.scan_udp:
            print "\n%d UDP port scan results for %s:" % (len(self.open_udp), self.host)
            for port in self.open_udp:
                print "UDP port %d is open" % port

    def scan_tcp_ports(self, host, ports):
        #Code from http://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python
        #was used to help write this code
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    def scan_udp_ports(self,host, ports):
        #This for loop code was inspired by the Kali Linux Network Scanning Cookbook
        #I'm assume this is okay, since the book is one of our reading materials
        open_ports = []
        for port in ports:
             ip = IP(dst=host)
             udp = UDP(dport=port)
             resp = sr1(ip/udp, timeout=2, verbose=False)
             time.sleep(1)
             if resp == None:
                 #print "UDP port %d is open" % port
                 open_ports.append(port)
        return open_ports

# A class that represents and manages a pool of host scanning threads.
class ScanningThreadPool:

    def __init__(self, hosts, num_threads, scan_tcp, scan_udp, ports):
        self.hosts = hosts
        self.hosts_done = 0
        self.scan_tcp = scan_tcp
        self.scan_udp = scan_udp
        self.ports = ports
        self.num_threads = num_threads
        self.threads = []

    # When a thread is done, print it's results and start a new thread if there
    # are more hosts to scan.
    def thread_done(self, thread):
        thread.print_results()
        if self.hosts_done < len(self.hosts):
            t = HostScannerThread(self.hosts[self.hosts_done], self.scan_tcp, self.scan_udp, self.ports, self)
            self.hosts_done += 1
            self.threads.append(t)
            t.start()

    # Fills the pool full of host scanning threads then waits for all hosts to be
    # scanned and all threads to join.
    def start(self):
        for i in range(0,self.num_threads):
            t = HostScannerThread(self.hosts[self.hosts_done], self.scan_tcp, self.scan_udp, self.ports, self)
            self.hosts_done += 1
            self.threads.append(t)
            t.start()
        j = 0
        while j < len(self.threads):
            self.threads[j].join()
            j += 1

def main():
    # Parse command line arguments
    # The following are some usage examples:
    # python port_scanner.py 192.169.0.0 50
    # python port_scanner.py 192.169.0.0,192.168.0.55 50
    # python port_scanner.py -tu 192.169.0.0-255 50
    # python port_scanner.py -u -thc 5 192.169.0.0-255 50,50,70
    # python port_scanner.py -u -thc 5 192.169.0.0-255 50-6500
    parser = argparse.ArgumentParser(description='Conducts a port scan.')
    parser.add_argument('-t', "--tcp", action="store_true", default=False,
        help="Targets TCP ports.")
    parser.add_argument('-u', "--udp", action="store_true", default=False,
        help="Targets UDP ports.")
    parser.add_argument('-tu', "--tcpandudp", action="store_true", default=False,
        help="Targets TCP and UDP ports.")
    parser.add_argument('-thc', "--threadcount", type=int,default=1,
        help="Indicates the number of threads to use.")
    parser.add_argument('-f', "--hostfile", action="store_true", default=False,
        help="Reads hosts in from a file.")

    parser.add_argument("hosts", action="store", help="The hosts expression. This can be a path to a file (each host should be on its own line), a comma separated list of hosts or a host range (syntax: 192.168.0.0-255)")
    parser.add_argument("ports", action="store", help="The ports expression. This can be a comma separated list of ports (syntax: 1,2,3,4,5) or a port range (syntax: 1024-2024)")
    args = parser.parse_args()

    scan_tcp = True if not args.udp else False
    scan_udp = args.udp

    if args.tcpandudp:
        scan_tcp = True
        scan_udp = True

    #Parse hosts
    hosts = None
    if args.hostfile:
        print "Opening file"
        hosts = read_hosts(args.hosts)
    else:
        hosts = parse_hosts(args.hosts)

    #Parse ports
    ports = parse_ports(args.ports)

    #Out of the total possible hosts, discover those that are alive through pings
    hosts = ping_discovery(hosts)

    #Start a thread pool to manage the threads that will scan the hosts
    if len(hosts) > 0:
        threadpool = ScanningThreadPool(hosts, args.threadcount, scan_tcp, scan_udp, ports)
        threadpool.start()
    else:
        print "None of the hosts are up! No scanning was done."

if __name__ == '__main__':
    main()
