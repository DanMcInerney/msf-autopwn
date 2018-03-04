#!/usr/bin/env python2

# This fixes the error in pymetasploit
import ssl
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

import os
import sys
import time
import argparse
import netifaces
from IPython import embed
from termcolor import colored
from multiprocessing import Process
from libnmap.process import NmapProcess
from netaddr import IPNetwork, AddrFormatError
from subprocess import Popen, PIPE, CalledProcessError
from metasploit.msfrpc import MsfRpcClient, MsfRpcError
from libnmap.parser import NmapParser, NmapParserException

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-p", "--password", help="Password for msfrpcd")
    return parser.parse_args()

# Colored terminal output
def print_bad(msg):
    print(colored('[-] ', 'red') + msg)

def print_info(msg):
    print(colored('[*] ', 'blue') + msg)

def print_good(msg):
    print(colored('[+] ', 'green') + msg)

def print_great(msg):
    print(colored('[!] {}'.format(msg), 'yellow', attrs=['bold']))

def keep_alive(client):
    '''
    msfrpcd will kill auth tokens after 5m
    '''
    last_check = time.time()
    while True:
        if time.time() - last_check > 100:
            client.consoles.list
        time.sleep(1)

def run_proc(cmd):
    '''
    Runs single commands
    '''
    cmd_split = cmd.split()
    print_info('Running: {}'.format(cmd))
    proc = Popen(cmd_split, stdout=PIPE, stderr=PIPE)

    return proc

def parse_nmap(args):
    '''
    Either performs an Nmap scan or parses an Nmap xml file
    Will either return the parsed report or exit script
    '''
    if args.hostlist:
        hosts = []
        with open(args.hostlist, 'r') as hostlist:
            host_lines = hostlist.readlines()
            for line in host_lines:
                line = line.strip()
                try:
                    if '/' in line:
                        hosts += [str(ip) for ip in IPNetwork(line)]
                    elif '*' in line:
                        print_bad('CIDR notation only in the host list, e.g. 10.0.0.0/24')
                        sys.exit()
                    else:
                        hosts.append(line)
                except (OSError, AddrFormatError):
                    print_bad('Error importing host list file. Are you sure you chose the right file?')
                    sys.exit()

        report = nmap_scan(hosts)

    else:
        print_bad('Specify hostlist with: -l <hostlist.txt>')
        sys.exit()

    return report

def nmap_scan(hosts):
    '''
    Do Nmap scan
    '''
    #nmap_args = '-sS -T4 -sV -n --max-retries 5 -oA autopwn-scan'
    nmap_args = '-sS -T4 -sV -n --max-retries 5 --top-ports 10 -oA autopwn-scan'
    nmap_proc = NmapProcess(targets=hosts, options=nmap_args, safe_mode=False)
    rc = nmap_proc.sudo_run_background()
    nmap_status_printer(nmap_proc)
    report = NmapParser.parse_fromfile(os.getcwd()+'/autopwn-scan.xml')

    return report

def nmap_status_printer(nmap_proc):
    '''
    Prints that Nmap is running
    '''
    i = -1
    x = -.5
    while nmap_proc.is_running():
        i += 1
        # Every 30 seconds print that Nmap is still running
        if i % 30 == 0:
            x += .5
            print_info("Nmap running: {} min".format(str(x)))

        time.sleep(1)

def get_hosts(args, report):
    '''
    Gets list of hosts with port 445 or 3268 (to find the DC) open
    and a list of hosts with smb signing disabled
    '''
    hosts = []

    print_info('Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            ip = host.address
            hosts.append(host)
            print_info('Host up: {}'.format(ip))
            for s in host.services:
                if s.port == 'open':
                    print_info(' {} open'.format(str(s.port)))

    if len(hosts) == 0:
        print_bad('No hosts found')
        sys.exit()

    return hosts

def cleanup(msfrpc_proc):
    msfrpc_proc.kill()

def main(report, args):
    msfrpc_proc = run_proc('msfrpcd -P 1')
    time.sleep(8)
    hosts = get_hosts(args, report)
    client = MsfRpcClient(args.password, port=55553)

    # initialize keep alive process
    p = Process(target=keep_alive, args=(client,))
    p.start()

    # initialize a console
    client.consoles.console()
    client.consoles.list
    con = client.consoles.console('0')
    time.sleep(2)
    con = client.consoles.console('0')
    cleanup(msfrpc_proc)

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root')
        sys.exit()
    report = parse_nmap(args)
    main(report, args)


