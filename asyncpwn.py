#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import sys
import time
import base64
import string
import msfrpc
import signal
import random
import asyncio
import requests
import argparse
import netifaces
from threading import Thread, Lock
from datetime import datetime
from termcolor import colored
from libnmap.process import NmapProcess
from asyncio.subprocess import PIPE, STDOUT
from netaddr import IPNetwork, AddrFormatError
from subprocess import Popen, PIPE, CalledProcessError
from libnmap.parser import NmapParser, NmapParserException
from IPython import embed

CLIENT = msfrpc.Msfrpc({})

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-p", "--password", default='Au70PwN', help="Password for msfrpc")
    parser.add_argument("-u", "--username", default='msf', help="Username for msfrpc")
    parser.add_argument("-x", "--xml", help="Path to Nmap XML file")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Amount of workers to use")
    parser.add_argument('--nmap-opts', default='', help='Additional Nmap options, e.g. --nmap-opts "-sU --max-rtt-timeout=300"')
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

def parse_nmap(args):
    '''
    Either performs an Nmap scan or parses an Nmap xml file
    Will either return the parsed report or exit script
    '''
    if args.xml:
        try:
            report = NmapParser.parse_fromfile(args.xml)
        except FileNotFoundError:
            print_bad('Host file not found: {}'.format(args.xml))
            sys.exit()

    elif args.hostlist:
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
        print_bad('Use the "-x [path/to/nmap-output.xml]" option if you already have an Nmap XML file \
or "-l [hostlist.txt]" option to run an Nmap scan with a hostlist file.')
        sys.exit()

    return report

def nmap_scan(hosts):
    '''
    Do Nmap scan
    '''
    nmap_args = '-sS -n --max-retries 5 -oA asyncpwn-scan {}'.format(args.nmap_opts)
    nmap_proc = NmapProcess(targets=hosts, options=nmap_args, safe_mode=False)
    rc = nmap_proc.sudo_run_background()
    nmap_status_printer(nmap_proc)
    report = NmapParser.parse_fromfile(os.getcwd()+'/asyncpwn-scan.xml')

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

def keep_alive(args, lock):
    '''
    msfrpc will kill auth tokens after 5m
    '''
    global CLIENT

    last_check = time.time()
    while True:
        if time.time() - last_check > 100:
            with lock:
                CLIENT.login(args.username, args.password)
        time.sleep(1)

def get_hosts(args, report):
    '''
    Gets list of hosts with port 445 or 3268 (to find the DC) open
    and a list of hosts with smb signing disabled
    '''
    hosts = []
    DCs = []

    print_info('Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            # Get open services
            for s in host.services:
                if s.port == 445:
                    if s.state == 'open':
                        if host not in hosts:
                            hosts.append(host)
                elif s.port == 3268:
                    if s.state == 'open':
                        if host not in DCs:
                            DCs.append(host)

    if len(hosts) == 0:
        print_bad('No hosts with port 445 open')
        sys.exit()

    return hosts, DCs

def main(report, args):
    global CLIENT

    # Returns a list of Nmap object hosts
    # So you must use host.address, for example, to get the ip
    hosts, DCs = get_hosts(args, report)
    lock = Lock()

    # initialize keep alive process
    # won't attempt first login until 100s from start
    p = Thread(target=keep_alive, args=(args, lock))
    p.setDaemon(True)
    p.start()

    CLIENT.login(args.username, args.password)

    c_ids = [x[b'id'] for x in CLIENT.call('console.list')[b'consoles']]

    print(len(c_ids), args.workers)
    while len(c_ids) > args.workers:
        print('destroying {}'.format(c_ids[-1]))
        CLIENT.call('console.destroy', [c_ids[-1]])
        time.sleep(1)
        c_ids = [x[b'id'] for x in CLIENT.call('console.list')[b'consoles']]

    while len(c_ids) < args.workers:
        print('creating console')
        CLIENT.call('console.create')
        time.sleep(1)
        c_ids = [x[b'id'] for x in CLIENT.call('console.list')[b'consoles']]

    c_ids = [x[b'id'] for x in CLIENT.call('console.list')[b'consoles']]


if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root')
        sys.exit()

    report = parse_nmap(args)
    main(report, args)

