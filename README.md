msf-autopwn
------
Performs or reads an Nmap scan then automatically exploits machines that contain some of the most common vulnerabilities.

#### Installation
This install is only tested on Kali. Clone into the repo, enter the cloned folder and run install.sh. Open a new terminal and start metasploit with the included rc file. Back in the original terminal continue by entering the newly-created virtual environment with pipenv. Finally, enter the included msfrpc/ folder and install it now that you're inside the virtual environment.

```
git clone https://github.com/DanMcInerney/msf-autopwn
cd msf-autopwn
./install.sh
In a new terminal: msfconsole -r msfrpc.rc
pipenv shell
cd msfrpc && python2 setup install && cd ..
```

#### Usage
```./msf-autopwn.py -t targets.txt```

Run and parse Nmap on all newline-separated IPs or CIDR ranges (e.g.192.168.1.0/24) in the targets.txt file

```./msf-autopwn.py -x autopwn-scan.xml -u user1 -p P@ssw0rd```

Parse an Nmap XML file and connect to the msfrpc server using the username user1 and the password P@ssw0rd

```./msf-autpwn.py -n nessus_file.nessus```

Parse Nessus file for vulnerabilities with Metasploit modules and run them.

#### Details
Runs an Nmap scan ```nmap -sS -O -T4 -sV -n --max-retries 5 --script smb-vuln-ms17-010,smb-vuln-ms08-067 -oA autopwn-scan``` then parses the output for vulnerable machines. The vulnerabilities it currently looks for are MS17-010 (EternalSynergy/Romance if possible, EternalBlue if not) and MS08-067. Prints the live Metasploit output. Any sessions gained will be accessible via the msfconsole terminal you started before running msf-autopwn. The modules chosen are only the most commonly seen based on group experience. If you wish to suggest other modules that you've commonly seen on internal networks I welcome you to open an issue.

Working modules:
* exploit/windows/smb/ms08_067_netapi
* exploit/windows/smb/ms17_010_psexec
* exploit/windows/smb/ms17_010_eternalblue
* exploit/multi/http/struts_dmi_rest_exec

Future additional modules:
* Jenkins
  * Find with nmap service output
  * exploit/linux/misc/jenkins_java_deserialize

* Websphere
  * Find with nmap service output
  * exploit/windows/misc/ibm_websphere_java_deserialize

* Tomcat
  * Find with nmap service output
  * exploit/multi/http/tomcat_jsp_upload_bypass
  * exploit/multi/http/tomcat_mgr_deploy
  * exploit/multi/http/tomcat_mgr_upload

* JBoss
  * Find with nmap service output
  * exploit/multi/http/jboss_bshdeployer
  * exploit/multi/http/jboss_invoke_deploy

* Struts
  * Find with nmap service output
  * exploit/multi/http/struts2_content_type_ognl
  * exploit/multi/http/struts2_rest_xstream
