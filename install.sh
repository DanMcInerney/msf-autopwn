apt-get update
apt-get install git python-pip
pip2 install pipenv
pipenv install --two
pipenv shell
echo '[*] Run the following commands:'
echo '      git clone https://github.com/DanMcInerney/msfrpc'
echo '      cd msfrpc && python2 setup install && cd ..'
echo '[*] Run metasploit in a new terminal using the included rc file:'
echo '      sudo msfconsole -r msfrpc.rc'
echo '[*] Run script:'
echo '      ./msf-autopwn -l targets.txt'
