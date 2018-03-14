apt-get update
apt-get install git python-pip
pip install pipenv
pipenv install --two
echo '[*] Run metasploit in a new terminal using the included rc file:'
echo '      sudo msfconsole -r msfrpc.rc'
echo '[*] Create virtualenv:'
echo '      pipenv shell'
echo '[*] Run the following commands in the virtualenv:'
echo '      git clone https://github.com/DanMcInerney/msfrpc'
echo '      cd msfrpc/python-msfrpc/ && python2 setup install && cd ../..'
echo '[*] Run script:'
echo '      ./msf-autopwn -l targets.txt'
