from subprocess import check_call

cmd = 'sudo apt-get install default-jre; sudo apt-get install python-pip; sudo pip install python-owasp-zap-v2; cd python-nmap-0.1.4; sudo python setup.py install'
check_call(cmd, shell=True)
