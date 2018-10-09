#!/usr/bin/python
from scapy.all import *;
import os;

def packetSniffer(packet):
	print packet.show()
	output = packet.summary()
	wrpcap("output.pcap", packet, append=True)
        dirpath = os.getcwd()
        file = open(dirpath+"/"+"output.txt","a+")
        file.write(output)
	file.write("\n")

def main():
        dirpath = os.getcwd()
        filecheck_1 = os.path.isfile(dirpath+"/"+"output.txt")
        if filecheck_1 == True:
                os.remove(dirpath+"/"+"output.txt")

        filecheck_2 = os.path.isfile(dirpath+"/"+"output.pcap")
        if filecheck_2 == True:
                os.remove(dirpath+"/"+"output.pcap")

	ip = raw_input("Enter the IP address to sniff the traffic for: ")
	format = "host"+" "+ip 
	sniff(filter=format, prn=packetSniffer)
if __name__ == '__main__':
	main()

