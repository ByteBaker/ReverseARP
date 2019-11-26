import socket
import os
import platform    # For getting the operating system name
import subprocess  # For executing a shell command
import sys
from re import search, fullmatch
import progressbar

"""
	The idea is to ping all the hosts in the local network.
	From ARP table, match the requested MAC address with those
	that responded to the ping, and return the IP addresses
	that matches the requested MAC address.

"""

MAC_REGEX = '^([A-Fa-f0-9]{2}[:-]){5}([A-Fa-f0-9]{2})$'		# Matches colon or hyphen separated MAC address
CURRENT_OS = platform.system().lower()						# Get the current OS for according action
FNULL = open(os.devnull, 'w')								# NULL pointer to pipe system command output
NETWORK_ADDR = 'x.x.x.x'									# Get the address of the network currently connected to
MY_ADDR = 'x.x.x.x'											# My address in the network, required to skip during ping
LIVE_HOSTS = []												# List of active IP addresses in the network


def ping(host):
    # Returns True if host (str) responds to a ping request.

    # Ping 1 request with 1 byte and TTL = 200 ms for shorter latency in LAN
    if CURRENT_OS == 'windows':
    	command = ['ping', '-n', '1', '-l', '1', '-w', '100', host]
    elif CURRENT_OS == 'linux':
    	command = ['ping', '-c', '1', '-s', '1', '-W', '100', host]
    else:
    	return False
    STATUS = subprocess.call(command, stdout=FNULL, stderr=subprocess.STDOUT) == 0

    return STATUS


def get_net_add():
	global MY_ADDR, NETWORK_ADDR
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8", 80))
		MY_ADDR = s.getsockname()[0]
		s.close()
		NETWORK_ADDR = '.'.join(MY_ADDR.split('.')[:3]) + '.HOST'
	except:
		print("Not connected to any network...")
		exit(1)

def loop_ping(MAC_ADDR, net_addr=NETWORK_ADDR):
	"""
		Pings a network from host 1 to 255 except self.
		Then writes the ARP table to file named ARP_DATA.
	"""
	print("Scanning the hosts in the network...")
	progress = progressbar.ProgressBar(maxval=255, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
	progress.start()
	desired_ip = None

	with open('ARP_DATA', 'w') as OUTFILE:
		subprocess.call('arp -a', stdout=OUTFILE, stderr=subprocess.STDOUT)
	status, desired_ip = search_arp_data(MAC_ADDR)
	if status:
		progress.finish()
		return desired_ip

	for host in range(1,255):
		host_addr = net_addr.replace('HOST', str(host))
		if host_addr != MY_ADDR:
			if ping(host_addr):
				LIVE_HOSTS.append(host_addr)
				with open('ARP_DATA', 'w') as OUTFILE:
					subprocess.call('arp -a', stdout=OUTFILE, stderr=subprocess.STDOUT)
				status, desired_ip = search_arp_data(MAC_ADDR)
				if status:
					progress.finish()
					return desired_ip
					break
		progress.update(host + 1)
	progress.finish()

	status, desired_ip = search_arp_data(MAC_ADDR)
	if status:
		progress.finish()
		return desired_ip	
	return desired_ip


def search_arp_data(MAC_ADDR):
	"""
		Searches the whole ARP table for MAC_ADDR and returns its IP address.
	"""
	arp_file_contents = list()
	required_IP = None
	with open('ARP_DATA', 'r') as ARP_DATA:
		arp_file_contents = ARP_DATA.readlines()
	for line in arp_file_contents:
		if search(MAC_ADDR, line):
			required_IP = line.split()[0]
			break

	if required_IP:
		return True, required_IP
	return False, required_IP


def findmac(MAC_ADDR):
	print()
	get_net_add()																# Network and self address retrieved
	target_ip_addr = loop_ping(MAC_ADDR, NETWORK_ADDR)							# All live hosts pinged, ARP table saved to file
	if target_ip_addr:
		print('IP address of ' + MAC_ADDR + ' is ' + target_ip_addr)
	else:
		print(MAC_ADDR + ' not found in network.')
	os.remove('ARP_DATA')


if __name__ == '__main__':
	if len(sys.argv) > 1:
		if fullmatch(MAC_REGEX, sys.argv[1]):
			findmac(sys.argv[1])
		else:
			print('Not a MAC address')
	else:
		print('No host address provided')
