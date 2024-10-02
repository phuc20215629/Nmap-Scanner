#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<-------------------------------------------------->")

# Input target IP or range
ip_addrs = input("Please enter the IP address(es) you want to scan: ")
ip_list = ip_addrs.split()
print("The IP you entered is: ", ip_list)

response = input(""" \nPlease enter the type of scan you want to run: 
                       1) SYN ACK Scan
                       2) UDP Scan
                       3) Comprehensive Scan
Input: """)
print("You have selected option: ", response)
print("\nNmap Version: ", scanner.nmap_version())

for ip_addr in ip_list:
    if response == '1':
        scanner.scan(ip_addr, '1-1024', '-v --open -sS')
        print("\nScan results for", ip_addr, "using SYN ACK Scan:")
        for host in scanner.all_hosts():
            print("Host:", host, "(", scanner[host].hostname(), ")")
            print("State:", scanner[host].state())
            for proto in scanner[host].all_protocols():
                print("Protocol:", proto)
                ports = scanner[host][proto].keys()
                for port in ports:
                    print("Port:", port, "State:", scanner[host][proto][port]['state'])

    elif response == '2':
        scanner.scan(ip_addr, '1-1024', '-v --open -sU')
        print("\nScan results for", ip_addr, "using UDP Scan:")
        for host in scanner.all_hosts():
            print("Host:", host, "(", scanner[host].hostname(), ")")
            print("State:", scanner[host].state())
            for proto in scanner[host].all_protocols():
                print("Protocol:", proto)
                ports = scanner[host][proto].keys()
                for port in ports:
                    print("Port:", port, "State:", scanner[host][proto][port]['state'])

    elif response == '3':
        scanner.scan(ip_addr, '1-1024', '-v -sS -sU -sV -sC -A -O -T4')
        print("\nScan results for", ip_addr, "using Comprehensive Scan:")
        for host in scanner.all_hosts():
            print("Host:", host, "(", scanner[host].hostname(), ")")
            print("State:", scanner[host].state())
            for proto in scanner[host].all_protocols():
                print("Protocol:", proto)
                ports = scanner[host][proto].keys()
                for port in ports:
                    print("Port:", port, "State:", scanner[host][proto][port]['state'])

    else:
        print("Invalid option. Please choose 1, 2, or 3.")