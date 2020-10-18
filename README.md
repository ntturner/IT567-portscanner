# IT567-portscanner

This port scanner is for assignment 3 in IT 567.

Python 3 is required. The `scapy` library is also a dependency:

```
pip3 install scapy
```

Run the program with this command, substituting in the IP address or range to scan:

```
python3 portscan.py xxx.xxx.xxx.xxx
```

Acceptable formats for IP address entry: 
1. 192.168.1.1 (Single IP address)
2. 192.168.1.0/24 (CIDR notation)
3. 192.168.1-2.1-124 (Range of IP addresses)

For the second and third formats, IP addresses are generated automatically.

Available switches are --ports (-p), --portRange (-pR), and --UDP.

```
--ports: Provide a single port or multiple ports to scan, in this format: 80 81 82. Defaults to port 22.
--portRange: Give a range of ports in this format: 10-25. Can be used in conjunction with the --ports flag.
--UDP: Will scan ports for UDP in addition to TCP (default to TCP only).
```

The following command uses all flags mentioned as well as an IP range. It will conduct both TCP and UDP scans for all hosts with IP addresses between 192.168.1.30 and 192.168.1.50 on ports 1 to 125 and 443:

```
python3 portscan.py 192.168.1.30-50 -p 443 -pR 1-125 --UDP
```
