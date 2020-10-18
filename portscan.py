from scapy.all import *
import argparse
import re
import ipaddress
import itertools

def is_tcp_port_open(host, port):
    srcport=RandShort()
    pkt = sr1(IP(dst=host)/TCP(sport=srcport, dport=port, flags="S"), verbose=False, timeout=1)
    if pkt != None:
        if pkt.haslayer(TCP):
            pktflags = pkt.getlayer(TCP).flags
            if pktflags == 'SA':
                return True
            else:
                return False
        else:
            return False
    else:
        return False

def is_udp_port_open(host, port):
    pkt = sr1(IP(dst=host)/UDP(sport=port, dport=port), verbose=False, timeout=1)
    if pkt != None:
        if pkt.haslayer(ICMP):
            return False
        elif pkt.haslayer(UDP):
            return True
        else:
            return False
    else:
        # If no response, assume the port is open.
        return True

def scanner(host, ports, udp=False):
    tcp_total = 0
    udp_total = 0

    for port in ports:
        print('\nScanning port ' + str(port) + '. . . .')
        if is_tcp_port_open(host, port):
            print('TCP port ' + str(port) + ' open.')
            tcp_total += 1
        if udp is True:
            if is_udp_port_open(host, port):
                print('UDP port ' + str(port) + ' open.')
                udp_total += 1

    print('\nTCP ports open: ' + str(tcp_total))
    if udp is True:
        print('UDP ports open: ' + str(udp_total))

def PortRange(string):
    m = re.match(r'(\d+)(?:-(\d+))?$', string)

    if not m:
        raise Exception("'" + string + "' is not a range of number. Expected forms like '1-125'.")
    start = int(m.group(1))
    end = int(m.group(2))
    if start is None or end is None:
        raise Exception("'" + string + "' is not a range of number. Expected forms like '1-125'.")

    # Swap start and end if they are backwards.
    if start > end:
        temp = end
        end = start
        start = temp
    
    if start < 1 or end > 65535:
        raise Exception("'" + string + "' is outside the bounds of port scanning.")

    return list(range(start, end + 1))

def ip_range(hosts):
    octets = hosts.split('.')
    parsed_ranges = [octet.split('-') for octet in octets]
    ranges = [range(int(r[0]), int(r[1]) + 1) if len(r) == 2 else r for r in parsed_ranges]
    hosts = []
    for address in itertools.product(*ranges):
        hosts.append('.'.join(map(str, address)))
    return hosts

parser = argparse.ArgumentParser(description='Run a port scan on the IP range.')
parser.add_argument('hosts', help='IP addresses for scanning.')
parser.add_argument('-p', '--ports', help='Ports for scanning. Default: 22', type=int, nargs='+', default=[22])
parser.add_argument('-pR', '--portRange', help='Optional range for port scan. Must supply two integers in this format: 1-125',type=PortRange)
parser.add_argument('--UDP', action='store_true', help='Include this flag in order to run a UDP scan.')

args = parser.parse_args()

hosts = []
# Specify single IP, range of IPs, or CIDR notation.
if '/' in args.hosts:
    hosts = [str(x) for x in ipaddress.ip_network(args.hosts).hosts()]
elif '-' in args.hosts:
    hosts = ip_range(args.hosts)
else:
    hosts = [args.hosts]

for host in hosts:
    # Check if host is live using ICMP.
    pkt = sr1(IP(dst=host)/ICMP(), verbose=False, timeout=1)

    if pkt != None:
        ports = []
        if args.portRange is not None:
            ports = args.ports + list(set(args.portRange) - set(args.ports))
            ports.sort()
        else:
            ports = args.ports
        
        print('\n*********** Scanning host ' + host + ' ***********')
        scanner(host, ports, args.UDP)
    else:
        print(str(host) + ' is not reachable.')
