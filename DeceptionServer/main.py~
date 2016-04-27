from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.layers.dns import *
from ARPHandler import ARPHandler
from ICMPHandler import ICMPHandler
from RouteHandler import RouteHandler
from DHCPHandler import DHCPHandler
from DNSHandler import DNSHandler
from PolicyStorage import PolicyStorage
from Policy import Policy
from ViewReader import ViewReader
from NetworkView import NetworkView
#icmp = Ether()/IP()/ICMP()

#viewfile = raw_input("Enter the path to your view file (e.g. /home/mininet/nv.nv):")

with open("/home/mininet/config.conf") as file:
    lines = file.readlines()
print("Loaded path from config file " + lines[0])
viewfile = lines[0].replace("\n", "")

viewReader = ViewReader()
networkview = viewReader.readNetworkView(viewfile)


arpHandler = ARPHandler(networkview)
icmpHandler = ICMPHandler(networkview)
routeHandler = RouteHandler(networkview)
dhcpHandler = DHCPHandler(networkview)
dnsHandler = DNSHandler()



def readPkts(pkt):
    #print(pkt.show())
    if pkt[0].haslayer(ARP):
        arp = arpHandler.createARPResponse(pkt)
        sendp(arp, inter=0.001, verbose=0)
    elif pkt[0].haslayer(UDP) and pkt[0][IP][UDP].dport==53:
        print("DNS packet received... ")
        respPkt = dnsHandler.handleDNSPacket(pkt)
        sendp(respPkt, inter=0.001, verbose=0)
    elif pkt[0].haslayer(IP) and pkt[0][IP].ttl<25:
        print("Send traceroute response...")
        respPkt = routeHandler.createRouteResponse(pkt)
        sendp(respPkt, inter=0.001, verbose=0)
    elif pkt[0].haslayer(DHCP):
        print("DHCP packet received... ")
        dhcpPkt = dhcpHandler.handleDHCP(pkt)
        sendp(dhcpPkt, inter=0.001, verbose=0)

sniff(prn=readPkts)