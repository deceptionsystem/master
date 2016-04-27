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

#with open("/home/stefan/config.conf") as file:
#    lines = file.readlines()
#print("Loaded path from config file " + lines[0])
#viewfile = lines[0].replace("\n", "")

nvFile = str(raw_input("Enter view file:\n"))
viewfile = nvFile
print("Loaded network view from: " + viewfile)
viewReader = ViewReader()
networkview = viewReader.readNetworkView(viewfile)


arpHandler = ARPHandler(networkview)
icmpHandler = ICMPHandler(networkview)
routeHandler = RouteHandler(networkview)
dhcpHandler = DHCPHandler(networkview)
dnsHandler = DNSHandler()

seenPkts=[]

def readPkts(pkt):
    #print(pkt.show())
    if pkt[0] not in seenPkts:
        if pkt[0].haslayer(ARP):
            arp = arpHandler.createARPResponse(pkt)
            seenPkts.append(arp)
            sendp(arp, inter=0.001, verbose=0)
        if pkt[0].haslayer(UDP) and pkt[0][UDP].dport==53:
            print("DNS packet received... ")
            respPkt = dnsHandler.handleDNSPacket(pkt)
            seenPkts.append(respPkt)
            sendp(respPkt, inter=0.001, verbose=0)
        if pkt[0].haslayer(ICMP):
            if pkt[0][ICMP].type==3 and pkt[0][ICMP].code==3:
                #print("Received ICMP dest unreachable")
                #pkt.show2()
                outPkt = routeHandler.adjustNesetedPacket(pkt)
                seenPkts.append(outPkt)
                sendp(outPkt, inter=0.001, verbose=0)
        if pkt[0].haslayer(IP) and pkt[0][IP].ttl<25:
            print("Send traceroute response...")
            respPkt = routeHandler.createRouteResponse(pkt)
            seenPkts.append(respPkt)
            sendp(respPkt, inter=0.001, verbose=0)
        if pkt[0].haslayer(DHCP):
            print("DHCP packet received... ")
            dhcpPkt = dhcpHandler.handleDHCP(pkt)
            if dhcpPkt!=None:
                seenPkts.append(dhcpPkt)
                sendp(dhcpPkt, inter=0.001, verbose=0)

sniff(prn=readPkts)
