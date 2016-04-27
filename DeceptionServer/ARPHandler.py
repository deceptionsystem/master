from scapy.all import *
from scapy.layers.inet import *

class ARPHandler(object):

    def __init__(self,nv):
        self.networkview = nv
        self.nodes = []
        self.matching = {}
        self.realMatching = {}
        self.hostHops = {}
        self.refreshMatching()
        self.refreshRealMatching()
        print("ARP handler started...")

    def refreshMatching(self):
        print("Refresh matching...")

        #check hops
        for r in self.networkview.routes:
            hopCt=0
            for hop in r.hops:
                hopCt+=1
            hopCt-=2
            if hopCt>0 :
                self.hostHops[r.endNode.decepted_eth_addr] = hopCt

        self.nodes = self.networkview.access
        for n in self.nodes:
            if self.hostHops.has_key(n.decepted_eth_addr):
                print(str(n.decepted_ip_addr) + " -> " + str(self.networkview.gateway.decepted_eth_addr))
                self.matching[n.decepted_ip_addr] = self.networkview.gateway.decepted_eth_addr
            else:
                print(str(n.decepted_ip_addr) + " -> " + str(n.decepted_eth_addr))
                self.matching[n.decepted_ip_addr] = n.decepted_eth_addr

    def refreshRealMatching(self):
        print("Refresh real matching...")

        self.nodes = self.networkview.access
        for n in self.nodes:
            print(str(n.ip_addr) + " -> " + str(n.eth_addr))
            self.realMatching[n.ip_addr] = n.eth_addr

    def createARPResponse(self, pkt):
        self.refreshMatching()
        if pkt[0].src == self.networkview.target.eth_addr:
            if pkt[0].op == 1: #who-has
                ipAddr = pkt[0].pdst
                if ipAddr in self.matching.keys():
                    ethAddr = self.matching[ipAddr]

                    hw_src = pkt[0].hwsrc
                    ip_dst = pkt[0].pdst
                    ip_src = pkt[0].psrc

                    arp = eval(pkt[0].command())
                    arp[Ether].dst = hw_src
                    arp[Ether].src = ethAddr
                    arp[ARP].hwdst = hw_src
                    arp[ARP].hwsrc = ethAddr
                    arp[ARP].pdst = ip_src
                    arp[ARP].psrc = ip_dst
                    arp[ARP].op = 2
                    print("ARP for " + str(ipAddr) + " -> " + str(ethAddr))
                    return arp
        elif pkt[0].src != self.networkview.target.eth_addr:
            if pkt[0].op == 1: #who-has
                ipAddr = pkt[0].pdst
                if ipAddr in self.realMatching.keys():
                    ethAddr = self.realMatching[ipAddr]

                    hw_src = pkt[0].hwsrc
                    ip_dst = pkt[0].pdst
                    ip_src = pkt[0].psrc

                    arp = eval(pkt[0].command())
                    arp[Ether].dst = hw_src
                    arp[Ether].src = ethAddr
                    arp[ARP].hwdst = hw_src
                    arp[ARP].hwsrc = ethAddr
                    arp[ARP].pdst = ip_src
                    arp[ARP].psrc = ip_dst
                    arp[ARP].op = 2
                    print("ARP for " + str(ipAddr) + " -> " + str(ethAddr))
                    return arp

                if ipAddr in self.matching.keys():
                    ethAddr = self.matching[ipAddr]

                    hw_src = pkt[0].hwsrc
                    ip_dst = pkt[0].pdst
                    ip_src = pkt[0].psrc

                    arp = eval(pkt[0].command())
                    arp[Ether].dst = hw_src
                    arp[Ether].src = ethAddr
                    arp[ARP].hwdst = hw_src
                    arp[ARP].hwsrc = ethAddr
                    arp[ARP].pdst = ip_src
                    arp[ARP].psrc = ip_dst
                    arp[ARP].op = 2
                    print("ARP for " + str(ipAddr) + " -> " + str(ethAddr))
                    return arp



