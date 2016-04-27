from scapy.all import *
from scapy.layers.inet import *
from Policy import Policy

class ICMPHandler(object):

    def __init__(self,nv):
        self.nodes = []
        self.networkview = nv
        print("ICMP handler started...")


    def createICMPResponse(self, pkt):
        if pkt[0][ICMP].type==8:
            hw_src = pkt[0][Ether].src
            hw_dst = pkt[0][Ether].dst
            ip_src = pkt[0][IP].src
            ip_dst = pkt[0][IP].dst
            icmp = pkt[0]
            icmp[ICMP].type = 0
            icmp[ICMP].code = 0
            icmp[IP].src = ip_dst
            icmp[IP].dst = ip_src
            icmp[Ether].src = hw_dst
            icmp[Ether].dst = hw_src
            print("Send icmp response to " + str(ip_src))
            return icmp





