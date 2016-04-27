from scapy.all import *
from scapy.layers.inet import *

class RouteHandler(object):

    def __init__(self,nv):
        self.networkview = nv

    def createRouteResponse(self, pkt):
        src_eth = pkt[0][Ether].src
        dst_eth = pkt[0][Ether].dst
        src_ip = pkt[0][IP].src
        dst_ip = pkt[0][IP].dst
        cur_ttl = pkt[0][IP].ttl

        route = self.networkview.getRouteToIP(dst_ip)

        hop=0
        if route != None:
            for h in route.hops:
                print("Checking hop " + str(hop) + " to " + str(h.decepted_ip_addr) + " cur ttl=" + str(cur_ttl))
                hop_ip = h.decepted_ip_addr
                hop_eth = h.decepted_eth_addr
                if cur_ttl==hop and hop_ip!=dst_ip:
                    #icmp time exceed during transmission
                    ether = Ether(src=hop_eth, dst=src_eth)
                    ip = IP(src=hop_ip, dst=src_ip)
                    icmp = ICMP(type=11, code=0)
                    #resp = ether/ip/icmp/pkt[0][IP]/pkt[0][UDP]
                    resp = ether/ip/icmp/IPerror(str(pkt[0][IP]))
                    #recalculate checksum
                    #resp.show2()
                    return resp
                #if cur_ttl==hop and hop_ip==dst_ip:
                if cur_ttl>=(len(route.hops)-1) and hop_ip==dst_ip:
                    #icmp destination and port unreachable
                    ether = Ether(src=hop_eth, dst=src_eth)
                    ip = IP(src=hop_ip, dst=src_ip)
                    icmp = ICMP(type=3, code=3)
                    resp = ether/ip/icmp/IPerror(str(pkt[0][IP]))
                    #recalculate checksum
                    #resp.show2()
                    return resp
                hop+=1

    def adjustNesetedPacket(self, pkt):
        src_eth = pkt[0][Ether].src
        dst_eth = pkt[0][Ether].dst
        src_ip = pkt[0][IP].src
        dst_ip = pkt[0][IP].dst
        cur_ttl = pkt[0][IP].ttl
        nested_src_ip = pkt[0][ICMP][0].src
        nested_dst_ip = pkt[0][ICMP][0].dst
        route = self.networkview.getRouteToIP(src_ip)
        dec_src_ip = route.startNode.decepted_ip_addr
        dec_dst_ip = route.endNode.decepted_ip_addr
        #pkt.show2()
        pkt[0][ICMP][0].src = dec_src_ip
        pkt[0][ICMP][0].dst = dec_dst_ip
        #pkt.show2()
        return pkt
        #print("Nested " + str(nested_src_ip) + " " + str(nested_dst_ip) + " change to "  + str(dec_src_ip) + " " + str(dec_dst_ip))

