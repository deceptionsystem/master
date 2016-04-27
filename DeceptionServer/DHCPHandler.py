from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from Policy import Policy
from Node import Node
import binascii

class DHCPHandler(object):

    def __init__(self,nv):
        self.nodes = []
        self.networkview = nv
        print("DHCP server started...")

    def handleDHCP(self,pkt):
        if pkt[0][DHCP].options[0][1] == 1:
            return self.handleDiscover(pkt)
        elif pkt[0][DHCP].options[0][1] == 3:
            return self.handleRequest(pkt)


    def handleDiscover(self,pkt):
        n = self.networkview.getNodeByEth(pkt[0][Ether].src)

        if n!=None:
            for node in self.networkview.access:
                print("Node " + str(node.eth_addr) + " pkt eth " + str(pkt[0][Ether].src))

            eth_server = str(self.networkview.server.eth_addr)
            eth_client = n.eth_addr
            ip_server = str(self.networkview.server.ip_addr)
            ip_client = "255.255.255.255"
            port_src = 67
            port_dst = 68
            subnet_mask = "255.255.255.0"
            gateway = self.networkview.gateway.ip_addr

            ether = Ether(src=eth_server, dst=eth_client)
            ip = IP(src=ip_server, dst=ip_client)
            udp = UDP(sport=port_src, dport=port_dst)
            #chaddr="\x00\x00\x00\x00\x00\x03"
            bootp = BOOTP(op=2,yiaddr=n.decepted_ip_addr,siaddr="0.0.0.0",giaddr=gateway,chaddr=binascii.unhexlify(pkt[0][Ether].src.replace(":","")),xid=pkt[0][BOOTP].xid)
            dhcp = DHCP(options=[('message-type','offer')])/DHCP(options=[('subnet_mask',subnet_mask)])/DHCP(options=[('server_id',ip_server),('end')])

            resp_pkt = ether/ip/udp/bootp/dhcp
            #print(resp_pkt.show())
            return resp_pkt
        else:
            return None

    def handleRequest(self,pkt):
        n = self.networkview.getNodeByEth(pkt[0][Ether].src)

        eth_server = str(self.networkview.server.eth_addr)
        eth_client = n.eth_addr
        ip_server = str(self.networkview.server.ip_addr)
        ip_client = n.decepted_ip_addr
        port_src = 67
        port_dst = 68
        subnet_mask = "255.255.255.0"
        gateway = self.networkview.gateway.ip_addr

        ether = Ether(src=eth_server, dst=n.eth_addr)
        ip = IP(src=ip_server, dst=ip_client)
        udp = UDP(sport=port_src, dport=port_dst)
        bootp = BOOTP(op=2,yiaddr=n.decepted_ip_addr,siaddr="0.0.0.0",giaddr=gateway,chaddr=binascii.unhexlify(pkt[0][Ether].src.replace(":","")),xid=pkt[0][BOOTP].xid)
        dhcp = DHCP(options=[('message-type','ack')])/\
               DHCP(options=[('subnet_mask',subnet_mask)])/\
               DHCP(options=[('lease_time',6500000)])/\
               DHCP(options=[('renewal_time',6500000)])/\
               DHCP(options=[('rebinding_time',6500000)])/\
               DHCP(options=[('router',gateway)])/\
               DHCP(options=[('server_id',ip_server),('end')])
        resp_pkt = ether/ip/udp/bootp/dhcp

        #n = self.Policy.getNode("00:00:00:00:00:03")
        #n.ip_addr = "10.0.1.2"
        #self.Policy.updateNode(n)

        #print(resp_pkt.show())
        return resp_pkt
