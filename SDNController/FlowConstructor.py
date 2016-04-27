from pox.core import core
import pox.openflow.nicira as nx
from pox.lib.util import str_to_bool
from pox.SDNController_ncds.FlowCreator import FlowCreator
from pox.SDNController_ncds.ViewReader import ViewReader
from pox.openflow.of_json import *
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import pox.openflow.libopenflow_01 as of
from LoggingPrinter import LoggingPrinter
import os

class FlowConstructor(object):

    def __init__ (self):
        self.rules=[]
        self.rulesByIP={}
        self.rulesByMAC={}
        self.logging = LoggingPrinter()

    def constructRule(self,nv,packet,ingressPort,connection,event):
        self.networkview = nv
        hosts = self.networkview.access
        routes = self.networkview.routes
        #self.hostHops = {}
        currentOutPort=0
        currentOutSrcIP=None
        currentOutDstIP=None
        currentOutSrcMac=None
        currentOutDstMac=None
        flowRule=None

        #check if request comes from target node or not
        if str(packet.src)==str(self.networkview.target.eth_addr) and (str(nv.getNodeByEth(packet.src).visible)=="v" or nv.getNodeByEth(packet.src).isHoneypot==True):
            if packet.type==ethernet.ARP_TYPE:
                pkt = packet.find('arp')
                if pkt!=None:
                    if pkt.opcode==arp.REQUEST:
                        print("ARP packet src " + str(pkt.protosrc) + " " + str(pkt.protodst) + " " + str(nv.canContact(pkt.protosrc,pkt.protodst)) + " " + str(ingressPort))
                        #check if request is comming from target
                        if str(pkt.hwsrc)==str(self.networkview.target.eth_addr):
                            if nv.canContact(pkt.protosrc,pkt.protodst)==True:
                                flowRule = nx.nx_flow_mod()
                                flowRule.match.in_port = ingressPort
                                flowRule.match.NXM_OF_ETH_TYPE = ethernet.ARP_TYPE
                                flowRule.match.NXM_OF_ARP_OP = arp.REQUEST
                                flowRule.match.eth_src = EthAddr(pkt.hwsrc)
                                flowRule.idle_timeout = 30
                                flowRule.priority = 2
                                flowRule.actions.append(of.ofp_action_output(port = int(nv.server.switchPort)))
                                connection.send(flowRule)
                                self.logging.logRule(flowRule,"ARP")
                                currentOutPort = int(nv.server.switchPort)

                                flowRule = nx.nx_flow_mod()
                                flowRule.match.in_port = int(nv.server.switchPort)
                                flowRule.match.NXM_OF_ETH_TYPE = ethernet.ARP_TYPE
                                flowRule.match.NXM_OF_ARP_OP = arp.REPLY
                                flowRule.match.eth_dst = EthAddr(pkt.hwsrc)
                                flowRule.idle_timeout = 30
                                flowRule.priority = 2
                                flowRule.actions.append(of.ofp_action_output(port = ingressPort))
                                connection.send(flowRule)
                                self.logging.logRule(flowRule,"ARP")
                        else:
                            #if request is not from target, learn route
                            flowRule = nx.nx_flow_mod()
                            flowRule.match.in_port = ingressPort
                            flowRule.match.NXM_OF_ETH_TYPE = ethernet.ARP_TYPE
                            flowRule.match.NXM_OF_ARP_OP = arp.REQUEST
                            flowRule.match.eth_src = EthAddr(pkt.hwsrc)
                            flowRule.idle_timeout = 30
                            flowRule.priority = 2
                            flowRule.actions.append(of.ofp_action_output(port = int(nv.server.switchPort)))
                            connection.send(flowRule)
                            self.logging.logRule(flowRule,"ARP")
                            currentOutPort = int(nv.server.switchPort)

                            flowRule = nx.nx_flow_mod()
                            flowRule.match.in_port = int(nv.server.switchPort)
                            flowRule.match.NXM_OF_ETH_TYPE = ethernet.ARP_TYPE
                            flowRule.match.NXM_OF_ARP_OP = arp.REPLY
                            flowRule.match.eth_dst = EthAddr(pkt.hwsrc)
                            flowRule.idle_timeout = 30
                            flowRule.priority = 2
                            flowRule.actions.append(of.ofp_action_output(port = ingressPort))
                            connection.send(flowRule)
                            self.logging.logRule(flowRule,"ARP")

            elif packet.type==ethernet.IP_TYPE:
                #print("IP packet")
                #create rules for route to the specific host
                route_eth_dst=None
                route_ip_dst=None
                route_ip_src=None
                #print("Route src " + str(packet.payload.srcip) + " " + str(packet.payload.dstip) + " " + str(nv.canContact(packet.payload.srcip,packet.payload.dstip)))
                if nv.canContact(packet.payload.srcip,packet.payload.dstip)==True:
                    hopCt=0
                    for r in routes:
                        for i in range(1,(len(r.hops)-1)):
                            hop = r.hops[i]
                            #print("hopCt " + str(hopCt) + " isRouter " + str(hop.isRouter))
                            #print("Route src " + str(packet.payload.srcip) + " " + str(packet.payload.dstip) + " " + str(nv.canContact(packet.payload.srcip,packet.payload.dstip)))
                            if hop.isRouter==True and packet.payload.srcip==r.startNode.decepted_ip_addr and packet.payload.dstip==r.endNode.decepted_ip_addr:
                                if packet.payload.ttl<=(len(r.hops)-2):
                                    #establish route if packet ttl matches, forward to deception server
                                    hopCt+=1
                                    flowRule = nx.nx_flow_mod()
                                    flowRule.match.NXM_OF_ETH_TYPE = ethernet.IP_TYPE
                                    flowRule.match.NXM_NX_IP_TTL = hopCt
                                    flowRule.match.eth_src = EthAddr(r.startNode.decepted_eth_addr)
                                    #flowRule.match.eth_dst = EthAddr(r.endNode.decepted_eth_addr)
                                    flowRule.match.eth_dst = EthAddr(str(self.networkview.gateway.eth_addr))
                                    flowRule.match.ip_src = IPAddr(r.startNode.decepted_ip_addr)
                                    flowRule.match.ip_dst = IPAddr(r.endNode.decepted_ip_addr)
                                    flowRule.idle_timeout = 30
                                    flowRule.priority = 2
                                    flowRule.actions.append(of.ofp_action_output(port = int(nv.server.switchPort)))
                                    connection.send(flowRule)
                                    self.logging.logRule(flowRule,"")
                                    #port for current packet on multi hop route
                                    currentOutPort = int(r.hops[packet.payload.ttl].switchPort)
                                    print("1 - Multi hop port " + str(currentOutPort))

                                    #establish route for answer packet from deception server back to target node
                                    flowRule = nx.nx_flow_mod()
                                    flowRule.match.NXM_OF_ETH_TYPE = ethernet.IP_TYPE
                                    flowRule.match.eth_src = EthAddr(r.hops[hopCt].decepted_eth_addr)
                                    #flowRule.match.eth_dst = EthAddr(r.endNode.decepted_eth_addr)
                                    flowRule.match.eth_dst = EthAddr(r.startNode.decepted_eth_addr)
                                    flowRule.match.ip_src = IPAddr(r.hops[hopCt].decepted_ip_addr)
                                    flowRule.match.ip_dst = IPAddr(r.startNode.decepted_ip_addr)
                                    for d in range(0,hopCt):
                                        flowRule.actions.append(nx.nx_action_dec_ttl())
                                    flowRule.idle_timeout = 30
                                    flowRule.priority = 2
                                    flowRule.actions.append(of.ofp_action_output(port = int(ingressPort)))
                                    connection.send(flowRule)
                                    self.logging.logRule(flowRule,"")
                                else:
                                    hopCt=(len(r.hops)-2)

                    route_eth_dst=packet.dst
                    route_ip_dst=packet.payload.dstip
                    route_ip_src=packet.payload.srcip

                    if hopCt>0:
                        maxHop = hopCt
                        #forward packets with TTL to destination
                        #print("IP: " + str(route_ip_dst) + " V: " + str(nv.getNodeByDecIP(route_ip_dst).visible))
                        if nv.getNodeByDecIP(route_ip_dst).visible=="v" or nv.getNodeByDecIP(route_ip_dst).isHoneypot==True:
                            for ttl in range((maxHop+1),65):
                                flowRule = nx.nx_flow_mod()
                                flowRule.match.of_eth_type = ethernet.IP_TYPE
                                flowRule.match.eth_src = EthAddr(str(self.networkview.target.eth_addr))
                                flowRule.match.eth_dst = EthAddr(str(self.networkview.gateway.eth_addr))
                                flowRule.match.ip_src = IPAddr(str(self.networkview.target.decepted_ip_addr))
                                flowRule.match.ip_dst = IPAddr(str(route_ip_dst))
                                flowRule.match.NXM_NX_IP_TTL = ttl
                                flowRule.idle_timeout = 30
                                flowRule.priority = 1
                                flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(self.networkview.target.ip_addr)))
                                flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.target.eth_addr)))
                                flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(nv.getNodeByDecIP(route_ip_dst).ip_addr)))
                                flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(nv.getNodeByDecIP(route_ip_dst).eth_addr)))
                                flowRule.actions.append(of.ofp_action_output(port = int(nv.getNodeByDecIP(route_ip_dst).switchPort)))
                                connection.send(flowRule)
                                self.logging.logRule(flowRule,"")
                                if packet.payload.ttl>hopCt:
                                    currentOutPort = int(nv.getNodeByDecIP(route_ip_dst).switchPort)
                                    currentOutSrcIP=IPAddr(self.networkview.target.ip_addr)
                                    currentOutDstIP=IPAddr(nv.getNodeByDecIP(route_ip_dst).ip_addr)
                                    currentOutSrcMac=EthAddr(self.networkview.target.eth_addr)
                                    currentOutDstMac=EthAddr(nv.getNodeByDecIP(route_ip_dst).eth_addr)

                            #send back to target and decrease ttl
                            flowRule = nx.nx_flow_mod()
                            flowRule.match.of_eth_type = ethernet.IP_TYPE
                            flowRule.match.eth_src = EthAddr(str(nv.getNodeByDecIP(route_ip_dst).eth_addr))
                            flowRule.match.ip_src = IPAddr(nv.getNodeByDecIP(route_ip_dst).ip_addr)
                            flowRule.match.ip_dst = IPAddr(str(nv.getNodeByDecIP(route_ip_src).ip_addr))
                            flowRule.match.eth_dst = EthAddr(str(nv.getNodeByDecIP(route_ip_src).eth_addr))
                            flowRule.idle_timeout = 30
                            flowRule.priority = 1
                            for hop in range(0,hopCt):
                                flowRule.actions.append(nx.nx_action_dec_ttl())
                            #print("Decrease ttl by " + str(hopCount))
                            flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(str(nv.getNodeByDecIP(route_ip_dst).decepted_ip_addr))))
                            flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.gateway.eth_addr)))
                            flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.networkview.target.decepted_ip_addr)))
                            flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.networkview.target.eth_addr)))
                            flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                            connection.send(flowRule)
                            self.logging.logRule(flowRule,"")

                    else:
                        if nv.getNodeByDecIP(route_ip_dst).visible=="v" or nv.getNodeByDecIP(route_ip_dst).isHoneypot==True:
                            flowRule = nx.nx_flow_mod()
                            flowRule.match.of_eth_type = ethernet.IP_TYPE
                            flowRule.match.eth_src = EthAddr(str(self.networkview.target.eth_addr))
                            flowRule.match.eth_dst = EthAddr(str(route_eth_dst))
                            flowRule.match.ip_src = IPAddr(str(self.networkview.target.decepted_ip_addr))
                            flowRule.match.ip_dst = IPAddr(str(route_ip_dst))
                            flowRule.idle_timeout = 30
                            flowRule.priority = 1
                            flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(self.networkview.target.ip_addr)))
                            flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.target.eth_addr)))
                            flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(nv.getNodeByDecIP(route_ip_dst).ip_addr)))
                            flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(nv.getNodeByDecIP(route_ip_dst).eth_addr)))
                            flowRule.actions.append(of.ofp_action_output(port = int(nv.getNodeByDecIP(route_ip_dst).switchPort)))
                            connection.send(flowRule)
                            self.logging.logRule(flowRule,"")
                            currentOutPort = int(nv.getNodeByDecIP(route_ip_dst).switchPort)
                            currentOutSrcIP=IPAddr(self.networkview.target.ip_addr)
                            currentOutDstIP=IPAddr(nv.getNodeByDecIP(route_ip_dst).ip_addr)
                            currentOutSrcMac=EthAddr(self.networkview.target.eth_addr)
                            currentOutDstMac=EthAddr(nv.getNodeByDecIP(route_ip_dst).eth_addr)

                            #send back to target and decrease ttl
                            flowRule = nx.nx_flow_mod()
                            flowRule.match.of_eth_type = ethernet.IP_TYPE
                            flowRule.match.eth_src = EthAddr(str(nv.getNodeByDecIP(route_ip_dst).eth_addr))
                            flowRule.match.ip_src = IPAddr(nv.getNodeByDecIP(route_ip_dst).ip_addr)
                            flowRule.match.ip_dst = IPAddr(self.networkview.target.ip_addr)
                            flowRule.match.eth_dst = EthAddr(self.networkview.target.eth_addr)
                            flowRule.idle_timeout = 30
                            flowRule.priority = 1
                            flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(str(nv.getNodeByDecIP(route_ip_dst).decepted_ip_addr))))
                            flowRule.actions.append(of.ofp_action_dl_addr.set_src(str(nv.getNodeByDecIP(route_ip_dst).decepted_eth_addr)))
                            flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.networkview.target.decepted_ip_addr)))
                            flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.networkview.target.eth_addr)))
                            flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                            connection.send(flowRule)
                            self.logging.logRule(flowRule,"")


                    #handle nested packets in icmp error by forwarding it to the deception server
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.of_eth_type = ethernet.IP_TYPE
                    flowRule.match.of_ip_proto = ipv4.ICMP_PROTOCOL
                    flowRule.match.of_icmp_code = 3
                    flowRule.match.of_icmp_type = 3
                    flowRule.match.in_port = int(nv.getNodeByDecIP(route_ip_dst).switchPort)
                    flowRule.match.eth_src = EthAddr(str(nv.getNodeByDecIP(route_ip_dst).eth_addr))
                    flowRule.match.ip_src = IPAddr(nv.getNodeByDecIP(route_ip_dst).ip_addr)
                    flowRule.match.ip_dst = IPAddr(str(self.networkview.target.ip_addr))
                    flowRule.match.eth_dst = EthAddr(str(self.networkview.target.eth_addr))
                    flowRule.idle_timeout = 30
                    flowRule.priority = 1000
                    for hop in range(0,hopCt):
                        flowRule.actions.append(nx.nx_action_dec_ttl())
                    flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(str(nv.getNodeByDecIP(route_ip_dst).decepted_ip_addr))))
                    if hopCt>0:
                        flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.gateway.eth_addr)))
                    else:
                        flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(str(nv.getNodeByDecIP(route_ip_dst).decepted_eth_addr))))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.networkview.target.decepted_ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.networkview.target.eth_addr)))
                    flowRule.actions.append(of.ofp_action_output(port = int(nv.server.switchPort)))
                    if packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                        if packet.payload.payload.type==3 and packet.payload.payload.code==3:
                            currentOutPort = int(nv.server.switchPort)
                    connection.send(flowRule)
                    self.logging.logRule(flowRule,"")

                    #send response from deception server back to target host
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.of_eth_type = ethernet.IP_TYPE
                    flowRule.match.of_ip_proto = ipv4.ICMP_PROTOCOL
                    flowRule.match.of_icmp_code = 3
                    flowRule.match.of_icmp_type = 3
                    flowRule.match.in_port = int(nv.server.switchPort)
                    if hopCt>0:
                        flowRule.match.eth_src = EthAddr(str(self.networkview.gateway.eth_addr))
                    else:
                        flowRule.match.eth_src = EthAddr(str(nv.getNodeByDecIP(route_ip_dst).decepted_eth_addr))
                    flowRule.match.ip_src = IPAddr(nv.getNodeByDecIP(route_ip_dst).decepted_ip_addr)
                    flowRule.match.ip_dst = IPAddr(str(self.networkview.target.decepted_ip_addr))
                    flowRule.match.eth_dst = EthAddr(str(self.networkview.target.eth_addr))
                    flowRule.idle_timeout = 30
                    flowRule.priority = 1000
                    flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                    connection.send(flowRule)
                    self.logging.logRule(flowRule,"")


                #if packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                #    print("ICMP packet")
                #if packet.payload.protocol == ipv4.TCP_PROTOCOL:
                #    print("TCP packet")

                if packet.payload.protocol == ipv4.UDP_PROTOCOL:
                    print("Received UDP packet with TTL " + str(packet.payload.ttl))
                    if packet.payload.payload.srcport==68 and packet.payload.payload.dstport==67:
                        #Handle DHCP request
                        #print("Create rule " + str("DHCP from port 68 ") + "to port " + str(1))
                        flowRule = nx.nx_flow_mod()
                        flowRule.match.of_eth_type = ethernet.IP_TYPE
                        flowRule.match.of_ip_proto = ipv4.UDP_PROTOCOL
                        flowRule.match.eth_src = packet.src
                        #flowRule.match.eth_dst = nv.server.eth_addr
                        flowRule.match.udp_src = int(68)
                        flowRule.match.udp_dst = int(67)
                        flowRule.idle_timeout = 30
                        flowRule.actions.append(of.ofp_action_output(port = int(nv.server.switchPort)))
                        connection.send(flowRule)
                        self.logging.logRule(flowRule,"DHCP")
                        currentOutPort = int(nv.server.switchPort)

                        #print("Create rule " + str("DHCP from port 67 ") + " to port " + str(h.switchPort))
                        flowRule = nx.nx_flow_mod()
                        flowRule.match.of_eth_type = ethernet.IP_TYPE
                        flowRule.match.of_ip_proto = ipv4.UDP_PROTOCOL
                        flowRule.match.eth_src = nv.server.eth_addr
                        flowRule.match.eth_dst = packet.src
                        flowRule.match.udp_src = int(67)
                        flowRule.match.udp_dst = int(68)
                        flowRule.idle_timeout = 30
                        flowRule.actions.append(of.ofp_action_output(port = int(ingressPort)))
                        connection.send(flowRule)
                        self.logging.logRule(flowRule,"DHCP")

            #send out current packet
            if currentOutPort!=0:
                print("Sending current packet out on port " + str(currentOutPort))
                outPkt = of.ofp_packet_out(data = event.ofp)
                if currentOutSrcIP!=None:
                    outPkt.actions.append(of.ofp_action_nw_addr.set_src(currentOutSrcIP))
                    outPkt.actions.append(of.ofp_action_nw_addr.set_dst(currentOutDstIP))
                    outPkt.actions.append(of.ofp_action_dl_addr.set_src(currentOutSrcMac))
                    outPkt.actions.append(of.ofp_action_dl_addr.set_dst(currentOutDstMac))
                outPkt.actions.append(of.ofp_action_output(port = int(currentOutPort)))
                connection.send(outPkt)

        else:
            currentOutPort==0
            currentOutSrcIP=None
            currentOutDstIP=None
            currentOutSrcMac=None
            currentOutDstMac=None
            #print("Handle traffic of other nodes beside target nodes " + str(packet.src) + " " + str(packet.dst))
            if packet.type==ethernet.ARP_TYPE:
                pkt = packet.find('arp')
                if pkt!=None:
                    if pkt.opcode==arp.REQUEST:
                        flowRule = nx.nx_flow_mod()
                        flowRule.match.in_port = ingressPort
                        flowRule.match.NXM_OF_ETH_TYPE = ethernet.ARP_TYPE
                        flowRule.match.NXM_OF_ARP_OP = arp.REQUEST
                        flowRule.match.eth_src = EthAddr(pkt.hwsrc)
                        flowRule.idle_timeout = 30
                        flowRule.priority = 2
                        flowRule.actions.append(of.ofp_action_output(port = int(nv.server.switchPort)))
                        connection.send(flowRule)
                        self.logging.logRule(flowRule,"ARP")

                        flowRule = nx.nx_flow_mod()
                        flowRule.match.in_port = int(nv.server.switchPort)
                        flowRule.match.NXM_OF_ETH_TYPE = ethernet.ARP_TYPE
                        flowRule.match.NXM_OF_ARP_OP = arp.REPLY
                        flowRule.match.eth_dst = EthAddr(pkt.hwsrc)
                        flowRule.idle_timeout = 30
                        flowRule.priority = 2
                        flowRule.actions.append(of.ofp_action_output(port = ingressPort))
                        connection.send(flowRule)
                        self.logging.logRule(flowRule,"ARP")

            else:
                src_node = nv.getNodeByEth(packet.src)
                dst_node = nv.getNodeByEth(packet.dst)
                #print("Src node " + str(src_node) + " dst node " + str(dst_node) + " src " + str(packet.src) + " dst " + str(packet.dst))
                if src_node!=None and dst_node!=None:
                    #print("Route traffic from " + str(src_node.ip_addr) + " to " + str(dst_node.ip_addr))
                    if str(packet.dst)==str(self.networkview.target.eth_addr):
                        flowRule = nx.nx_flow_mod()
                        flowRule.match.of_eth_type = ethernet.IP_TYPE
                        flowRule.match.eth_dst = EthAddr(str(self.networkview.target.eth_addr))
                        flowRule.match.eth_src = EthAddr(str(src_node.eth_addr))
                        flowRule.match.ip_dst = IPAddr(str(self.networkview.target.ip_addr))
                        flowRule.match.ip_src = IPAddr(str(src_node.ip_addr))
                        flowRule.idle_timeout = 30
                        flowRule.priority = 1
                        flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(self.networkview.target.ip_addr)))
                        #flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.target.eth_addr)))
                        flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.networkview.target.decepted_ip_addr)))
                        #flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.networkview.target.decepted_eth_addr)))
                        flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                        connection.send(flowRule)
                        self.logging.logRule(flowRule,"")
                        currentOutPort = int(self.networkview.target.switchPort)
                        currentOutSrcIP=IPAddr(self.networkview.target.ip_addr)
                        currentOutDstIP=IPAddr(self.networkview.target.decepted_ip_addr)

                        flowRule = nx.nx_flow_mod()
                        flowRule.match.of_eth_type = ethernet.IP_TYPE
                        flowRule.match.eth_src = EthAddr(str(self.networkview.target.decepted_eth_addr))
                        flowRule.match.eth_dst = EthAddr(str(self.networkview.gateway.decepted_eth_addr))
                        flowRule.match.ip_src = IPAddr(str(self.networkview.target.decepted_ip_addr))
                        flowRule.match.ip_dst = IPAddr(str(self.networkview.target.ip_addr))
                        flowRule.idle_timeout = 30
                        flowRule.priority = 1
                        flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(str(self.networkview.target.ip_addr))))
                        flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(str(self.networkview.target.eth_addr))))
                        flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(src_node.ip_addr)))
                        flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(src_node.eth_addr)))
                        flowRule.actions.append(of.ofp_action_output(port = int(src_node.switchPort)))
                        connection.send(flowRule)
                        self.logging.logRule(flowRule,"")
                    else:
                        flowRule = nx.nx_flow_mod()
                        flowRule.match.of_eth_type = ethernet.IP_TYPE
                        flowRule.match.eth_dst = EthAddr(str(dst_node.eth_addr))
                        flowRule.match.eth_src = EthAddr(str(src_node.eth_addr))
                        flowRule.match.ip_dst = IPAddr(str(dst_node.ip_addr))
                        flowRule.match.ip_src = IPAddr(str(src_node.ip_addr))
                        flowRule.idle_timeout = 30
                        flowRule.priority = 1
                        flowRule.actions.append(of.ofp_action_output(port = int(dst_node.switchPort)))
                        connection.send(flowRule)
                        self.logging.logRule(flowRule,"")
                        currentOutPort = int(dst_node.switchPort)

                        flowRule = nx.nx_flow_mod()
                        flowRule.match.of_eth_type = ethernet.IP_TYPE
                        flowRule.match.eth_dst = EthAddr(str(src_node.eth_addr))
                        flowRule.match.eth_src = EthAddr(str(dst_node.eth_addr))
                        flowRule.match.ip_dst = IPAddr(str(src_node.ip_addr))
                        flowRule.match.ip_src = IPAddr(str(dst_node.ip_addr))
                        flowRule.idle_timeout = 30
                        flowRule.priority = 1
                        flowRule.actions.append(of.ofp_action_output(port = int(src_node.switchPort)))
                        connection.send(flowRule)
                        self.logging.logRule(flowRule,"")

            #send out current packet
            if currentOutPort!=0:
                print("Sending current packet out on port " + str(currentOutPort))
                outPkt = of.ofp_packet_out(data = event.ofp)
                if currentOutSrcIP!=None:
                    outPkt.actions.append(of.ofp_action_nw_addr.set_src(currentOutSrcIP))
                    outPkt.actions.append(of.ofp_action_nw_addr.set_dst(currentOutDstIP))
                outPkt.actions.append(of.ofp_action_output(port = int(currentOutPort)))
                connection.send(outPkt)



    def flowLookup(self,packet):
        if packet.type==ethernet.ARP_TYPE:
            print("ARP packet")
        elif packet.type==ethernet.IP_TYPE:
            print("IP packet")
            if packet.payload.protocol == ipv4.ICMP_PROTOCOL:
                print("ICMP packet")
            if packet.payload.protocol == ipv4.TCP_PROTOCOL:
                print("TCP packet")
            if packet.payload.protocol == ipv4.UDP_PROTOCOL:
                print("UDP packet")
        else:
            print("Other packet")

    def getFlowByIP(self,dstIP):
        return self.rulesByIP[dstIP]

    def getFlowByMAC(self,dstMAC):
        return self.rulesByMAC[dstMAC]

    def addFlowtoDB(self,rules):
        for rule in rules:
            if rule.match.ip_dst!=None:
                print(str(rule.match.ip_dst))
            else:
                print(str(rule.match.eth_dst))
            #print(str(rule))




