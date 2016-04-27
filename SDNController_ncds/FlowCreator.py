
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.openflow.nicira as nx
from pox.lib.packet.ethernet import ethernet
import pox.lib.packet.ipv4 as ipv4
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

FLOW_TIMEOUT=0

class FlowCreator(object):

    def generateRules(self,nv):
        self.networkview = nv
        hosts = self.networkview.access
        routes = self.networkview.routes
        self.hostHops = {}

        rules = []

        flowRule = nx.nx_flow_mod()
        flowRule.match.eth_dst = EthAddr("ff:ff:ff:ff:ff:ff")
        flowRule.hard_timeout = FLOW_TIMEOUT
        flowRule.actions.append(of.ofp_action_output(port = 1))
        rules.append(flowRule)

        '''
        flowRule = nx.nx_flow_mod()
        flowRule.match.eth_src = EthAddr("00:00:00:00:00:01")
        flowRule.match.eth_dst = EthAddr(self.networkview.target.eth_addr)
        flowRule.hard_timeout = FLOW_TIMEOUT
        flowRule.priority = 2
        flowRule.actions.append(of.ofp_action_output(port = 2))
        rules.append(flowRule)

        flowRule = nx.nx_flow_mod()
        flowRule.match.eth_src = EthAddr(self.networkview.target.eth_addr)
        flowRule.match.eth_dst = EthAddr("00:00:00:00:00:01")
        flowRule.hard_timeout = FLOW_TIMEOUT
        flowRule.priority = 2
        flowRule.actions.append(of.ofp_action_output(port = 1))
        rules.append(flowRule)

        #TMP for DNS test
        flowRule = nx.nx_flow_mod()
        flowRule.match.NXM_OF_ETH_TYPE = ethernet.IP_TYPE
        flowRule.match.ip_dst = IPAddr("10.168.0.10")
        flowRule.match.ip_src = IPAddr("10.168.0.11")
        flowRule.hard_timeout = FLOW_TIMEOUT
        flowRule.actions.append(of.ofp_action_output(port = 2))
        #rules.append(flowRule)

        flowRule = nx.nx_flow_mod()
        flowRule.match.NXM_OF_ETH_TYPE = ethernet.IP_TYPE
        flowRule.match.of_ip_proto = ipv4.UDP_PROTOCOL
        flowRule.match.udp_src = int(53)
        flowRule.hard_timeout = FLOW_TIMEOUT
        flowRule.priority = 999
        flowRule.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        rules.append(flowRule)
        '''


        #create rules for routes
        for r in routes:
            hopCt=0
            for hop in r.hops:
                #print("hopCt " + str(hopCt) + " isRouter " + str(hop.isRouter))
                if hopCt!=0 and hop.isRouter==True:
                    #print("Create rule " + str(r.startNode.decepted_ip_addr) + " --> " + str(r.endNode.decepted_ip_addr) + " with ttl " + str(hopCt) + " - " + str(1))
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.NXM_OF_ETH_TYPE = ethernet.IP_TYPE
                    flowRule.match.NXM_NX_IP_TTL = hopCt
                    flowRule.match.eth_src = EthAddr(r.startNode.decepted_eth_addr)
                    flowRule.match.eth_dst = EthAddr(r.endNode.decepted_eth_addr)
                    flowRule.match.ip_src = IPAddr(r.startNode.decepted_ip_addr)
                    flowRule.match.ip_dst = IPAddr(r.endNode.decepted_ip_addr)
                    flowRule.hard_timeout = FLOW_TIMEOUT
                    flowRule.priority = 2
                    flowRule.actions.append(of.ofp_action_output(port = 1))
                    rules.append(flowRule)
                hopCt+=1
            hopCt-=2
            if hopCt>0 :
                self.hostHops[r.endNode.decepted_eth_addr] = hopCt

        #for key in self.hostHops.keys():
        #    print("Key " + str(key))


        #create rules for packet flow
        for h in hosts:

            #generate rule from deception server to host for ARP and DHCP
            #print("Create rule " + str("ARP from port 1") + " --> " + str(h.eth_addr) + " to port " + str(h.switchPort))
            flowRule = nx.nx_flow_mod()
            flowRule.match.of_eth_type = ethernet.ARP_TYPE
            flowRule.match.in_port = 1
            flowRule.match.eth_dst = EthAddr(h.eth_addr)
            flowRule.hard_timeout = FLOW_TIMEOUT
            flowRule.actions.append(of.ofp_action_output(port = int(h.switchPort)))
            rules.append(flowRule)

            #print("Create rule " + str("ARP from ") + str(h.eth_addr) + " to port " + str(1))
            flowRule = nx.nx_flow_mod()
            flowRule.match.of_eth_type = ethernet.ARP_TYPE
            flowRule.match.in_port = 1
            flowRule.match.eth_src = EthAddr(h.eth_addr)
            flowRule.match.in_port = int(h.switchPort)
            flowRule.hard_timeout = FLOW_TIMEOUT
            flowRule.actions.append(of.ofp_action_output(port = 1))
            rules.append(flowRule)

            #print("Create rule " + str("DHCP from port 68 ") + "to port " + str(1))
            flowRule = nx.nx_flow_mod()
            flowRule.match.of_eth_type = ethernet.IP_TYPE
            flowRule.match.of_ip_proto = ipv4.UDP_PROTOCOL
            flowRule.match.eth_src = EthAddr(str(h.eth_addr))
            flowRule.match.udp_src = int(68)
            flowRule.hard_timeout = FLOW_TIMEOUT
            flowRule.actions.append(of.ofp_action_output(port = int(1)))
            rules.append(flowRule)

            #print("Create rule " + str("DHCP from port 67 ") + " to port " + str(h.switchPort))
            flowRule = nx.nx_flow_mod()
            flowRule.match.of_eth_type = ethernet.IP_TYPE
            flowRule.match.of_ip_proto = ipv4.UDP_PROTOCOL
            flowRule.match.eth_dst = EthAddr(str(h.eth_addr))
            flowRule.match.udp_src = int(67)
            flowRule.hard_timeout = FLOW_TIMEOUT
            flowRule.actions.append(of.ofp_action_output(port = int(h.switchPort)))
            rules.append(flowRule)


            #normal node
            if h.isHoneypot==False and h.isRouter==False and h.eth_addr!=self.networkview.target.eth_addr:
                #print("Create rule " + str(h.decepted_ip_addr) + " --> " + str(h.ip_addr))

                if self.hostHops.has_key(h.decepted_eth_addr):
                    #print("a - Create rule " + str(self.networkview.target.eth_addr) + " --> " + str(h.decepted_ip_addr) + "/" + str(self.networkview.gateway.eth_addr) + " - " + str(h.switchPort))
                    maxHop = self.hostHops.get(h.decepted_eth_addr)
                    for ttl in range((maxHop+1),65):
                        flowRule = nx.nx_flow_mod()
                        flowRule.match.of_eth_type = ethernet.IP_TYPE
                        flowRule.match.eth_src = EthAddr(str(self.networkview.target.eth_addr))
                        flowRule.match.eth_dst = EthAddr(str(self.networkview.gateway.eth_addr))
                        flowRule.match.ip_dst = IPAddr(str(h.decepted_ip_addr))
                        flowRule.match.NXM_NX_IP_TTL = ttl
                        flowRule.hard_timeout = FLOW_TIMEOUT
                        flowRule.priority = 1
                        flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(h.decepted_ip_addr)))
                        flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.gateway.eth_addr)))
                        flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(h.ip_addr)))
                        flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(h.eth_addr)))
                        #print("1 - " + str(self.networkview.gateway.eth_addr) + " --> " + str(h.eth_addr))
                        flowRule.actions.append(of.ofp_action_output(port = int(h.switchPort)))
                        rules.append(flowRule)

                    #send back to user and decrease ttl
                    #print("b - Create rule " + str(self.networkview.gateway.eth_addr) + " --> " + str(h.decepted_ip_addr) + "/" + str(self.networkview.target.eth_addr) + " - " + str(self.networkview.target.switchPort))
                    hopCount = self.hostHops[h.decepted_eth_addr]
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.of_eth_type = ethernet.IP_TYPE
                    flowRule.match.eth_src = EthAddr(str(h.eth_addr))
                    flowRule.match.ip_dst = IPAddr(str(h.decepted_ip_addr))
                    flowRule.match.eth_dst = EthAddr(str(self.networkview.gateway.eth_addr))
                    flowRule.hard_timeout = FLOW_TIMEOUT
                    flowRule.priority = 1
                    for hop in range(0,hopCount):
                        flowRule.actions.append(nx.nx_action_dec_ttl())
                    #print("Decrease ttl by " + str(hopCount))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(h.decepted_ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.gateway.eth_addr)))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.networkview.target.ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.networkview.target.eth_addr)))
                    flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                    #print("2 - " + str(self.networkview.gateway.eth_addr) + " --> " + str(self.networkview.target.eth_addr))
                    rules.append(flowRule)

                else:
                    #print("a - Create rule " + str(self.networkview.target.eth_addr) + " --> " + str(h.decepted_ip_addr) + "/" + str(h.decepted_eth_addr) + " - " + str(h.switchPort))
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.of_eth_type = ethernet.IP_TYPE
                    flowRule.match.eth_src = EthAddr(str(self.networkview.target.eth_addr))
                    flowRule.match.eth_dst = EthAddr(str(h.decepted_eth_addr))
                    flowRule.match.ip_dst = IPAddr(str(h.decepted_ip_addr))
                    flowRule.hard_timeout = FLOW_TIMEOUT
                    flowRule.priority = 1
                    flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(h.decepted_ip_addr)))
                    #flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(h.decepted_eth_addr)))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(h.ip_addr)))
                    #flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(h.eth_addr)))
                    flowRule.actions.append(of.ofp_action_output(port = int(h.switchPort)))
                    #print("3 - " + str(h.decepted_eth_addr) + " --> " + str(h.eth_addr))
                    rules.append(flowRule)

                    #print("b - Create rule " + str(h.eth_addr) + " --> " + str(h.decepted_eth_addr) + " - " + str(self.networkview.target.switchPort))
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.eth_src = EthAddr(str(h.eth_addr))
                    flowRule.match.eth_dst = EthAddr(str(h.decepted_eth_addr))
                    flowRule.hard_timeout = FLOW_TIMEOUT
                    flowRule.priority = 1
                    flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(h.decepted_ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(h.decepted_eth_addr)))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.networkview.target.ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.networkview.target.eth_addr)))
                    flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                    #print("4 - " + str(h.decepted_eth_addr) + " --> " + str(self.networkview.target.eth_addr))
                    rules.append(flowRule)


            #honeypot
            if h.isHoneypot==True and h.isRouter==False and h.eth_addr!=self.networkview.target.eth_addr:
                if self.hostHops.has_key(h.decepted_eth_addr):
                    #print("c - Create rule " + str(self.networkview.target.eth_addr) + " --> " + str(h.decepted_ip_addr) + "/" + str(self.networkview.gateway.eth_addr) + " - " + str(h.switchPort))
                    maxHop = self.hostHops.get(h.decepted_eth_addr)
                    for ttl in range((maxHop+1),65):
                        flowRule = nx.nx_flow_mod()
                        flowRule.match.of_eth_type = ethernet.IP_TYPE
                        flowRule.match.eth_src = EthAddr(str(self.networkview.target.eth_addr))
                        flowRule.match.eth_dst = EthAddr(str(self.networkview.gateway.eth_addr))
                        flowRule.match.ip_dst = IPAddr(str(h.decepted_ip_addr))
                        flowRule.match.NXM_NX_IP_TTL = ttl
                        flowRule.hard_timeout = FLOW_TIMEOUT
                        flowRule.priority = 1
                        flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(h.decepted_ip_addr)))
                        flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.gateway.eth_addr)))
                        flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(h.ip_addr)))
                        flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(h.eth_addr)))
                        #print("5 - " + str(self.networkview.gateway.eth_addr) + " --> " + str(h.eth_addr))
                        flowRule.actions.append(of.ofp_action_output(port = int(h.switchPort)))
                        rules.append(flowRule)

                    #send back to user and decrease ttl
                    #print("d - Create rule " + str(self.networkview.gateway.eth_addr) + " --> " + str(h.decepted_ip_addr) + "/" + str(self.networkview.target.eth_addr) + " - " + str(self.networkview.target.switchPort))
                    hopCount = self.hostHops[h.decepted_eth_addr]
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.of_eth_type = ethernet.IP_TYPE
                    flowRule.match.eth_src = EthAddr(str(h.eth_addr))
                    flowRule.match.ip_dst = IPAddr(str(h.decepted_ip_addr))
                    flowRule.match.eth_dst = EthAddr(str(self.networkview.gateway.eth_addr))
                    flowRule.hard_timeout = FLOW_TIMEOUT
                    flowRule.priority = 1
                    for hop in range(0,hopCount):
                        flowRule.actions.append(nx.nx_action_dec_ttl())
                    #print("Decrease ttl by " + str(hopCount))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(h.decepted_ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.networkview.gateway.eth_addr)))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.networkview.target.ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.networkview.target.eth_addr)))
                    #print("6 - " + str(self.networkview.gateway.eth_addr) + " --> " + str(self.networkview.target.eth_addr))
                    flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                    rules.append(flowRule)

                else:
                    #print("c - Create rule " + str(self.networkview.target.eth_addr) + " --> " + str(h.decepted_ip_addr) + "/" + str(h.decepted_eth_addr) + " - " + str(h.switchPort))
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.of_eth_type = ethernet.IP_TYPE
                    flowRule.match.eth_src = EthAddr(str(self.networkview.target.eth_addr))
                    flowRule.match.eth_dst = EthAddr(str(h.decepted_eth_addr))
                    flowRule.match.ip_dst = IPAddr(str(h.decepted_ip_addr))
                    flowRule.hard_timeout = FLOW_TIMEOUT
                    flowRule.priority = 1
                    flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(h.decepted_ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(h.decepted_eth_addr)))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(h.ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(h.eth_addr)))
                    #print("7 - " + str(self.networkview.gateway.eth_addr) + " --> " + str(h.eth_addr))
                    flowRule.actions.append(of.ofp_action_output(port = int(h.switchPort)))
                    rules.append(flowRule)

                    #print("d - Create rule " + str(h.eth_addr) + " --> " + str(h.decepted_eth_addr) + " - " + str(self.networkview.target.switchPort))
                    flowRule = nx.nx_flow_mod()
                    flowRule.match.eth_src = EthAddr(str(h.eth_addr))
                    flowRule.match.eth_dst = EthAddr(str(h.decepted_eth_addr))
                    flowRule.hard_timeout = FLOW_TIMEOUT
                    flowRule.priority = 1
                    flowRule.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(h.decepted_ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(h.decepted_eth_addr)))
                    flowRule.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(self.networkview.target.ip_addr)))
                    flowRule.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.networkview.target.eth_addr)))
                    #print("8 - " + str(h.decepted_eth_addr) + " --> " + str(self.networkview.target.eth_addr))
                    flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                    rules.append(flowRule)

                #deception server to target node
                #print("e - Create rule " + str(h.decepted_eth_addr) + " --> " + str(self.networkview.target.eth_addr) + " - " + str(self.networkview.target.switchPort))
                flowRule = nx.nx_flow_mod()
                flowRule.match.eth_src = EthAddr(str(h.decepted_eth_addr))
                flowRule.match.eth_dst = EthAddr(str(self.networkview.target.eth_addr))
                flowRule.hard_timeout = FLOW_TIMEOUT
                flowRule.priority = 1
                flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                rules.append(flowRule)

                #deception server to honeypot
                #print("f - Create rule " + str(h.decepted_eth_addr) + " --> " + str(h.eth_addr) + " - " + str(h.switchPort))
                flowRule = nx.nx_flow_mod()
                flowRule.match.eth_src = EthAddr(str(h.decepted_eth_addr))
                flowRule.match.eth_dst = EthAddr(str(h.eth_addr))
                flowRule.hard_timeout = FLOW_TIMEOUT
                flowRule.priority = 1
                flowRule.actions.append(of.ofp_action_output(port = int(h.switchPort)))
                rules.append(flowRule)

            #honeyrouter
            if h.isHoneypot==False and h.isRouter==True and h.eth_addr!=self.networkview.target.eth_addr:
                #print("g - Create rule " + str(self.networkview.target.eth_addr) + " --> " + str(h.ip_addr) + "/" + str(h.decepted_eth_addr) + " - " + str(h.switchPort))
                #print("Create rule " + str(h.decepted_ip_addr) + " --> " + str(h.ip_addr))
                flowRule = nx.nx_flow_mod()
                flowRule.match.of_eth_type = ethernet.IP_TYPE
                flowRule.match.eth_src = EthAddr(str(self.networkview.target.eth_addr))
                flowRule.match.eth_dst = EthAddr(str(h.decepted_eth_addr))
                flowRule.match.ip_dst = IPAddr(str(h.decepted_ip_addr))
                flowRule.hard_timeout = FLOW_TIMEOUT
                flowRule.priority = 1
                flowRule.actions.append(of.ofp_action_output(port = int(h.switchPort)))
                rules.append(flowRule)

                #print("h - Create rule " + str(h.decepted_eth_addr) + " --> " + str(self.networkview.target.eth_addr) + " - " + str(self.networkview.target.switchPort))
                #print("Create rule " + str(h.ip_addr) + " --> " + str(h.decepted_ip_addr))
                flowRule = nx.nx_flow_mod()
                flowRule.match.eth_src = EthAddr(str(h.decepted_eth_addr))
                flowRule.match.eth_dst = EthAddr(str(self.networkview.target.eth_addr))
                flowRule.hard_timeout = FLOW_TIMEOUT
                flowRule.priority = 1
                flowRule.actions.append(of.ofp_action_output(port = int(self.networkview.target.switchPort)))
                rules.append(flowRule)

        return rules

