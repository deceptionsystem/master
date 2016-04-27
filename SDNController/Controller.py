
from pox.core import core
import pox.openflow.nicira as nx
from pox.lib.util import str_to_bool
from pox.openflow.of_json import *
import pox.openflow.libopenflow_01 as of
from FlowCreator import FlowCreator
from ViewReader import ViewReader
from FlowConstructor import FlowConstructor
from pox.openflow.of_json import *
from viewfilestore import viewfilestore
from pox.lib.recoco import Timer
import os
import sys

log = core.getLogger()
nv_store = viewfilestore()

class Controller(object):

  def __init__ (self,connection,transparent):
    log.info("Init...")
    self.connection = connection
    self.transparent = transparent
    connection.addListeners(self)

    self.flowcreator = FlowCreator()
    self.netView = self.createFlowRules()
    self.flowConstructor = FlowConstructor()



  def _handle_PacketIn (self, event):
    packet = event.parsed
    #log.info("Packet from " + str(packet.src) + " to " + str(packet.dst))
    #self.flowdb.flowLookup(packet)
    self.flowConstructor.constructRule(self.netView,packet,event.port,self.connection,event)

  def createFlowRules(self):
    viewreader = ViewReader()
    print("Loaded network view from " + nv_store.getNVPath())
    viewfile = nv_store.getNVPath()
    nv = viewreader.readNetworkView(viewfile)
    return nv

class ncds_controller(object):
  def __init__ (self,transparent):
    core.openflow.addListeners(self)
    core.openflow.addListenerByName("FlowStatsReceived",self._handle_flowstats_received)
    core.openflow.addListenerByName("PortStatsReceived",self._handle_portstats_received)
    self.transparent = transparent
    viewreader = ViewReader()
    print("Loaded network view from " + nv_store.getNVPath())
    viewfile = nv_store.getNVPath()
    self.nv = viewreader.readNetworkView(viewfile)
    self.cntPackets=0
    self.cntBytes=0
    Timer(2, self._timer_func, recurring=True)


  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    Controller(event.connection, self.transparent)

  # handler to display flow statistics received in JSON format
  # structure of event.stats is defined by ofp_flow_stats()
  def _handle_flowstats_received (self,event):
    #log.info("flow stats!!!")
    stats = flow_stats_to_list(event.stats)
    from time import gmtime, strftime

    #log.debug("FlowStatsReceived from %s: %s",dpidToStr(event.connection.dpid), stats)
    #statistics = str(stats)
    #parts = statistics.split(",")
    #for p in parts:
    #  log.info("%s",p)

    hp_eth=""
    hp_ips=[]

    for node in self.nv.access:
      if node.isHoneypot:
        hp_eth = node.eth_addr
        hp_ips.append(node.decepted_ip_addr)
        #log.info("%s - %s",node.decepted_ip_addr,node.eth_addr)

    # Get number of bytes/packets in flows for web traffic only
    hp_bytes = 0
    hp_packets = 0
    for f in event.stats:
      if str(f.match.dl_dst)==str(hp_eth) or f.match.nw_dst in hp_ips:
        hp_bytes+=f.byte_count
        hp_packets+=f.packet_count
    #print("Node %s Honeypot Bytes %s, Packets %s",self.nv.target.decepted_ip_addr,hp_bytes,hp_packets)
    #print("View node " + str(self.nv.target.decepted_ip_addr) + " sent " + str(hp_bytes) + " Bytes and " + str(hp_packets) + " Packets to honeypots")

    #log.info("%s - %s",hp_packets,self.cntPackets)
    if hp_packets-self.cntPackets>0:
      #self.fileTimes.write("Scanner detected at " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\n")
      result="Scanner detected at " + str(self.nv.target.decepted_ip_addr) + " at " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\n"
      print(result)
      fileReport = open("/home/stefan/ScannerDetection.txt", 'a')
      fileReport.write(result)
      fileReport.close()

    self.cntPackets=hp_packets
    self.cntBytes=hp_bytes
    #log.info("Web traffic from %s: %s bytes (%s packets) over %s flows",dpidToStr(event.connection.dpid), web_bytes, web_packet, web_flows)

  # handler to display port statistics received in JSON format
  def _handle_portstats_received (self,event):
    #log.info("port stats!!!")
    stats = flow_stats_to_list(event.stats)
    #log.debug("PortStatsReceived from %s: %s",dpidToStr(event.connection.dpid), stats)

  def _timer_func(self):
    for connection in core.openflow._connections.values():
      connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
      connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))

def launch (transparent=False):
  #nvFile = str(raw_input("Enter view file:\n"))
  nvFile = "/home/stefan/Desktop/nv.nv"
  nv_store.setNVPath(nvFile)
  core.registerNew(ncds_controller, str_to_bool(transparent))
  log.info("NCDS SDN Controller running...")
