from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet.ethernet import ethernet
import pox.lib.packet as pkt
import pox.lib.packet.arp as arp
import pox.lib.packet.icmp as icmp
import pox.lib.packet.tcp as tcp
import pox.lib.packet.ipv4 as ipv4
import pox.lib.packet.dns as dns
import pox.lib.packet.udp as udp
from pox.lib.addresses import IPAddr, EthAddr, IPAddr6
import time

log = core.getLogger()

class NCDS_DNS(object):

  def __init__ (self,connection,transparent):
    log.info("Init DNS handler")
    self.connection = connection
    self.transparent = transparent

  def handle_dns_packet(self, packet, event):
      dns_name = str(packet.questions[0].name)
      dns_type = packet.questions[0].qtype
      dns_class = packet.questions[0].qclass
      log.info("name " + dns_name + " type " + pkt.rrtype_to_str[dns_type] + " class " + pkt.rrclass_to_str[dns_class])
      log.info("Len " + str(len(packet.questions)))

      dns_reply = dns()
      dns_reply.qr = True
      dns_reply.rd = True
      dns_reply.ra = True

      answ = dns.rr("www.google.com",1,1,3600,4,IPAddr("1.1.1.1"))

      dns_reply.answers.append(answ)
      dns_reply.questions = packet.questions
      dns_reply.id = packet.id
      #dns_reply.total_questions = packet.total_questions
      #dns_reply.total_answers = 1

      udp_req = event.parsed.find("udp")
      udp_reply = udp()
      udp_reply.srcport = udp_req.srcport
      udp_reply.dstport = udp_req.dstport
      udp_reply.len = len(dns_reply) + udp_reply.MIN_LEN
      udp_reply.set_payload(dns_reply)

      ip_reply = ipv4()
      ip_req = event.parsed.find("ipv4")
      reqSrc = ip_req.dstip
      reqDst = ip_req.srcip
      ip_reply = ip_req
      ip_reply.srcip = reqDst
      ip_reply.dstip = reqSrc
      ip_reply.set_payload(udp_reply)

      eth_reply = ethernet()
      eth_reply.type = ethernet.IP_TYPE
      eth_reply.dst = EthAddr("00:00:00:00:00:02")
      eth_reply.src = EthAddr("00:00:00:00:00:01")
      eth_reply.set_payload(ip_reply)

      msg = of.ofp_packet_out()
      msg.data = eth_reply.pack()
      msg.actions.append(of.ofp_action_output(port = 2))
      msg.in_port = event.port
      self.connection.send(msg)
      log.info("send DNS response...")