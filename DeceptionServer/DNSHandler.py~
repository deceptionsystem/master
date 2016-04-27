from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dns import *

from dnslib import *

class DNSHandler(object):

    def __init__(self):
        print "initiated DNS..."

    def handleDNSPacket(self, pkt):

        #print(pkt.show())
        dp=pkt[0][IP][UDP].dport
        sp=pkt[0][IP][UDP].sport

        ether = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
        ip = IP(dst="10.168.0.10", src="10.168.0.11")
        udp = UDP(sport=dp,dport=sp)
        dns = DNS(qr=1,id=pkt[0][IP][DNS].id,qd=DNSQR(qname=pkt[0][IP][DNS][DNSQR].qname),an=(DNSRR(rrname=pkt[0][IP][DNS][DNSQR].qname,rdata="10.168.0.3",ttl=3600,rclass="IN",type="A")),ar=1) #DNSRROPT(rclass=3000)

        response = ether/ip/udp/dns

        #response = IP(dst="8.8.8.8")/UDP(sport=pkt[UDP].dport)/DNS(rd=1,qr=1,ra=1,id=pkt[0][IP][DNS].id,qd=DNSQR(qname=pkt[0][IP][DNS][DNSQR].qname))

        print("ANSWER")
        #print(response.show())
        return response