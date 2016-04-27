
class Honeypot(object):

    def __init__(self,name,ip,mac,dip,dmac,port):
        self.shortName=name
        self.realIP=ip
        self.realMacaddress=mac
        self.decIP=dip
        self.decMacaddress=dmac
        self.portNum=port

