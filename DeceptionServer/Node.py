
class Node(object):

    def __init__(self,shortName=None,ip_addr=None,decepted_ip_addr=None,eth_addr=None,decepted_eth_addr=None,isHoneypot=False,isRouter=False,isServer=False,switchPort=0,visible="nv"):
        self.shortName = shortName
        self.ip_addr = ip_addr
        self.decepted_ip_addr = decepted_ip_addr
        self.eth_addr = eth_addr
        self.decepted_eth_addr = decepted_eth_addr
        self.switchPort = switchPort
        self.isHoneypot = isHoneypot
        self.isRouter = isRouter
        self.isServer = isServer
        self.visible = visible