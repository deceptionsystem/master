from Node import Node
from Route import Route

class NetworkView(object):

    def __init__(self, target, access, routes, gateway, server):
        self.target = target
        self.server = server
        self.access = access
        self.routes = routes
        self.gateway = gateway

    def hasAccess(self,node):
        for n in self.access:
            if n.eth_addr == node.eth_addr:
                return True
        return False

    def getRouteTo(self,node):
        for r in self.routes:
            if str(r.endNode.eth_addr) == str(node.eth_addr):
                return r
        return None

    def getRouteToIP(self,ip):
        for r in self.routes:
            if str(r.endNode.ip_addr) == str(ip):
                return r
        return None

    def getNodeByName(self,name):
        for n in self.access:
            if n.shortName == name:
                return n
        return None

    def getNodeByEth(self,eth_addr):
        for n in self.access:
            if str(n.eth_addr) == str(eth_addr) or str(n.decepted_eth_addr) == str(eth_addr):
                return n
        return None

    def getNodeByIP(self,ip_addr):
        for n in self.access:
            if str(n.ip_addr) == str(ip_addr):
                return n
        return None

    def getNodeByDecIP(self,ip_addr):
        for n in self.access:
            if str(n.decepted_ip_addr) == str(ip_addr):
                return n
        return None

    def canContact(self,src_ip,dst_ip):
        if str(src_ip)==str(self.target.decepted_ip_addr):
            for node in self.access:
                if str(node.decepted_ip_addr)==str(dst_ip):
                    return True
        return False