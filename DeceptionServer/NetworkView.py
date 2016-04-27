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
            if n.decepted_eth_addr == node.eth_addr:
                return True
        return False

    def getRouteTo(self,node):
        for r in self.routes:
            if r.endNode.decepted_eth_addr == node.eth_addr:
                return r
        return None

    def getRouteToIP(self,ip):
        for r in self.routes:
            if r.endNode.decepted_ip_addr == ip:
                return r
        return None

    def getNodeByName(self,name):
        for n in self.access:
            if n.shortName == name:
                return n
        return None

    def getNodeByEth(self,eth_addr):
        for n in self.access:
            if n.eth_addr == eth_addr:
                return n
        return None

    def getNodeByDeceptedEth(self,eth_addr):
        for n in self.access:
            if n.decepted_eth_addr == eth_addr:
                return n
        return None

    def getNodeByIP(self,ip_addr):
        for n in self.access:
            if n.decepted_ip_addr == ip_addr:
                return n
        return None