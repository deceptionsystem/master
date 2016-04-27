
class Route(object):

    def __init__(self,startNode=None,endNode=None):
        self.startNode = startNode
        self.endNode = endNode
        self.hops = []
        self.hops.append(self.startNode)
        self.hops.append(self.endNode)

    def addHop(self,node):
        routeLen = len(self.hops)
        endNode = self.hops[routeLen-1]
        self.hops[routeLen-1] = node
        self.hops.append(endNode)


