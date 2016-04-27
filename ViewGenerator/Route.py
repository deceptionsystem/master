
class Route(object):

    def __init__(self,start,end):
        self.startnode=start
        self.endnode=end
        self.hops=[]

    def addHop(self,hop):
        self.hops.append(hop)
