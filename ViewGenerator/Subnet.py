

class Subnet(object):

    def __init__(self,subnetNum):
        self.number=subnetNum
        self.hosts=[]
        self.honeypots=[]
        self.honeyrouter=[]
        self.gateway=""
        self.hostNums=[]