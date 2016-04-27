from Node import Node
from Route import Route
from NetworkView import NetworkView
class ViewReader(object):

    def __init__(self):
        #self.filename="/home/mininet/Desktop/nv.nv"
        print("View reader started...")


    def readNetworkView(self,filename):
        target = None
        access = []
        routes = []
        tempNodes = {}
        gateway = ""

        with open(filename) as file:
            lines = file.readlines()
            for line in lines:
                line = line.replace("\n","")
                args = line.split(",")
                if args[0] == "Target":
                    n = Node(args[1],args[2],args[3],args[4],args[4],False,False,False,args[5],args[6])
                    target = n
                    access.append(n)
                    tempNodes[args[1]] = n
                if args[0] == "Server":
                    n = Node(args[1],args[2],args[2],args[3],args[3],False,False,True,args[4],args[5])
                    server = n
                if args[0] == "Node":
                    n = Node(args[1],args[2],args[3],args[4],args[4],False,False,False,args[5],args[6])
                    access.append(n)
                    tempNodes[args[1]] = n
                if args[0] == "Honeypot":
                    hp = Node(args[1],args[2],args[3],args[4],args[5],True,False,False,args[6])
                    access.append(hp)
                    tempNodes[args[1]] = hp
                if args[0] == "Honeyrouter":
                    hr = Node(args[1],args[2],args[2],args[3],args[3],False,True,False,args[4])
                    access.append(hr)
                    tempNodes[args[1]] = hr
                if args[0] == "Route":
                    idxh=0
                    r = Route(tempNodes[args[1]],tempNodes[args[2]])
                    for h in args:
                        if idxh > 2:
                            r.addHop(tempNodes[h])
                        idxh+=1
                    routes.append(r)
                if args[0] == "Gateway":
                    gateway = tempNodes[args[1]]

        nv = NetworkView(target,access,routes,gateway,server)
        print("Generated network view for " +  str(target.decepted_ip_addr) + " on port " + str(target.switchPort))
        return nv