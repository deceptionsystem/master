from Subnet import Subnet
from Honeypot import Honeypot
from Host import Host
from Honeyrouter import Honeyrouter

class NetworkPrinter(object):
    def __init__(self):
        self.viewtext=""
        self.realhosts=[]

    def printView(self,target,server,subnet,routes,targetPort,gateway):

        self.viewtext = self.viewtext + ("Target," + str(target.shortName) + "," + str(target.realIP) + "," + str(target.deceptiveIP) + "," + str(target.macaddress) + "," + str(target.portNum) + "," + str(server.visible) + "\n")
        self.viewtext = self.viewtext + ("Server," + str(server.shortName) + "," + str(server.realIP) + "," + str(server.macaddress) + "," + str(server.portNum) + "," + str(server.visible) + "\n")
        print("Generated network view for " + target.realIP + " -> " + target.deceptiveIP)
        for subKey in subnet.keys():
            for host in subnet[subKey].hosts:
                if host.portNum != targetPort:
                    self.viewtext = self.viewtext + ("Node," + str(host.shortName) + "," + str(host.realIP) + "," + str(host.deceptiveIP) + "," + str(host.macaddress) + "," + str(host.portNum) + "," + str(host.visible) + "\n")
                    self.realhosts.append(host.deceptiveIP)
        for subKey in subnet.keys():
            for honeypot in subnet[subKey].honeypots:
                self.viewtext = self.viewtext + ("Honeypot," + str(honeypot.shortName) + "," + str(honeypot.realIP) + "," + str(honeypot.decIP) + "," + str(honeypot.realMacaddress) + "," + str(honeypot.decMacaddress) + "," + str(honeypot.portNum) + "\n")
        for subKey in subnet.keys():
            for honeyrouter in subnet[subKey].honeyrouter:
                self.viewtext = self.viewtext + ("Honeyrouter," + str(honeyrouter.shortName) + "," + str(honeyrouter.decIP) + "," + str(honeyrouter.decMacaddress) + "," + str(honeyrouter.portNum) + "\n")

        for route in routes:
            r=""
            r="Route," + str(route.startnode.shortName) + "," + str(route.endnode.shortName)
            for hop in route.hops:
                r=r + "," + str(hop.shortName)
            self.viewtext = self.viewtext + (r + "\n")
        self.viewtext = self.viewtext + ("Gateway," + str(gateway) + "\n")

        fileView = open('/home/mininet/nv.nv','w')
        fileView.write(self.viewtext)
        fileView.close()

        return self.realhosts
        #print (self.viewtext)
