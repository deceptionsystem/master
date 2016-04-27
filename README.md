# NCDS - Network Cyber Deception System #

In case of any questions, bugs, comments or concerns please contact us at: ncds.deception@gmail.com
NCDS can be used under the terms of the Creative Commons (CC0) license.

Please note that the implementation details of this network cyber deception system are discussed in the research paper "Cyber Deception: Virtual Networks to Defend Reconnaissance".
The released implementation is a research prototype that gives a proof of concept of the discussed deception techniques. This implementation is not at the state to be released as a product which can be deployed in a production network.

### Before you start ###

Please make sure that you have Python, Scapy (version 2.3.2), POX and Mininet installed on your Linux system.
Please install the latest version of Scapy from here: http://www.secdev.org/projects/scapy/
If you install Scapy with "apt-get install python-scapy" you will only get version 2.2.0 which is significantly different from 2.3.2!

### Configure the virtual network view ###

Network view files (e.g. nv.nv) can be written manually or auto-generated with our *Virtual View Generator*.
A network view file (*.nv) contains the information ncessary to simulate a virtual network view.

The following values are stored in a network view file. Each line in a *.nv file starts with a component name.
A list of components for a virtual network view are:*Target, Server, Node, Honeypot, Honeyrouter, Route, Gateyway*
We provide a few examples of virtual network view files in the folder *ViewFileExamples*

The components are explained in detail as follows:

----------------------------------------
Target: The node in a network that has the current virtual network view applied to. A target node is configured as follows:
Target,*Shortname,DeceptiveIP,RealMAC,PortOnSDNSwitch,Visibility (always v for visible in case of the target)*

Example:
Target,h1,10.0.3.220,00:00:00:00:00:02,2,v

Only one target node can exists in a view file.

----------------------------------------
Server: The server specifies the IP, MAC address and port number where the deception server will be running. 
The location of the deception server is specified as follows:
Server,*Shortname,RealIP,RealMAC,PortOnSDNSwitch,Visibility (always v for visible in case of the server)*

Example:
Server,s,10.0.0.1,00:00:00:00:00:01,1,v

Only one deception server node can exists in a view file.

----------------------------------------
Node: A node component specifies all the other real hosts that are accessible by the target node. It is configured as follows:
Node,*Shortname,RealIP,DeceptiveIP,RealMAC,PortOnSDNSwitch,Visibility  (v for visible or nv for not visible)*

Example:
Node,h2,10.0.0.3,10.0.1.229,00:00:00:00:00:03,3,v

Multiple nodes can exists in a network view.

----------------------------------------
Honeypot: A honeypot specifies a fake node which acts as a trap for adversarial scanners.
A honeypot points to a port where a real end host is located that acts as a honeypot. Multiple honeypots in a network view can point to the same physical honeypot. A honeypot is configured as follows:

Honeypot,*Shortname,RealIP,DeceptiveIP,RealMAC,DeceptiveMAC,PortOnSDNSwitch*

Example:
Honeypot,hp2,10.0.0.5,10.0.1.24,00:00:00:00:00:05,b4:fb:5e:6c:2f:14,5 

Multiple honeypots can exists in a network view.

----------------------------------------
Honeyrouter: Honeyrouters specify virtual routers that connect nodes and honeypots in a virtual network view.
Multiple hops between nodes in a virtual network can be simulated with honeyrouters. A honeyrouter always has to point to the port on an SDN switch where the deception server is located.
A honeyrouter is configured as follows:

Honeyrouter,*Shortname,DeceptiveIP,DeceptiveMAC,PortToDeceptionServer*

Example:
Honeyrouter,hr1,10.0.3.1,4a:87:71:13:c8:43,1

Multiple honeyrouters can exists in a network view.

----------------------------------------
Route: A route specifies the topological path between different hosts in a network view.
A route can be configured as follows:

Route,*ShortnameOfStartNode,ShortnameOfEndNode,[Honeyrouter1, Honeyrouter2,...]*

A route has to consist of a start node, which can be a #Target, #Node or #Honeypot and 0 or more #Honeyrouters on the path between them.

Example:
Route,h1,h2,hr1,hr2

Multiple routes can exists in a network view.

----------------------------------------
Gateway: The gateway specifies the #Honeyrouter how the subnet where the #Target is located is connected to the rest of the virtual network. A gateway can be configured by pointing to the #Honeyrouter of the subnet of the target node:

Gateway, *HoneyrouterOfTargetSubnet*

Example:
Gateway,hr1

One one gateway can exist in a network view.

----------------------------------------

### Auto-Generate Virtual Network View Files ###

Before a network view file can be auto-generated, it has to be specified in the *Main.py* file, located in the "/ViewGenerator" directory.
<br />
The following code specifies a virtual network view file:

-------------------------------------------------------------
```python
RealHosts={}
RealHosts[1]="10.0.0.1/00:00:00:00:00:01/1/v" #realIP,realMAC,PortonSDNSwitch,Visibility
RealHosts[2]="10.0.0.2/00:00:00:00:00:02/2/v"
RealHosts[3]="10.0.0.3/00:00:00:00:00:03/3/v"
RealHosts[4]="10.0.0.4/00:00:00:00:00:04/4/v"
RealHosts[5]="10.0.0.5/00:00:00:00:00:05/5/v"
RealHosts[6]="10.0.0.6/00:00:00:00:00:06/6/nv"

SubnetSpace="10.168.1"

NCDSIndex=1
TargetIndex=2
HoneyPotIndex=3

NCDSPort=int(RealHosts[NCDSIndex].split("/")[2])
TargetPort=int(RealHosts[TargetIndex].split("/")[2])
HoneyPort=int(RealHosts[HoneyPotIndex].split("/")[2])

NumberSubnets=10
MinNumHoneyPotsInSubnet=12
MaxNumHoneyPotsInSubnet=22
MaxSubnets=48
MaxHosts=255

#Strategy="even_dist"
#Strategy="crowded_dist"
Strategy="random_dist"

```
-------------------------------------------------------------

A view starts with a list of IP and MAC addresses of real hosts that will be accessible in a virtual network view.
<br />
- The "SubnetSpace" variable specifies to subnetwork prefix of a subnet in the virtual network view (starting with first subnet prefix).
- The "NCDSIndex" specifies the index of the deception server in the list of real hosts.
- The "TargetIndex" specifies the index of the target host in the list of real hosts.
- The "HoneyPotIndex" specifies the index of the honeypot server in the list of real hosts.
- The "NumberSubnets" specifies how many subnets will be simulated in a virtual network view.
- The "MinNumHoneyPotsInSubnet" and "MaxNumHoneyPotsInSubnet" specfies a range of how many honeypots should be located in each virtual subnet.
- The "MaxSubnets" variable specifies the maximum IP address prefix of a sunbet address, for example MaxSubnets=48 specifies a maximum subnet address of "10.0.48.0/24" in the given example (255 is the maximum value for this variable).
- The "MaxHosts" variable specifies the maximum address number of a deceptive host IP address that will be assigned to a host in a virtual network view. For example MaxHosts=255 would result in a maximum IP address of "10.0.48.255" in the given example (255 is the maximum value for this variable). 
- The "Strategy" value specifies the strategy how real visible hosts are distributed over the topology of a virtual network view, the options are random, crowded or even distribution between subnets.
<br />


After a network view file is configured the system can be started as follows:

### Start the SDN Controller ###

Copy the SDN Controller directory into the POX folder (e.g. /home/mininet/pox/pox/SDNController_ncds)
With the following command the SDN controller has to be started on a terminal: "./pox.py log.level --DEBUG SDNController_ncds.Controller"
Here "SDNController_ncds" is the directory of the NCDS SDN controller, "Controller" is the python file of the NCDS SDN controller. 
Upon startup the SDN controller will prompt the user to enter the path to the network view file, the same .nv file as for entered for the deception server has to be used.

### Start the deception server ###

To begin the Mininet network emulator has to be started. As an example the command "sudo mn --topo=single,12 --mac --controller=remote" Mininet starts emulating a network with a single SDN switch and 12 nodes. The controller is specified as remote and will automatically connect with the POX NCDS SDN controller. The option --mac will set the MAC addresses of nodes in increasing order starting at "00:00:00:00:00:01". By default the IP address of nodes in Mininet is starting at "10.0.0.1" and increasing.
<br />

After Mininet is started and connected to the SDN NCDS controller, the controller will automatically start reading the network view file and loading the appropriate SDN flow rules into the SDN switch of the subnet where the target node is located.
<br />

In a Mininet-Environment, the deception server has to be started at the node which is located on port 1 of the SDN switch (this option can be changes in the source code). The deception server has to be started with root privileges. To start the deception server in the terminal of the node located at port 1 type for example: "/home/mininet/DeceptionServer# python main.py"
Upon startup the deception server will prompt the user to enter the path to the network view file, the same .nv file as for entered for the SDN controller has to be used.
<br />

After the server is running a terminal at the target node, e.g. node that is located on port 2 of the SDN switch, has to request a DHCP lease to be able to connect to the network. This should be done by executing the following commands on the node located on port 2: "dhclient -r" (will release the current DHCP lease), "dhclient h2-eth0" (will request a new DHCP lease from the deception server at the specified network interface (here "h2-eth0").
<br />

Now the network will appear to the target node as specified in the network view file. This can be evaluated by scanning the network with a tool like NMAP (or ZenMAP to visualize the virtual topology). To map a virtual network, as specified in our example view file "nv.nv" ZenMAP can be started with the following command: "nmap -T4 -A -v --traceroute 10.0.1.0/24 10.0.2.0/24 10.0.3.0/24"
<br />

The target node is able to connect to the specified *Nodes* in the same way as in a normal network.

