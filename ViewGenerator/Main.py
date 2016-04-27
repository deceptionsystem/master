from GeneratorVirtualView import GenerateVirtualView

RealHosts={}

RealHosts[1]="10.0.0.1/00:00:00:00:00:01/1/v"
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

GenView = GenerateVirtualView(MaxSubnets,MaxHosts)
(realhosts, target) = GenView.generatgeView(RealHosts,SubnetSpace,TargetPort,NCDSPort,HoneyPort,HoneyPotIndex,NumberSubnets,MinNumHoneyPotsInSubnet,MaxNumHoneyPotsInSubnet,Strategy)
