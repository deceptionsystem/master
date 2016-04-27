class LoggingPrinter(object):

    #def __init__ (self):


    def logRule(self,rule,type):
        eth_src=None
        eth_dst=None
        ip_src=None
        ip_dst=None
        ttl_cnt=None

        log=""

        if rule.match.eth_src!=None:
            eth_src=rule.match.eth_src
            log=log+" from " + str(eth_src)
        if rule.match.eth_dst!=None:
            eth_dst=rule.match.eth_dst
            log=log+" to " + str(eth_dst)
        if rule.match.ip_src!=None:
            ip_src=rule.match.ip_src
            log=log+" from " + str(ip_src)
        if rule.match.ip_dst!=None:
            ip_dst=rule.match.ip_dst
            log=log+" to " + str(ip_dst)
        if rule.match.NXM_NX_IP_TTL!=None:
            ttl_cnt=rule.match.NXM_NX_IP_TTL
            log=log+" with TTL " + str(ttl_cnt)

        outport=""
        for r in rule.actions:
            if hasattr(r,'port'):
                outport=r.port

        #print("Created " + str(type) + " flow rule for" + str(log) + " to output switch port " + str(outport))
