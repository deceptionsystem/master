import subprocess
import time

while True:
    p = subprocess.Popen(['ovs-ofctl', 'dump-flows', 's1'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out, err = p.communicate()
    numFlows = len(out.split('\n')) - 2
    with open("flowcnt.txt", "a") as myfile:
        outstr = str(numFlows) + "\n"
        myfile.write(outstr)
    print ("Flows " + str(numFlows))
    time.sleep(1)
