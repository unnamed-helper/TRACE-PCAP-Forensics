import random, os, base64, sys
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap
random.seed(3); pk=[]; t=1760500000.0
for i in range(300):
    t+=random.uniform(.001,.01)
    cl=f"10.1.{i%12}.{10+i%40}"; lab=base64.b32encode(os.urandom(6)).decode().lower().strip("=")
    nm=f"{lab}.victim-zone.example"
    q=Ether()/IP(src=cl,dst="10.9.9.53")/UDP(sport=30000+i,dport=53)/DNS(id=i,rd=1,qd=DNSQR(qname=nm)); q.time=t; pk.append(q)
    t+=.001
    r=Ether()/IP(src="10.9.9.53",dst=cl)/UDP(sport=53,dport=30000+i)/DNS(id=i,qr=1,aa=1,rcode=3,qd=DNSQR(qname=nm)); r.time=t; pk.append(r)
wrpcap(sys.argv[1],pk); print(len(pk))
