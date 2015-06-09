import sys
import dpkt

filename = sys.argv[1]
pcapFile = dpkt.pcap.Reader(open(filename,'r'))

class Query(object):
  def __init__(self, ethernetPacket):
    self.ethernetPacket = ethernetPacket
    self.unpack()

  def unpack(self):
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
    continue

  ip = eth.data
  tcp = ip.data
    pass

for ts, pkt in pcapFile:
  eth = dpkt.ethernet.Ethernet(pkt) 
  query = Query(eth)

  # if ip.p == dpkt.ip.IP_PROTO_TCP: 
