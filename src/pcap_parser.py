import sys
import traceback
import dpkt
import ipaddress
import socket
import csv

class ResourceRecord(object):
  def __init__(self, ip, rr):
    self.ip = ip
    self.rr = rr
    self.srcAddress = socket.inet_ntoa(ip.src)
    self.dstAddress = socket.inet_ntoa(ip.dst)
    self.rrTargetAddress = ipaddress.IPv4Address(self.dns.an[0].rdata)

class Query(object):
  def __init__(self, ip, query):
    self.ip = ip
    self.srcAddress = socket.inet_ntoa(ip.src)
    self.dstAddress = socket.inet_ntoa(ip.dst)
    self.query = query
    self.name = query.name

class FeatureFormatter(object):
  def __init__(self, features):
    self.features = features # list of tuples

  def toCSV(self, stream):
    for f in self.features:
      stream.write(",".join(map(lambda x : str(x), f)) + "\n")

class FeatureExtractor(object):
  def __init__(self, queries):
    self.queries = queries

  def extract(self):
    pass

class QueryLengthFeatureExtractor(FeatureExtractor):
  def __init__(self, queries):
    FeatureExtractor.__init__(self, queries)

  def extract(self):
    sources = {}
    features = []

    for packet in self.queries:
      src = None
      if packet.query != None:
        src = packet.query.srcAddress
      if len(packet.records) > 0:
        src = packet.query.dstAddress

      queryLength = len(packet.query.name)

      if src not in sources:
        sources[src] = len(sources) 
      feature = (sources[src], queryLength)

      features.append(feature)
    return features

def parse(filename):
  pcapFile = dpkt.pcap.Reader(open(filename,'r'))

  dnsPackets = []
  for ts, pkt in pcapFile:
    eth = dpkt.ethernet.Ethernet(pkt) 
    packet = Packet(eth)
    if packet.isDNS:
      dnsPackets.append(packet)

  return dnsPackets

class Packet(object):
  def __init__(self, ethernetPacket):
    self.ethernetPacket = ethernetPacket
    self.query = None
    self.records = []
    self.isDNS = self.unpack()

  def unpack(self, debug = False):
    if self.ethernetPacket.type != dpkt.ethernet.ETH_TYPE_IP:
      return False # DNS runs on top of IP

    self.ip = self.ethernetPacket.data
    if self.ip.p == dpkt.ip.IP_PROTO_UDP: # DNS runs over UDP
      self.udp = self.ip.data

      tb = None
      try:
        self.dns = dpkt.dns.DNS(self.udp.data)

        if len(self.dns.an) == 0:
          self.query = Query(self.ip, self.dns.qd[0])

        self.records = []
        for rr in self.dns.an:
          self.records.append(ResourceRecord(self.ip, rr))
        return True
      except Exception as e:
        isDns = False
        tb = traceback.format_exc()
        if debug:
          print >> sys.stderr, str(e)
      finally:
        if tb != None and debug:
          print tb
    else:
      return False

if __name__ == "__main__":
  if (len(sys.argv) != 2):
    print >> sys.stderr, "usage: python pcap_parser.py <pcap file>"
    sys.exit(-1)
    
  filename = sys.argv[1]
  print >> sys.stderr, "Parsing...", filename
  
  dnsPackets = parse(filename)
  extractor = QueryLengthFeatureExtractor(dnsPackets)
  features = extractor.extract()
  formatter = FeatureFormatter(features)
  print formatter.toCSV(sys.stdout)

  print >> sys.stderr, "Done. Parsed %d DNS packets" % len(dnsPackets)