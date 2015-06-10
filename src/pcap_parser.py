import sys
import traceback
import dpkt
# from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

filename = sys.argv[1]

def parseWithDPKT(filename):
  pcapFile = dpkt.pcap.Reader(open(filename,'r'))

  class Packet(object):
    def __init__(self, ethernetPacket):
      self.ethernetPacket = ethernetPacket
      self.isDNS = self.unpack()

    def unpack(self, debug = False):
      if self.ethernetPacket.type != dpkt.ethernet.ETH_TYPE_IP:
        return False # DNS runs on top of IP

      # print self.dns

      self.ip = self.ethernetPacket.data
      if self.ip.p == dpkt.ip.IP_PROTO_UDP: # DNS runs over UDP
        self.udp = self.ip.data

        tb = None
        try:
          self.dns = dpkt.dns.DNS(self.udp.data)
          print "DNS query details: "
          print self.dns.qd
          print "number of RRs", len(self.dns.an)
          if len(self.dns.an) > 0: # each element in an is a RR answer
            print self.dns.an
            print "RR #1 name: ", self.dns.an[0].name
            print "RR #1 r(ecord) data: ", self.dns.an[0].rdata

          # print self.dns.data
          # print self.dns.id
          # print self.dns.op
          # print self.dns.ns # name servers
          # print self.dns.qr # query response, 1 bit
          # print self.dns.opcode # 4 bits
          # print self.dns.aa # authoritative answer, 1 bit
          # print self.dns.rd # recurse desired, 1 bit
          # print self.dns.ra # recursion available, 1 bit
          # print self.dns.zero # 1 bit
          # print self.dns.rcode # return code, 4 bits
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
        return True

  queries = []
  for ts, pkt in pcapFile:
    eth = dpkt.ethernet.Ethernet(pkt) 
    packet = Packet(eth)
    if packet.isDNS:
      queries.append(packet)

  print "Total queries: ", len(queries)

def parseWithScapy(filename):
  pkts = rdpcap(filename)

  for p in pkts:
    pkt_time = pkt.sprintf('%sent.time%')
    try:
      if DNSQR in pkt and pkt.dport == 53:
         print '[**] Detected DNS QR Message at: ', pkt_time
      elif DNSRR in pkt and pkt.sport == 53:
         print '[**] Detected DNS RR Message at: ', pkt_time
    except:
      pass

# if p.haslayer(DNS):   
#     if p.qdcount > 0 and isinstance(p.qd, DNSQR):
#         name = p.qd.qname
#     elif p.ancount > 0 and isinstance(p.an, DNSRR):
#         name = p.an.rdata
#     else:
#         continue

#     print name

# Run the 1st parser...
parseWithDPKT(filename)