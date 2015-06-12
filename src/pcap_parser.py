import sys
import traceback
import dpkt
import ipaddress
import socket

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
