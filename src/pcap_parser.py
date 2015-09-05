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
        self._unpack()

    def _unpack(self):
        self.target = self.rr.name
        self.type = self.rr.type

        # Parse the RR type (see https://en.wikipedia.org/wiki/List_of_DNS_record_types)
        if self.rr.type == 5:
            # print "CNAME request", rr.name, "\tresponse", rr.cname
            self.cname = self.rr.cname
        elif self.rr.type == 1:
            # print "Type 1 Request", rr.name, "\tresponse", socket.inet_ntoa(rr.rdata)
            self.targetAddress = socket.inet_ntoa(self.rr.rdata)
        elif self.rr.type == 12:
            # print "PTR request", rr.name, "\tresponse", rr.ptrname
            self.ptrname = self.rr.ptrname

class Query(object):
    def __init__(self, ip, dns, query):
        self.ip = ip
        self.query = query
        self.dns = dns
        self.srcAddress = socket.inet_ntoa(ip.src)
        self.dstAddress = socket.inet_ntoa(ip.dst)
        self._unpack()

    def _unpack(self):
        self.name = self.query.name
        self.id = self.dns.id
        self.qr = self.dns.qr
        self.type = self.query.type

class DNSPacket(object):
    def __init__(self, index, ethernetPacket, ts):
        self.ethernetPacket = ethernetPacket
        self.query = None
        self.records = []
        self.ts = ts
        self.index = index
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

                # QR = 0, query
                # QR = 1, response
                if self.dns.qr == 0:
                    self.query = Query(self.ip, self.dns, self.dns.qd[0])
                else:
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


class PacketParser(object):
    def __init__(self, filename):
        self.filename = filename

    def parseDNS(self, filename):
        pcapFile = dpkt.pcap.Reader(open(filename,'r'))

        dnsPackets = []
        index = 0
        for ts, pkt in pcapFile:
            eth = dpkt.ethernet.Ethernet(pkt)
            packet = DNSPacket(index, eth, ts)
            if packet.isDNS:
                dnsPackets.append(packet)
            index = index + 1

        return dnsPackets
