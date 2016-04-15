import sys
import os
import gzip

from pcap_parser import *

domains = set()

for dirpath, dnames, fnames in os.walk(sys.argv[1]):
    for f in fnames:
        if f.endswith(".pcap.gz"):
            with gzip.open(f, 'rb') as fh:
                parser = PacketParser()
                packets = parser.parseDNS(fh)
                for packet in packets:
                    if packet.query != None:
                        domains.add(packet.query.name)