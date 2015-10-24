#!/usr/bin/env python

import sys
import math
import statistics
import argparse
import itertools

from pcap_parser import *
from feature_extractor import *
from classifier import *

def build_extractors(dnsPackets):
    extractors = []

    extractors.append(QueryLengthFeatureExtractor(dnsPackets))
    extractors.append(QueryResolutionTimeFeatureExtractor(dnsPackets))
    extractors.append(QueryFrequencyFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
    extractors.append(TargetQueryFrequencyFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
    extractors.append(TargetNameFeatureExtractor(dnsPackets))
    extractors.append(TargetAddressFeatureExtractor(dnsPackets))
    extractors.append(QueryComponentDifferenceDiversityFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
    extractors.append(QueryEntropyDiversityFeatureExtractor(dnsPackets, params = {"window" : float(val)}))

    return extractors

def main(args):
    filenames = args.file
    dnsPackets = []
    for filename in filenames:
        parser = PacketParser(filename)
        packets = parser.parseDNS(filename)
        for packet in packets:
            dnsPackets.append(packet)

    extractors = build_extractors(dnsPackets)
    for num_of_extractors in range(1, len(extractors) + 1):
        for subset in itertools.combinations(extractors, num_of_extractors):
            output = extract(dnsPackets, subset)
            # TODO: send output to a file...

if __name__ == "__main__":
    desc = '''
Parse a PCAP file and extract a set of features for classification.
'''

    parser = argparse.ArgumentParser(prog='feature_extractor', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
    parser.add_argument('-f', '--file', action="store", required=True, help="Relative path to PCAP file to parse", nargs="+")

    args = parser.parse_args()
