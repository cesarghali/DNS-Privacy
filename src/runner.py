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
    extractors.append(TargetNameFeatureExtractor(dnsPackets))
    extractors.append(TargetAddressFeatureExtractor(dnsPackets))

    extractors.append(QueryComponentDifferenceDiversityFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
    extractors.append(QueryEntropyDiversityFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
    extractors.append(QueryFrequencyFeatureExtractor(dnsPackets, params = {"window" : float(val)}))
    extractors.append(TargetQueryFrequencyFeatureExtractor(dnsPackets, params = {"window" : float(val)}))

    return extractors

def run_classifiers(data):
    testPercentage = 0.1
    iterations = 1000
    options = ""

    numberOfUsers = np.amax([map(float, column[1:]) for column in data][0:len(data)])

    classifiers = "sgd, tree, svm, logistic".split(",")

    for num_of_classifiers in range(1, len(classifiers) + 1):
        for subset in itertools.combinations(classifiers, num_of_classifiers):
            classifier_subset = ",".join(subset)
            errorRate, startTime, endTime = run(data, numberOfUsers, testPercentage, classifier_subset, iterations, options)

            print >> sys.stderr, ""
            print >> sys.stderr, "Execution time: " + str(datetime.timedelta(seconds=(endTime - startTime)))
            print >> sys.stderr, "Error rate: " + str(errorRate / iterations)
            print >> sys.stderr, "Number of users: " + str(numberOfUsers)
            print >> sys.stdout, fileName + "\t" +\
                classifier_subset + "\t" +\
                options + "\t" +\
                str(datetime.timedelta(seconds=(endTime - startTime))) + "\t" +\
                str(errorRate / iterations) + "\t" +\
                str(numberOfUsers)

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
            features = extract(dnsPackets, subset)
            run_classifiers(features)

if __name__ == "__main__":
    desc = '''
Parse a PCAP file and extract a set of features for classification.
'''
    parser = argparse.ArgumentParser(prog='feature_extractor', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
    parser.add_argument('-f', '--file', action="store", required=True, help="Relative path to PCAP file(s) to parse", nargs="+")

    args = parser.parse_args()
    main(args)
