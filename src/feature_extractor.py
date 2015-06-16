#!/usr/bin/env python

import sys
import math
import statistics
import argparse
from pcap_parser import *

#### DONE
# DONE 1. Relative (per-user) query length
# DONE 2. Relative source query frequency
# DONE 3. Relative target query frequency 
# DONE 4. Query resolution length (time)
# REMOVED -- not needed 7. Query source identity (address)
# DONE 8. Query target address 
# ADDED: Query target name (different from above since a name could map to different addresses)
# DONE 7. Query diversity entropy
# DONE 9. Query diversity stddev 

#### TODO
### 5. Reverse DNS entry IP address ranges
### 6. Query source-target association (e.g., client/stub-recursive association)
# -. Query diversity number of URI component differences

#### Requires more than one PCAP file (into and out of a resolver)
# 10. Resolution chain length (number of recursive queries)
# 11. Resolution chain (domains in the chain itself)

#### More sophisticated
# 12. Monitoring reply from cache (Adv controls in/out links of R and can know if something is served from cache even if the source of the query is anonymised)

class FeatureFormatter(object):
    ''' Class that formats lists of features for the output
    '''
    def __init__(self, features):
        self.features = features # list of tuples

    def toCSV(self, stream):
        for f in self.features:
            stream.write(",".join(map(lambda x : str(x), f)) + "\n")

class FeatureExtractor(object):
    ''' Base class for all feature extractors.
    '''
    def __init__(self, queries):
        self.queries = queries

    def extract(self):
        pass

class TestFeatureExtractor(FeatureExtractor):
    ''' Template for new feature extractors
    '''
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self):
        features = []
        sources = {}

        for packet in self.queries:
            pass

        return features, sources

class QueryComponentDifferenceDiversityFeatureExtractor(FeatureExtractor):
    ''' Template for new feature extractors
    '''
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self, prams = {"window" : 0.05}):
        features = []
        sources = {}

        window = params["window"]

        i = 0
        while i < len(self.queries):
            packet = self.queries[i]
            offset = i + 1

            if packet.query != None:
                src = packet.query.srcAddress
                targetName = packet.query.name
                queriesSent = []
                start = packet.ts
                end = 0
                j = offset
                while j < len(self.queries):
                    nextPacket = self.queries[j]

                    # if the next packet was a query and issued by the same IP
                    if nextPacket.query != None and nextPacket.query.srcAddress == src:

                        # Check to see if it was issued for a different target, and if so, we start from here next time
                        if nextPacket.query.srcAddress == src:
                            queriesSent.append(nextPacket.query)

                        # else, add it to the list if the name matches the original target name
                        end = nextPacket.ts
                        if end - start > window:
                            break
                            
                    j += 1

                offset = j

                # compute the count of each query name/target (by *exact* match)
                prob = {}
                total = 0
                for query in queriesSent:
                    if query.name not in prob:
                        prob[query.name] = 0
                        total += 1
                    prob[query.name] += 1 

                # compute the stddev
                ps = []
                for name in prob:
                    p = float(prob[name]) / float(total)
                    ps.append(p)
                stddev = statistics.stdev(ps)

                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], stddev)
                features.append(feature)

            i = offset

        return features, sources

class QueryEntropyDiversityFeatureExtractor(FeatureExtractor):
    ''' Template for new feature extractors
    '''
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self, prams = {"window" : 0.05}):
        features = []
        sources = {}

        window = params["window"]

        i = 0
        while i < len(self.queries):
            packet = self.queries[i]
            offset = i + 1

            if packet.query != None:
                src = packet.query.srcAddress
                targetName = packet.query.name
                queriesSent = []
                start = packet.ts
                end = 0
                j = offset
                while j < len(self.queries):
                    nextPacket = self.queries[j]

                    # if the next packet was a query and issued by the same IP
                    if nextPacket.query != None and nextPacket.query.srcAddress == src:

                        # Check to see if it was issued for a different target, and if so, we start from here next time
                        if nextPacket.query.srcAddress == src:
                            queriesSent.append(nextPacket.query)

                        # else, add it to the list if the name matches the original target name
                        end = nextPacket.ts
                        if end - start > window:
                            break
                            
                    j += 1

                offset = j

                # compute the count of each query name/target (by *exact* match)
                prob = {}
                total = 0
                for query in queriesSent:
                    if query.name not in prob:
                        prob[query.name] = 0
                        total += 1
                    prob[query.name] += 1 

                # compute the entropy
                # H= -\sum p(x) log p(x)
                acc = 0
                for name in prob:
                    p = float(prob[name]) / float(total)
                    logp = math.log(p)
                    acc += (p * logp)
                entropy = acc * -1

                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], entropy)
                features.append(feature)

            i = offset

        return features, sources

class TargetQueryFrequencyFeatureExtractor(FeatureExtractor):
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self, params = {"window" : 0.05}):
        sources = {}
        features = []

        window = params["window"]

        i = 0
        while i < len(self.queries):
            packet = self.queries[i]
            offset = i + 1

            if packet.query != None:
                src = packet.query.srcAddress
                targetName = packet.query.name
                numberOfQueries = 1 
                start = packet.ts
                end = 0
                j = offset
                while j < len(self.queries):
                    nextPacket = self.queries[j]

                    # if the next packet was a query and issued by the same IP
                    if nextPacket.query != None and nextPacket.query.srcAddress == src:

                        # Check to see if it was issued for a different target, and if so, we start from here next time
                        if nextPacket.query.name != targetName and offset != (i + 1): 
                            offset = j # set the next query from which to start

                        # else, add it to the list if the name matches the original target name
                        end = nextPacket.ts
                        if end - start > window:
                            break
                        elif nextPacket.query.name == targetName:
                            numberOfQueries += 1
                    j += 1

                frequency = float(numberOfQueries) / float(window)

                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], frequency)
                features.append(feature)

            i = offset

        return features, sources

class QueryFrequencyFeatureExtractor(FeatureExtractor):
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self, params = {"window" : 0.05}):
        features = []
        sources = {}

        window = params["window"]

        i = 0
        while i < len(self.queries):
            packet = self.queries[i]
            offset = i + 1
            if packet.query != None:
                src = packet.query.srcAddress
                numberOfQueries = 1 
                start = packet.ts
                end = 0
                j = offset
                while j < len(self.queries):
                    nextPacket = self.queries[j]
                    if nextPacket.query != None:

                        # this next packet is the start of a new window, so record this offset
                        if nextPacket.query.srcAddress != src and offset != (i + 1):
                            offset = j

                        # check to see if the src address is the same, and if so, it contributes
                        elif nextPacket.query.srcAddress == src:
                            end = nextPacket.ts
                            if end - start > window:
                                break
                            else:
                                numberOfQueries += 1
                    j += 1

                frequency = float(numberOfQueries) / float(window)              

                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], frequency)
                features.append(feature)
            i = offset
        return features, sources

class TargetAddressFeatureExtractor(FeatureExtractor):
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self):
        features = []
        sources = {}

        for packet in self.queries:
            for record in packet.records:
                src = record.srcAddress
                if record.targetAddress != None:
                    target = record.targetAddress

                    if src not in sources:
                        sources[src] = len(sources)
                    feature = (sources[src], target)

                    features.append(feature)

        return features, sources

class TargetNameFeatureExtractor(FeatureExtractor):
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self):
        features = []
        sources = {}

        for packet in self.queries:
            if packet.query != None:
                src = packet.query.srcAddress
                target = packet.query.name
                if src not in sources:
                    sources[src] = len(sources)
                feature = (sources[src], target)

                features.append(feature)

        return features, sources

class QueryResolutionTimeFeatureExtractor(FeatureExtractor):
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self):
        features = []
        sources = {}

        for packet in self.queries:

            # Match queries to responses, so only start searching from queries
            if packet.query != None:
                src = packet.query.srcAddress
                target = packet.query.name
                for response in self.queries:
                    if len(response.records) > 0 and response.records[0].target == target:
                        match = response.records[0]
                        delta = response.ts - packet.ts
                        if delta > 0:
                            if src not in sources:
                                sources[src] = len(sources) 
                            feature = (sources[src], delta)

                            features.append(feature)

        return features, sources
  
class QueryLengthFeatureExtractor(FeatureExtractor):
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self):
        sources = {}
        features = []

        for packet in self.queries:
            src = None

            queryLength = -1
            if packet.query != None:
                src = packet.query.srcAddress
                queryLength = len(packet.query.name)
            if len(packet.records) > 0:
                src = packet.records[0].dstAddress
                queryLength = len(packet.records[0].target)

            if src not in sources:
                sources[src] = len(sources) 
            feature = (sources[src], queryLength)

            features.append(feature)
        print sources
        return features, sources

if __name__ == "__main__":
    desc = '''
Parse a PCAP file and extract a set of features for classification.
'''

    parser = argparse.ArgumentParser(prog='feature_extractor', formatter_class=argparse.RawDescriptionHelpFormatter, description=desc)
    parser.add_argument('-f', '--file', action="store", required=True, help="Relative path to PCAP file to parse")
    parser.add_argument('--ql', default=False, action="store_true", help="Query length feature")
    parser.add_argument('--qrt', default=False, action="store_true", help="Query resolution time feature")
    parser.add_argument('--qf', action="store", help="Query frequency with parameterized window")
    parser.add_argument('--tf', action="store", help="Source target frequency with parameterized window")
    
    # TODO: add other features to the cmdline as needed

    args = parser.parse_args()

    if (len(sys.argv) == 1):
        parser.print_help()
        sys.exit(-1)
        
    filename = args.file
    print >> sys.stderr, "Parsing...", filename
    
    parser = PacketParser(filename)
    dnsPackets = parser.parseDNS(filename)

    # Run each specified extractor over the packets
    featureSet = []
    sourceSet = []
    for key in vars(args):
        val = vars(args)[key]
        features = []
        sources = []

        if key == "ql" and val:
            extractor = QueryLengthFeatureExtractor(dnsPackets)
            features, sources = extractor.extract()
        elif key == "qrt" and val:
            extractor = QueryResolutionTimeFeatureExtractor(dnsPackets) 
            features, sources = extractor.extract()
        elif key == "qf" and val != None:
            extractor = QueryFrequencyFeatureExtractor(dnsPackets)
            extractor = TargetQueryFrequencyFeatureExtractor(dnsPackets)
        elif key == "tf" and val != None:
            extractor = TargetQueryFrequencyFeatureExtractor(dnsPackets)
            features, sources = extractor.extract()

        featureSet.append(features)
        sourceSet.append(features)

        formatter = FeatureFormatter(features)
        print formatter.toCSV(sys.stdout)

    print >> sys.stderr, "Done. Parsed %d DNS packets" % len(dnsPackets)

