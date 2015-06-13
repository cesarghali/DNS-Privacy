import sys
from pcap_parser import *

# DONE 1. Relative (per-user) query length
# 2. Relative source query frequency
# 3. Relative target query frequency 
# 4. Query resolution length (time)
# 5. Reverse DNS entry IP address ranges
# 6. Query source-target association (e.g., client/stub-recursive association)
# 7. Query source identity (address)
# 8. Query target identity (address)
# 9. Query diversity (character differences, URI component differences, etc.)
# 10. Resolution chain length (number of recursive queries)
# 11. Resolution chain (domains in the chain itself)
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

class QueryResolutionTimeFeatureExtractor(FeatureExtractor):
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self):
        features = []
        sources = []

        for packet in self.queries:
            if packet.query != None:
                src = packet.query.srcAddress
                print packet.records, packet.index
                for response in self.queries:
                    # dst = response.query.dstAddress, response.query.srcAddress
                    # print src, dst
                    if len(response.records) > 0:
                        match = response.records[0]
                        # print packet.ts

        return features

class QueryFrequencyFeatureExtractor(FeatureExtractor):
    def __init__(self, queries):
        FeatureExtractor.__init__(self, queries)

    def extract(self):
        features = []
        sources = []

        # Q: feature is a user ID and then his relative frequency? How do we determine the frequency?
        for packet in self.queries:
            pass 

        return features
  
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

if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print >> sys.stderr, "usage: python feature_extractor.py <pcap file>"
        sys.exit(-1)
        
    filename = sys.argv[1]
    print >> sys.stderr, "Parsing...", filename
    
    dnsPackets = parse(filename)
    # extractor = QueryLengthFeatureExtractor(dnsPackets)
    extractor = QueryResolutionTimeFeatureExtractor(dnsPackets)
    features = extractor.extract()
    formatter = FeatureFormatter(features)
    print formatter.toCSV(sys.stdout)

    print >> sys.stderr, "Done. Parsed %d DNS packets" % len(dnsPackets)

