import sys
from pcap_parser import *

# DONE 1. Relative (per-user) query length
# DONE 2. Relative source query frequency
# IN PROGRESS 3. Relative target query frequency 
# DONE 4. Query resolution length (time)
# 5. Reverse DNS entry IP address ranges
# 6. Query source-target association (e.g., client/stub-recursive association)
# REMOVED -- not needed 7. Query source identity (address)
# DONE 8. Query target address 
# ADDED: Query target name (different from above since a name could map to different addresses)
# 9. Query diversity (character differences, URI component differences, etc.)
# 10. Resolution chain length (number of recursive queries)
# 11. Resolution chain (domains in the chain itself)

# sophisticated:
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
    if (len(sys.argv) != 2):
        print >> sys.stderr, "usage: python feature_extractor.py <pcap file>"
        sys.exit(-1)
        
    filename = sys.argv[1]
    print >> sys.stderr, "Parsing...", filename
    
    dnsPackets = parse(filename)

    # Instantiate an extractor
    # extractor = QueryLengthFeatureExtractor(dnsPackets)
    # extractor = QueryResolutionTimeFeatureExtractor(dnsPackets) 
    # extractor = QueryFrequencyFeatureExtractor(dnsPackets)
    extractor = TargetQueryFrequencyFeatureExtractor(dnsPackets)

    # Get the features
    features, sources = extractor.extract()
    print >> sys.stderr, "IP address sources:", sources

    formatter = FeatureFormatter(features)
    print formatter.toCSV(sys.stdout)

    print >> sys.stderr, "Done. Parsed %d DNS packets" % len(dnsPackets)

