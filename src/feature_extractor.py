import sys
from pcap_parser import *

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
