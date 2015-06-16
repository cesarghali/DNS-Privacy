import sys, getopt
import math
from random import shuffle
from sklearn.linear_model import SGDClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression


class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'


def readInput(fileName):
   rows = []
   with open(fileName, "r") as csvfile:
      for row in csvfile:
         chunks = row.rstrip().split(',')
         if len(chunks) != 0:
            rows.append(chunks)
   return rows


def processInput(data, testPercentage):
   shuffle(data)
   testSize = int(math.floor(len(data) * testPercentage))

   trainingFeatures = [map(float, column[1:]) for column in data][0:len(data) - testSize]
   trainingTarget = [column[0] for column in data][0:len(data) - testSize]
   testFeatures = [map(float, column[1:]) for column in data][-testSize:]
   testTarget = [column[0] for column in data][-testSize:]

   return (trainingFeatures, trainingTarget, testFeatures, testTarget)


def sgd(trainingFeatures, trainingTarget, testFeatures, testTarget, options):
   lossFunction = "hinge"
   iterations = 200
   if options != "":
      chunks = options.split(",")
      if chunks[0] in ("hinge", "log", "modified_huber", "squared_hinge"):
         lossFunction = chunks[0]
      else:
         print color.RED + "SGD loss function is not recognized" + color.END
         usage()
         sys.exit(2)

      if chunks[1].isdigit() and int(chunks[1]) > 0:
         iterations = int(chunks[1])
      else:
         print color.RED + "SGD number of epoch must be a positive non-zero number" + color.END
         usage()
         sys.exit(2)

   clf = SGDClassifier(loss=lossFunction, n_iter=iterations)
   clf.fit(trainingFeatures, trainingTarget)
   return clf.predict(testFeatures)


def tree(trainingFeatures, trainingTarget, testFeatures, testTarget):
   clf = DecisionTreeClassifier()
   clf.fit(trainingFeatures, trainingTarget)
   return clf.predict(testFeatures)


def svm(trainingFeatures, trainingTarget, testFeatures, testTarget):
   clf = SVC()
   clf.fit(trainingFeatures, trainingTarget)
   return clf.predict(testFeatures)


def logistic(trainingFeatures, trainingTarget, testFeatures, testTarget, options):
   regularization = 1.0
   if options != "":
      try:
         regularization = float(options)
      except ValueError:
         print color.RED + "Logistic Regression regularization must be a float number" + color.END
         usage()
         sys.exit(2)

   clf = LogisticRegression(C=regularization)
   clf.fit(trainingFeatures, trainingTarget)
   return clf.predict(testFeatures)


def error(testTarget, testTargetPredicted):
   count = 0
   for i in range(0, len(testTarget)):
      tmp = []
      for j in range(0, len(testTargetPredicted)):
         # testTargetPredicted: rows and columns are swapped
         tmp.append(testTargetPredicted[j][i])
         
      if (max(set(tmp), key=tmp.count) != testTarget[i]):
         count = count + 1

   return ((1.0 * count) / len(testTarget))


def usage():
   print ""
   print "usage: classifier.py -i <input file> [-p <test percentage>] -c <classifiers> [-t <iterations>] [-o <options>]"
   print ""
   print "\t" + color.BOLD + "input file:" + color.END + " must be csv, first column is target and rest are features"
   print "\t" + color.BOLD + "test percentage:" + color.END + " is the percentage of input data to be treated as test data"
   print "\t" + color.BOLD + "classifiers:" + color.END + " comma seperated list of one or more classifiers to use in prediction "
   print "\t             Options are: sgd, tree, svm, logistic"
   print "\t" + color.BOLD + "iterations:" + color.END + " number of classification iterations"
   print "\t" + color.BOLD + "options:" + color.END + " options to pass to the classifier"
   print "\t         " + color.UNDERLINE + "sgd:" + color.END + " [<loss={'hinge', 'log', 'modified_huber', 'squared_hinge'}>],<n_iter=int>]"
   print "\t         " + color.UNDERLINE + "tree:" + color.END + " none"
   print "\t         " + color.UNDERLINE + "svm:" + color.END + " none"
   print "\t         " + color.UNDERLINE + "logistic:" + color.END + " [<regularization=float>]"
   print ""


def main(argv):
   fileName = ""
   testPercentage = 0.1
   classifiers = ""
   iterations = 1
   options = ""
   try:
      opts, args = getopt.getopt(argv, "hi:p:c:t:o:",
                                 ["ifile=", "percentage=", "classifiers=",
                                  "iterations=", "options="])
   except getopt.GetoptError:
      usage()
      sys.exit(2)

   if (len(opts) < 2):
      usage()
      sys.exit(2)

   for opt, arg in opts:
      if opt == "-h":
         usage()
         sys.exit()
      elif opt in ("-i", "--ifile"):
         fileName = arg
      elif opt in ("-p", "--percentage"):
         testPercentage = float(arg)
      elif opt in ("-c", "--classifiers"):
         classifiers = arg
      elif opt in ("-t", "--iterations"):
         iterations = int(arg)
      elif opt in ("-o", "--options"):
         options = arg
      else:
         usage()
         sys.exit(2)

   if fileName == "":
      print color.RED + "Input file must be specified." + color.END
      usage()
      sys.exit(2)

   if classifiers == "":
      print color.RED + "Classifier(s) must be specified." + color.END
      usage()
      sys.exit(2)

   data = readInput(fileName)
   errorRate = 0.0
   for i in range(0, iterations):
      trainingFeatures, trainingTarget, testFeatures, testTarget = processInput(data, testPercentage)
      testTargetPredicted = []
      for cls in classifiers.split(","):
         if cls == "sgd":
            testTargetPredicted.append(sgd(trainingFeatures, trainingTarget, testFeatures, testTarget, options))
         elif cls == "tree":
            testTargetPredicted.append(tree(trainingFeatures, trainingTarget, testFeatures, testTarget))
         elif cls == "svm":
            testTargetPredicted.append(svm(trainingFeatures, trainingTarget, testFeatures, testTarget))
         elif cls == "logistic":
            testTargetPredicted.append(logistic(trainingFeatures, trainingTarget, testFeatures, testTarget, options))
         else:
            print color.RED + "Unknown classifier" + color.END
            usage()
            sys.exit(2)

      errorRate = errorRate + error(testTarget, testTargetPredicted)

   print "Error rate: " + str(errorRate / iterations)


if __name__ == "__main__":
   main(sys.argv[1:])

