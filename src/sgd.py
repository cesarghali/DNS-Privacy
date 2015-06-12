import sys
import math
from random import shuffle
from sklearn.linear_model import SGDClassifier


def readInput(fileName):
    rows = []
    with open(fileName, 'r') as csvfile:
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


def applySGD(trainingFeatures, trainingTarget, testFeatures, testTarget):
    clf = SGDClassifier(loss="hinge", n_iter=200)
    clf.fit(trainingFeatures, trainingTarget)
    testTargetPredicted = clf.predict(testFeatures)

    count = 0
    for i in range(0, len(testTarget)):
        if (testTargetPredicted[i] != testTarget[i]):
            count = count + 1

    errorRate = (1.0 * count) / len(testTarget)

    return errorRate


if __name__ == "__main__":
    if (len(sys.argv) < 3):
        print >> sys.stderr, "usage: python sgd.py <input file> <test percentage> [<iterations>]"
        sys.exit(-1)
    fileName = sys.argv[1]
    testPercentage = float(sys.argv[2])
    iterations = 1
    if (len(sys.argv) == 4):
        iterations = int(sys.argv[3])

    data = readInput(fileName)
    errorRate = 0.0
    for i in range(0, iterations):
        trainingFeatures, trainingTarget, testFeatures, testTarget = processInput(data, testPercentage)
        errorRate = errorRate + applySGD(trainingFeatures, trainingTarget, testFeatures, testTarget)
    print "Error rate: " + str(errorRate / iterations)

