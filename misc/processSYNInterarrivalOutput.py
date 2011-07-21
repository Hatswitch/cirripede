import re

'''
process output of measureSYNInterarrival.cc
'''

Id = '$Id$'

####################################################################
def genCDFFromCounts(valueToCounts, outFilePath):
    totalCount = sum(valueToCounts.values())
    fil = open(outFilePath, 'w')
    fil.write('# total count: %u\n' % (totalCount))
    cumulativeCount = 0
    for value in sorted(valueToCounts.keys()):
        cumulativeCount += valueToCounts[value]
        fraction = float(cumulativeCount) / totalCount
        fil.write('%f\t%f  # count of this value: %u\n' % (value, fraction, valueToCounts[value]))
        pass
    fil.close()
    return

####################################################################

d = {}

def run(fpath):
    f=open(fpath)
    pattern = re.compile(
        r'interval: ([0-9]+), count: ([0-9]+)')
    for l in f.readlines():
        l = l.strip()
        match = re.match(pattern, l)
        if match:
#            print match.groups()
            interval = int(match.group(1))
            pktcount = int(match.group(2))
            if not interval in d:
                d[interval] = 0
                pass
            d[interval] += pktcount
#            print
            pass
        pass

    f.close()

    print 'file:', fpath
    genCDFFromCounts(d, 'cdf_syniat')
    return

if __name__ == '__main__':
    import sys
    run(sys.argv[1])
    pass
