import re

'''
process output of countpackets.cc
'''

Id = '$Id$'

d = {'SYN': [0, 0],
     '443': [0, 0],
     'SYNon443': [0, 0],
     }

def run(fpath):
    f=open(fpath)
    pattern = re.compile(
        r'(SYN|443|SYNon443): [0-9.]+ M \(([0-9]+)\), [0-9.]+ GB \(([0-9]+) bytes\)')
    for l in f.readlines():
        if l.startswith('SYN:') or l.startswith('443:') or l.startswith('SYNon443:'):
            l = l.strip()
            match = re.match(pattern, l)
            assert match
            print l
            print match.groups()
            typ = match.group(1)
            pktcount = int(match.group(2))
            size = int(match.group(3))
            d[typ] [0] += pktcount
            d[typ] [1] += size
            print
            pass
        pass

    f.close()

    print 'file:', fpath
    for k in ('SYN', '443', 'SYNon443'):
        v = d[k]
        print k, ':', float(v[0])/(10**6), 'M packets, ', float(v[1])/(2**30), 'GB'
        pass
    return

if __name__ == '__main__':
    import sys
    run(sys.argv[1])
    pass
