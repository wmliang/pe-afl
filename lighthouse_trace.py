from __future__ import print_function
import sys
import bisect
import pefile

def readfile(p):
    r = []
    for l in open(p).read().strip().split('\n'):
        r.append(l.strip())
    return r

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Usage: {} [XXX.sys] [XXX.sys.mapping.txt] [trace.txt]'.format(sys.argv[0]))
        quit()

trace = readfile(sys.argv[3])
mapping = readfile(sys.argv[2])
pe = pefile.PE(sys.argv[1])
base = pe.OPTIONAL_HEADER.ImageBase
trace = [ int(c, 16)+base-0x21 for c in trace ]
get_last = lambda seq, val: seq[bisect.bisect_right(seq, val) - 1]

mm = {}
for m in mapping:
    (x,y) = m.split()
    mm[int(y,16)] = int(x,16)
kk = sorted(mm.keys())
for c in trace:
    print(hex(mm[get_last(kk, c)]))
