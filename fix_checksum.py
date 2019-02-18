from __future__ import print_function
import pefile
import sys

def fix(fname):
    pe = pefile.PE(fname)
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(filename=fname)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage:', sys.argv[0], '<PE>')
        quit()
    fix(sys.argv[1])
