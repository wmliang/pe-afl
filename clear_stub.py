import pefile
import struct
import sys

p32 = lambda v: struct.pack('<I', v)

def go(fname):
    pe = pefile.PE(fname)
    with open(fname, 'rb') as f:
        buf = f.read()
    replace = buf[pe.DOS_HEADER.e_lfanew:pe.OPTIONAL_HEADER.SizeOfHeaders] + '\x00'*(pe.DOS_HEADER.e_lfanew-0x40)
    buf = buf[:0x40-4] + p32(0x40) + replace + buf[pe.OPTIONAL_HEADER.SizeOfHeaders:]
    name = fname[:-4]+'.no_stub'+fname[-4:]
    with open(name, 'wb') as f:
        f.write(buf)
    pe.close()
    return name

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'Usage:', sys.argv[0], '<PE>'
        quit()
    go(sys.argv[1])
