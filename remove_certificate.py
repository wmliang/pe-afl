from __future__ import print_function
import pefile
import sys

def go(fname):
    pe = pefile.PE(fname)
    d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_SECURITY')
    assert d.VirtualAddress + d.Size == pe.get_length(), 'some overlays behind certificate'
    s = d.Size
    d.VirtualAddress = 0
    d.Size = 0
    name = fname[:-4]+'.no_certificate'+fname[-4:]
    pe.write(filename=name, cut=s)
    pe.close()
    return name

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage:', sys.argv[0], '<PE>')
        quit()
    go(sys.argv[1])
