from __future__ import print_function
import instrument
import argparse
import os
import re

if os.name == 'nt':
    import subprocess
    import struct
    def asm(code):
        kstool_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bin', 'kstool.exe')
        if not os.path.isfile(kstool_path):
            print('kstool.exe not found')
            quit()
        l = ';'.join([ l if '#' not in l else l.split('#')[0] for l in code.strip().split('\n')])
        output = subprocess.check_output(kstool_path+' x32 "'+l+'"', shell=True)
        assert 'ERROR' not in output, 'wrong assembly: ' + l
        c = output.split('=')[1].replace('[', '').replace(']', '').replace(' ', '').strip()
        return c.decode('hex')
    p32 = lambda v: struct.pack('<I', v)
    u32 = lambda v: struct.unpack('<I', v)[0]
else:
    # ubuntu platform
    from pwn import *

C_ADDR1, C_ADDR2 = [0x44444444]*2
M_PREV_LOC1, M_PREV_LOC2, M_ID, M_AREA_PTR, M_CALLBACK, MAGIC = [0x55555555]*6

snip = {}
def init_snip():
    snip['nop'] = '\x90'*0x24
    snip['single'] = asm('''
push ebx
push eax
lahf
seto al
mov ebx, dword ptr ['''+hex(M_PREV_LOC1)+''']           # __afl_prev_loc @ .cov+0x10000
xor ebx, '''+hex(C_ADDR1)+'''
inc byte ptr ['''+hex(M_AREA_PTR)+'''+ebx]              # __afl_area_ptr @ .cov
mov dword ptr ['''+hex(M_PREV_LOC2)+'''], '''+hex(C_ADDR2)+'''
add al, 127
sahf
pop eax
pop ebx
''')
    snip['multi'] = asm('''
push ecx
push ebx
push eax
lahf
seto al
movzx ecx, byte ptr fs:[0x24]
shl ecx, 2
mov ebx, dword ptr ['''+hex(M_PREV_LOC1)+'''+ecx]       # __afl_prev_loc @ .cov+0x10000
xor ebx, '''+hex(C_ADDR1)+'''
inc byte ptr ['''+hex(M_AREA_PTR)+'''+ebx]              # __afl_area_ptr @ .cov
mov dword ptr ['''+hex(M_PREV_LOC2)+'''+ecx], '''+hex(C_ADDR2)+'''
add al, 127
sahf
pop eax
pop ebx
pop ecx
''')
    PsGetCurrentProcessId_win10 = '''
mov ebx, fs:0x124
mov ebx, dword ptr [ebx+0x37c]
'''
    PsGetCurrentProcessId_win7 = '''
mov ebx, fs:0x124
mov ebx, dword ptr [ebx+0x22c]
'''
    if pe.OPTIONAL_HEADER.MajorOperatingSystemVersion == 10:
        PsGetCurrentProcessId = PsGetCurrentProcessId_win10
    else:
        PsGetCurrentProcessId = PsGetCurrentProcessId_win7
    snip['filter'] = asm('''
push ebx
push eax
lahf
seto al
'''+PsGetCurrentProcessId+'''
cmp ebx, dword ptr ['''+hex(M_ID)+''']                  # pid @ .cov+0x10000+0x10
jne skip
mov ebx, dword ptr ['''+hex(M_PREV_LOC1)+''']           # __afl_prev_loc @ .cov+0x10000
xor ebx, '''+hex(C_ADDR1)+'''
inc byte ptr ['''+hex(M_AREA_PTR)+'''+ebx]              # __afl_area_ptr @ .cov
mov dword ptr ['''+hex(M_PREV_LOC2)+'''], '''+hex(C_ADDR2)+'''
skip:
add al, 127
sahf
pop eax
pop ebx
''')
    snip['callback'] = asm('''
pushad
lahf
seto al
push eax
'''+PsGetCurrentProcessId+'''
cmp ebx, dword ptr ['''+hex(M_ID)+''']                  # pid @ .cov+0x10000+0x10
jne skip
call dword ptr ['''+hex(M_CALLBACK)+''']          	# callback @ .cov+0x10000+0x20
skip:
pop eax
add al, 127
sahf
popad
''')
    args.snip_len = len(bb_snippet(0))
    args.snip_reloc = [m.start() for m in re.finditer(p32(MAGIC), bb_snippet(0))]

def bb_snippet(addr):
    if args.nop:
        return snip['nop']
    elif args.callback:
        return snip['callback']
    elif args.multi:
        s = snip['multi']
    elif args.filter:
        s = snip['filter']
    else:
        s = snip['single']
    r = s.replace(p32(C_ADDR1), p32(addr&0xFFFF),1)
    return r.replace(p32(C_ADDR2), p32((addr>>1)&0xFFFF))

def stk_snippet(count):
    if count % 4:
    	return asm('''
pushad
mov ecx, {}
mov edi, esp
add edi, 32
xor eax, eax
mov al, 0xdd
rep stosd
mov ecx, {}
rep stosb
popad
'''.format(count >> 2, count & 3))
    else:
    	return asm('''
pushad
mov ecx, {}
mov edi, esp
add edi, 32
xor eax, eax
mov al, 0xdd
rep stosd
popad
'''.format(count >> 2))

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--nop', help='Instrument NOP only for testing', action='store_true')
    parser.add_argument('-m', '--multi', help='Support multi-thread target', action='store_true')
    parser.add_argument('-v', '--verbose', help='Print debug log', action='store_true')
    parser.add_argument('-cb', '--callback', help='Instrument with callback, which is in helper driver and written in C', action='store_true')
    parser.add_argument('-s', '--stack', help='Enable stack frame poisoning', action='store_true')
    parser.add_argument('-e', '--entry', help='Inject code on entry point, ie. -e9090')
    parser.add_argument('-l', '--enlarge', help='Enlarge section size, default=4')
    parser.add_argument('PE', help='Target PE for instrument')
    parser.add_argument('IDA_DUMP', help='dump.txt from IDA')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arg()
    args.pe_afl = True
    if args.multi and instrument.is_driver(args.PE):
        assert False, 'TODO: -m support user application only'
    if args.callback and not instrument.is_driver(args.PE):
        assert False, 'TODO: -cb support kernel driver only'
    args.filter = False
    if instrument.is_driver(args.PE) and not args.callback:
        args.filter = True

    if instrument.is_driver(args.PE):
        instrument.INFO('kernel-mode driver is instrumenting')
        if args.callback:
            instrument.INFO('callback instrument is on')
    else:
        instrument.INFO('user-mode binary is instrumenting')
        if args.multi:
            instrument.INFO('multi-thread instrument is on')
        else:
            instrument.INFO('single-thread instrument is on')
    if args.stack:
        instrument.INFO('stack frame poisoning is on')

    pe,ida=instrument.start(args)
    init_snip()

    # stack frame poison instrument
    if args.stack:
        stk=ida['stk_frame']
        for i in stk:
            ofs = i+0xb if stk[i][0] == 6 else i+8
            instrument.inject_code(ofs, stk_snippet(stk[i][1]))

    # basic block instrument
    for i in ida['bb']:
        instrument.inject_code(i, bb_snippet(i-pe.OPTIONAL_HEADER.ImageBase))

    # entry point instrument
    if args.entry:
        instrument.inject_code(pe.OPTIONAL_HEADER.AddressOfEntryPoint+pe.OPTIONAL_HEADER.ImageBase, args.entry.decode('hex'))

    instrument.end()

