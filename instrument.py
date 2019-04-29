from __future__ import print_function
import argparse
import bisect
import pefile
import struct
import math
import sys
import os
import re

pe=None
args=None
ida=None
code_loc = None

p64 = lambda v: struct.pack('<Q', v)
p32 = lambda v: struct.pack('<I', v)
p16 = lambda v: struct.pack('<H', v)
u64 = lambda v: struct.unpack('<Q', v)[0]
u32 = lambda v: struct.unpack('<I', v)[0]
u16 = lambda v: struct.unpack('<H', v)[0]
new_name = lambda s: s.Name.strip('\x00')[:-1]+'2'
align_sec = lambda v: int(math.ceil(v / float(pe.OPTIONAL_HEADER.SectionAlignment))) * pe.OPTIONAL_HEADER.SectionAlignment
align_file = lambda v: int(math.ceil(v / float(pe.OPTIONAL_HEADER.FileAlignment))) * pe.OPTIONAL_HEADER.FileAlignment
check32 = lambda v: -0x80000000 <= v < 0x80000000
check64 = lambda v: -0x8000000000000000 <= v < 0x8000000000000000
is_exe = lambda s: bool(s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) if hasattr(s, 'Characteristics') else False
is_driver = lambda s: '.sys' in s or 'ntoskrnl' in s
is_32 = lambda : True if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] else False
strrep = lambda s1, idx, s2: s1[:idx] + s2 + s1[idx+len(s2):]
va2ofs = lambda v: pe.get_offset_from_rva(v - pe.OPTIONAL_HEADER.ImageBase)
rva2ofs = lambda v: pe.get_offset_from_rva(v)
ofs2rva = lambda v: pe.get_rva_from_offset(v)
ofs2va = lambda v: pe.get_rva_from_offset(v) + pe.OPTIONAL_HEADER.ImageBase
get_sec_by_name = lambda v: [s for s in pe.sections if s.Name.startswith(v)][0]
get_sec_by_ofs = lambda v: pe.get_section_by_offset(v)
get_sec_by_rva = lambda v: pe.get_section_by_rva(v)
get_sec_by_va = lambda v: pe.get_section_by_rva(v-pe.OPTIONAL_HEADER.ImageBase)

class RELA:
    def __init__(self, target, op, opnd, tlen):
        self.target = target
        self.op = op 
        self.opnd = opnd 
        self.tlen = tlen
    def __str__(self):
        return str([hex(self.target), self.op, self.opnd, self.tlen])

class CODE:
    def __init__(self, va, exp, align, code, tlen):
        self.va = va 
        self.exp = exp
        self.align = align
        self.code = code
        self.tlen = tlen
    def __str__(self):
        return str([hex(self.va), self.exp, self.align, self.code, self.tlen])

class ADDR:
    def __init__(self, diff, code_len):
        self.diff = diff
        self.code_len = code_len
    def __str__(self):
        return str([hex(self.diff), self.code_len])

def LOG(*args_):
    if args.verbose:
        print(' '.join(list(args_)))

def INFO(s):
    print('[*] ' + s)

def clear_stub():
    if '.no_stub' not in pe.path:
        # leave space for section table
        import clear_stub
        name = clear_stub.go(pe.path)
        print('cleared DOS stub')
        load_pe(name)

def check_certificate():
    d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_SECURITY')
    if d.VirtualAddress:
        import remove_certificate
        name = remove_certificate.go(pe.path)
        print('removed certificate')
        load_pe(name)

def in_range(val, pair):
    for a,b in pair:
        if a <= val < b:
            return True
    return False

def get_last(seq, val):
    if val < seq[0]:
        return None
    return seq[bisect.bisect_right(seq, val) - 1]

injected = {}
def inject_code(addr, code='', expand=''):
    # expand is a partial operand for expanding from short jump to long jump
    v,s = va2ofs(addr), get_sec_by_va(addr)
    assert is_exe(s), 'v is out of .text'

    # instrument with word-aligned
    align = ''
    if expand == '':
        code += '\x90' * (len(code)%2)
    else:
        align = '\x90' * (len(expand)%2)

    if v in injected:
        i = injected[v]
        i.exp = expand
        i.align = align
        # multiple injection is allowed 
        i.code = code + i.code
        i.tlen = len(i.code + i.exp + i.align)
    else:
        injected[v] = CODE(*[addr, expand, align, code, len(expand+code+align)])
        # for optimization
        if not hasattr(s, 'addr_set'):
            s.addr_set = []
        bisect.insort(s.addr_set, v)

def build_map(sec=None):
    # for optimization
    if sec == None:
        sec = sorted(pe.sections, key=lambda s: s.PointerToRawData)
    else:
        sec = [sec]
    for s in sec:
        if hasattr(s, 'addr_map'):
            diff = 0
            for i in s.addr_set:
                tlen = injected[i].tlen
                s.addr_map[i] = ADDR(*[i+diff+len(injected[i].exp), tlen - len(injected[i].exp)])
                diff += tlen

def get_last_section(type):
    rva = 0;fa = 0;tbl = 0
    for s in pe.sections:
        rva = max(rva, s.VirtualAddress+s.Misc_VirtualSize)
        fa = max(fa, s.PointerToRawData+s.SizeOfRawData)
        tbl = max(tbl, s.get_file_offset()+s.sizeof())
    LOG('[get_last_section]', s.Name, hex(rva), hex(fa), hex(tbl))
    if type == 'rva':
        return align_sec(rva)
    elif type == 'fa':
        return align_file(fa)
    elif type == 'tbl':
        return tbl

def get_text_diff(fa):
    s = get_sec_by_ofs(fa)
    diff = 0
    if fa in s.addr_map:
        diff = s.addr_map[fa].diff-fa
    else:
        last_old = get_last(s.addr_set, fa)
        if last_old:
            diff = s.addr_map[last_old].diff - last_old + s.addr_map[last_old].code_len
    return diff

def get_data_diff(fa):
    s = get_sec_by_ofs(fa)
    diff = 0
    last_old = get_last(s.addr_set, fa)
    if last_old:
        diff = s.addr_map[last_old].diff - last_old + s.addr_map[last_old].code_len
    return diff

def new_reloc_entry(addr, type):
    entry = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_ENTRY_format__)
    assert (0 <= type <= 11) , 'invalid type'
    setattr(entry, 'Data', (addr&0xFFF)+(type<<12))
    entry.set_file_offset(0)
    return pefile.RelocationData(struct = entry, type = type, base_rva = addr&~0xFFF, rva = addr)

updated_reloc = []
def add_to_reloc(addr, type):
    for x in updated_reloc:
        if (addr&~0xFFF) == x.struct.VirtualAddress:
            # insert new entry into existed base reloc
            x.entries.append(new_reloc_entry(addr, type))
            x.struct.SizeOfBlock += 2
            return
    
    # new a entry 
    s = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__)
    setattr(s, 'VirtualAddress', addr&~0xFFF)
    setattr(s, 'SizeOfBlock', 8+2)
    s.set_file_offset(0)

    # insert new base reloc
    entries = []
    entries.append(new_reloc_entry(addr, type))
    updated_reloc.append(pefile.BaseRelocationData(struct = s, entries = entries))

def write_reloc():
    #IMAGE_REL_BASED_ABSOLUTE        No operation relocation. Used for padding.
    #IMAGE_REL_BASED_HIGHLOW         Add the delta between the ImageBase and the allocated memory block to the 32 bits found at the offset. 
    updated_reloc.sort(key=lambda x: x.struct.VirtualAddress)

    # append IMAGE_REL_BASED_ABSOLUTE for padding
    for x in updated_reloc:
        if (x.struct.SizeOfBlock/2)%2:
            x.entries.append(new_reloc_entry(0, 0))
            x.struct.SizeOfBlock += 2

    def debug_reloc(r):
        LOG('[debug_reloc]')
        for base_reloc in r:
            LOG('\n'.join(base_reloc.struct.dump()))
            for reloc in base_reloc.entries:
                LOG('%08Xh %s' % (reloc.rva, pefile.RELOCATION_TYPE[reloc.type][16:]))
    if args.verbose:
        debug_reloc(updated_reloc)

    reloc = get_sec_by_name('.reloc')
    ofs = reloc.PointerToRawData
    end = ofs + reloc.SizeOfRawData     # end is file aligned
    update_reloc_raw = ''
    for base_reloc in updated_reloc:
        d = p32(base_reloc.struct.VirtualAddress) + p32(base_reloc.struct.SizeOfBlock)
        update_reloc_raw += d
        for rr in base_reloc.entries:
            d = p16(rr.struct.Data)
            update_reloc_raw += d

    d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_BASERELOC')
    d.Size = len(update_reloc_raw)
    d.VirtualAddress = reloc.VirtualAddress
    update_reloc_raw += '\x00'*(0x200-len(update_reloc_raw)%0x200) 	# padding
    reloc.Misc_VirtualSize = reloc.SizeOfRawData = len(update_reloc_raw)
    return update_reloc_raw

def update_reloc_raw(type, raw, v):
    if type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
        addr = u32(raw[v:v+4])
        # use rva rather than offset here, due to some undefined data between data sections
        s = pe.get_section_by_rva(addr-pe.OPTIONAL_HEADER.ImageBase)
        if is_exe(s) and not in_range(va2ofs(addr), ida['idata']):
            LOG('[update_reloc_raw]', hex(addr))
            if va2ofs(addr) in injected:
                last = get_last(code_loc, addr)
                if last and last <= addr < ida['code_loc'][last]:
                    diff3 = get_text_diff(va2ofs(addr))
                else:
                    diff3 = get_data_diff(va2ofs(addr))
            else:
                diff3 = get_data_diff(va2ofs(addr))
            vv = addr + s.sec_diff + diff3
            assert check32(vv), 'vv is out of range'
            return strrep(raw, v, p32(vv))
        else:
            return raw
    elif type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
        assert False, 'TODO'
    else:
        assert False, 'TODO'

def update_and_verify_section_table():
    # update .reloc in section table
    idx = [i for i,j in enumerate(pe.sections) if '.reloc' in j.Name][0]
    reloc = pe.sections.pop(idx)
    old_reloc_size = reloc.SizeOfRawData
    reloc.VirtualAddress = get_last_section('rva')
    reloc.PointerToRawData = get_last_section('fa')
    reloc.set_file_offset(get_last_section('tbl'))
    pe.sections.append(reloc)
    # confirm all sections have to stick together, don't overlap or seperate
    rva = 0
    fa = 0
    for s in pe.sections:
        if rva != 0 and fa != 0:
            assert rva == s.VirtualAddress and (0 == s.PointerToRawData or fa == s.PointerToRawData)
            prev_s.next_section_virtual_address = s.VirtualAddress, (hex(s.VirtualAddress), hex(s.PointerToRawData))
        prev_s = s
        rva = align_sec(s.VirtualAddress+s.Misc_VirtualSize)
        fa = align_file(s.PointerToRawData+s.SizeOfRawData)
    s.next_section_virtual_address = s.VirtualAddress+s.Misc_VirtualSize
    return old_reloc_size


def get_relative_diff(from_fa, to_fa):
#           +----------------+
#           |                v           I = injected
#     +---+-+-+              +---+---+   C = original code
#     | I | C |              | I | C |
#     ----+---+              +---+-+-+
#     ^                            |
#     +----------------------------+
    from_s = get_sec_by_ofs(from_fa)
    to_s = get_sec_by_ofs(to_fa)
    if from_s != to_s:
        # for inter-section
        diff = (to_fa+get_text_diff(to_fa)-to_s.PointerToRawData) - (from_fa+get_text_diff(from_fa)-from_s.PointerToRawData)
        if from_fa in from_s.addr_set:
            diff -= from_s.addr_map[from_fa].code_len
        sec_diff = (to_s.VirtualAddress+to_s.sec_diff) - (from_s.VirtualAddress+from_s.sec_diff)
        return from_fa + diff + sec_diff

    # for intra-section
    diff = get_text_diff(to_fa) - get_text_diff(from_fa)
    if from_fa in from_s.addr_set:
        diff -= from_s.addr_map[from_fa].code_len
    return to_fa + diff

def update_instr(op, operand_len, v):
    assert check32(v), 'v is out of range'

    if -0x80 <= v < 0x80:
        if operand_len != 1:
            # instruction will not be shorter
            return expand_instr(op, v)
        else:
            return op + chr(v&0xFF).encode('hex')
    else:
        return expand_instr(op, v)

def expand_instr(op, v):
    assert check32(v), 'v is out of range'
    dword = lambda v: p32(v&0xFFFFFFFF).encode('hex')
    mpx = ''
    if op.startswith('f2'):
        mpx = 'f2'
        op = op[2:]

    if op == 'e2':              		    # loop rel8
        assert mpx == '', 'unsupport op ' + op
        return '4975' + dword(v)		    # dec ecx ; jnz label
    elif op == 'e3':                                # jecxz rel8
        assert mpx == '', 'unsupport op ' + op
        return '85c974' + dword(v)		    # test ecx, ecx ; jz label
    elif op == 'eb':                                # jmp rel8
        return mpx + 'e9' + dword(v)
    elif op == 'e9':                                # jmp rel32
        return mpx + 'e9' + dword(v)
    elif op == 'e8':                                # call
        return mpx + 'e8' + dword(v)
    elif op[0] == '7':                              # jxx rel8
        return mpx + '0f8' + op[-1] + dword(v)
    elif op[:3] == '0f8':                           # jxx rel32
        return mpx + op + dword(v)
    else:
        assert False, 'unsupport op ' + op 

def seh_padding():
    # SEHandlerTable have to align with 4-byte
    is_padded = False
    d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG')
    ofs = va2ofs(d.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase)
    if not hasattr(get_sec_by_ofs(ofs), 'addr_set'):
        return is_padded
    delta = get_data_diff(ofs) % 4
    if delta:
        is_padded = True
        LOG('[seh_padding]', hex(d.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase))
        # pad NOP in the last injected
        s = get_sec_by_ofs(ofs)
        addr = ofs2va(get_last(s.addr_set, ofs))
        inject_code(addr, '\x90'*(4-delta))
        build_map(s)
        print('SEHandlerTable is padded')
    return is_padded

def update_addr(addr):
    v,s = rva2ofs(addr), get_sec_by_rva(addr)
    if hasattr(s, 'sec_diff'):
        return addr + s.sec_diff + get_text_diff(v)
    else:
        return addr

def dup_sec(sec, name=None, size=0):
    s = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    s.__unpack__(sec.__pack__())
    if name:
        s.Name = name
    else:
        s.Name = (new_name(sec)).ljust(8, '\x00')
    # skip .reloc if necessary
    diff = get_sec_by_name('.reloc').SizeOfRawData if '.reloc' in pe.sections[-1].Name else 0
    s.VirtualAddress = get_last_section('rva') - align_sec(diff)
    s.PointerToRawData = get_last_section('fa') - align_file(diff)
    ss = size if size else sec.SizeOfRawData*args.enlarge
    s.Misc_VirtualSize = align_sec(ss)
    s.SizeOfRawData = align_file(ss)
    diff = s.sizeof() if '.reloc' in pe.sections[-1].Name else 0
    s.set_file_offset(get_last_section('tbl') - diff)
    s.next_section_virtual_address = s.VirtualAddress + s.Misc_VirtualSize
    assert s.get_file_offset() + 40 <= pe.OPTIONAL_HEADER.SizeOfHeaders, 'TODO'
    pe.__structures__.append(s)
    pe.sections.append(s)
    print('added section', s.Name.strip('\x00'))
    LOG(str(s))
    return s

def build_text_raw():
    for s in pe.sections:
        if is_exe(s) and s.Name.strip('\x00')[-1] != '2':
            start = s.PointerToRawData
            end = start + s.SizeOfRawData
            setattr(s, 'raw', p32(start) + '\x00'*(start-4) + pe.get_raw()[start:end])
            name = s.Name.strip('\x00')
            LOG(name, '@', hex(start), '~', hex(end))

def update_load_config_tbl(tbl, cnt, pe_size, append, align=4):
    tbl2 = update_addr(tbl - pe.OPTIONAL_HEADER.ImageBase)
    ofs,s = rva2ofs(tbl2), get_sec_by_rva(tbl2)
    if hasattr(s, 'raw'): # original section
        for n in range(cnt):
            s.raw = strrep(s.raw, ofs+n*align, p32(update_addr(u32(s.raw[ofs+n*align:ofs+n*align+4]))))
    else: # new section
        append = '\x00'*pe_size + append
        for n in range(cnt):
            append = strrep(append, ofs+n*align, p32(update_addr(u32(append[ofs+n*align:ofs+n*align+4]))))
        append = append[pe_size:]
    return append

def process_pe():
    # update section table
    # add new section entry, size of new section is affected by args.enlarge
    assert '.reloc' in pe.sections[-1].Name, '.reloc is not at the end'
    assert pe.get_length() == get_last_section('fa'), 'overlays is behind PE'
    for sec in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        if is_exe(sec):
            # empty inject is for triggering the data update later
            if not hasattr(sec, 'addr_set'):
                inject_code(sec.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase, '')
            s = dup_sec(sec)
            setattr(sec, 'sec_diff', s.VirtualAddress - sec.VirtualAddress)
            setattr(sec, 'addr_map', {})
    s = get_sec_by_name('.data')
    assert not is_driver(pe.path) or s.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_NOT_PAGED'], 'any non page memory ?'
    if hasattr(args, 'pe_afl'):
        dup_sec(s, name='.cov', size=0x10fff)
    cut_reloc_size = update_and_verify_section_table()

    # update relative address
    print('expanding relative ...')
    jmp_map = {}
    relative = {}
    for k in sorted(ida['relative']):
        relative[k] = RELA(*ida['relative'][k])
    for k in sorted(relative):
        if relative[k].opnd == 1: # short jmp
            order = -1 if k>relative[k].target else 1
            for i in range(k, relative[k].target+order, order):
                if order == 1 and (i == k or i == relative[k].target):
                    continue
                if i not in jmp_map:
                    jmp_map[i] = [k]
                else:
                    jmp_map[i].append(k)
    expand_list = []
    for i in injected:
        if injected[i].va in jmp_map:
            expand_list += jmp_map[injected[i].va]
    expand_list = list(set(expand_list))
    for i in expand_list:
        if i not in jmp_map:
            continue
        for j in jmp_map[i]:
            if j not in expand_list:
                expand_list.append(j)
    for k in expand_list:
        cmd_len = relative[k].tlen
        e = len(expand_instr(relative[k].op, 0))/2-cmd_len
        # the expanded byte is stored in the next instruction
        inject_code(k+cmd_len, expand='\x00'*e)
    print('expanded %d of %d branches ' % (len(expand_list), len(relative)))

    build_map()
    seh_padding()
    print('updating relative ...')

    for k in sorted(relative):
        from_ofs = va2ofs(k)
        to_ofs = va2ofs(relative[k].target)
        new_ofs = get_relative_diff(from_ofs, to_ofs)
        LOG('[update relative]', hex(k), hex(relative[k].target), hex(to_ofs), hex(new_ofs))
        cmd_len = relative[k].tlen
        expand_len = 0
        next_ofs = va2ofs(k+cmd_len)
        if next_ofs in injected:
            expand_len = len(injected[next_ofs].exp)
        instr = update_instr(relative[k].op, relative[k].opnd+expand_len, new_ofs-(from_ofs+cmd_len+expand_len)).decode('hex')
        assert len(instr) == cmd_len + expand_len
        if instr[cmd_len:] != '': # update expand
            injected[next_ofs].exp = instr[cmd_len:]
        s = get_sec_by_ofs(from_ofs)
        s.raw = strrep(s.raw, from_ofs, instr[:cmd_len])

    # update .reloc entry
    print('updating relocation ...')
    for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
        for reloc in base_reloc.entries:
            if reloc.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                continue

            v,s = rva2ofs(reloc.rva), get_sec_by_rva(reloc.rva)
            if is_exe(s) and not in_range(v, ida['idata']):
                # assume that all relocation are data here
                diff2 = get_data_diff(v)
                LOG('[update reloc] %08Xh %s' % (reloc.rva, pefile.RELOCATION_TYPE[reloc.type][16:]) + ', diff2 = ' + hex(diff2))
                add_to_reloc(reloc.rva + s.sec_diff + diff2, reloc.type)
                s.raw = update_reloc_raw(reloc.type, s.raw, v)
            else:
                LOG('[update reloc] %08Xh %s' % (reloc.rva, pefile.RELOCATION_TYPE[reloc.type][16:]))
                add_to_reloc(reloc.rva, reloc.type)
                if not hasattr(s, 'raw'):
                    setattr(s, 'raw', p32(s.PointerToRawData) + '\x00'*(s.PointerToRawData-4) + s.get_data()) # give a padding
                s.raw = update_reloc_raw(reloc.type, s.raw, v)

    # add and update reloc from injected
    if hasattr(args, 'pe_afl') and not args.nop:
        print('updating relocation in instrumented code ...')
        t = pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW'] if is_32() else pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']
        afl_area_ptr = get_sec_by_name('.cov').VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        afl_prev_loc = afl_area_ptr + 0x10000
        if args.callback:
            rr = [afl_prev_loc+0x10, afl_prev_loc+0x20]
        elif args.filter:
            rr = [afl_prev_loc+0x10, afl_prev_loc, afl_area_ptr, afl_prev_loc]
        else: # single and multi
            rr = [afl_prev_loc, afl_area_ptr, afl_prev_loc]
        for v in sorted(injected):
            if injected[v].tlen < args.snip_len:
                continue
            m = [i + len(injected[v].exp + injected[v].align) for i in args.snip_reloc]
            s = get_sec_by_ofs(v)
            addr = ofs2rva(v) + s.sec_diff + get_text_diff(v)
            addr -= len(injected[v].exp)
            for i in range(len(m)):
                injected[v].code = strrep(injected[v].code, args.snip_reloc[i], p32(rr[i]))
                add_to_reloc(addr + m[i], t)
    append_reloc = write_reloc()

    print('finalizing ...')
    append = ''
    mapping_txt = ''
    pe_size = pe.get_length() - cut_reloc_size
    s2 = [s for s in sorted(pe.sections, key=lambda s: s.PointerToRawData) if hasattr(s, 'addr_set')]
    for i,s in enumerate(s2):
       new_s = get_sec_by_name(new_name(s))
       old_idx = s.PointerToRawData
       for idx in s.addr_set:
           append += s.raw[old_idx:idx] + injected[idx].exp + injected[idx].align + injected[idx].code
           tt = pe_size+len(append)-injected[idx].tlen+len(injected[idx].exp)
           tts = get_sec_by_ofs(tt)
           LOG('[merge] idx =', hex(idx), hex(tt))
           mapping_txt += hex(idx-s.PointerToRawData+s.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase).strip('L') + '\t'
           mapping_txt += hex(tt-tts.PointerToRawData+tts.VirtualAddress+pe.OPTIONAL_HEADER.ImageBase).strip('L') + '\n'
           old_idx = idx
       append += s.raw[idx:]
       end = new_s.PointerToRawData + new_s.SizeOfRawData
       assert len(append)+pe_size <= end, 'injection too large, use -l {} to enlarge and try again'.format(args.enlarge+1)
       assert i == len(s2)-1 or end == get_sec_by_name(new_name(s2[i+1])).PointerToRawData, 'Some space is unexpected'
       append += '\x00'*(end - len(append) - pe_size)
       delattr(s, 'raw')
    if hasattr(args, 'pe_afl'):
        append += '\x00'*0x11000    # reserved for __afl_area_ptr and __afl_prev_loc
        if args.callback or args.filter:
            append = strrep(append, len(append)-0x1000+0x10, p32(0xffffffff))
    # log mapping to file, it can be used in IDA directly
    with open(args.IDA_DUMP.replace('dump', 'mapping'), 'w+') as ff:
        ff.write(mapping_txt)

    build_text_raw()

    # update export table
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            s = get_sec_by_rva(e.address)
            if not is_exe(s):
                continue
            s = get_sec_by_ofs(e.address_offset)
            if not hasattr(s, 'raw'):
                setattr(s, 'raw', p32(s.PointerToRawData) + '\x00'*(s.PointerToRawData-4) + s.get_data()) # padding
            s.raw = strrep(s.raw, e.address_offset, p32(update_addr(e.address)))

    # update SEHHandlerTable and GuardCFFunctionTable
    d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG')
    if d.VirtualAddress:
        s = get_sec_by_rva(d.VirtualAddress)
        if is_exe(s):
            d.VirtualAddress = update_addr(d.VirtualAddress)
        append = update_load_config_tbl(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable, pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerCount, pe_size, append)
        if d.Size > 0x60:
            extra = (pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags & 0xF0000000)>>28
            append = update_load_config_tbl(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable, pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionCount, pe_size, append, align=extra+4)
    # update TLS directory
    d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_TLS')
    if d.VirtualAddress:
        s = get_sec_by_rva(d.VirtualAddress)
        if is_exe(s):
            d.VirtualAddress = update_addr(d.VirtualAddress)

    # update PE header
    pe.OPTIONAL_HEADER.SizeOfImage = get_last_section('rva')
    pe.FILE_HEADER.NumberOfSections += len([s for s in pe.sections if hasattr(s, 'sec_diff')])
    if hasattr(args, 'pe_afl'):
        pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = update_addr(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    LOG('SizeOfImage='+hex(pe.OPTIONAL_HEADER.SizeOfImage))
    LOG('NumberOfSections='+hex(pe.FILE_HEADER.NumberOfSections))
    LOG('AddressOfEntryPoint='+hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    # clear Bound Import Directory in order to get more space for new section
    d = pe.get_directory_by_name('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT')
    d.VirtualAddress = 0
    d.Size = 0
   
    # handle the rest of raw
    for i in sorted(injected):
        s = get_sec_by_ofs(i)
        s.raw = strrep(s.raw, i, '\xCC')   # for debug use
    for s in pe.sections:
        if hasattr(s, 'raw'):
            s.raw = s.raw[u32(s.raw[:4]):]
            if not is_exe(s):
                assert len(s.raw) == s.SizeOfRawData, 'Section size has changed'
            print('updated', s.Name.strip('\x00'))

    return cut_reloc_size, append + append_reloc 

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Print debug log', action='store_true')
    parser.add_argument('-i', '--ins', help='Instrument code, ie. -e"{1:9090,}"')
    parser.add_argument('-l', '--enlarge', help='Enlarge section size, default=4')
    parser.add_argument('PE', help='Target PE for instrument')
    parser.add_argument('IDA_DUMP', help='dump.txt from IDAPython')
    return parser.parse_args()

def load_pe(fname):
    global pe
    if pe and ('.no_stub' in pe.path or '.no_certificate' in pe.path):
        pe.close()
        os.remove(pe.path)
    try:
        pe = pefile.PE(fname)
        pe.path = fname
    except:
        print('Invalid PE file @', fname)
        quit()

def start(a):
    global args, pe, ida, code_loc
    args=a

    args.enlarge = int(args.enlarge) if args.enlarge else 4

    load_pe(args.PE)
    check_certificate()
    clear_stub()
    build_text_raw()

    # import dump.txt from IDA
    ida = eval(open(args.IDA_DUMP).read().strip())
    code_loc = sorted(ida['code_loc'].keys())
    return pe,ida

def end():
    global ida
    ida['idata'] = map(lambda v: [va2ofs(v[0]), va2ofs(v[1])], ida['idata'])

    cut_size, append = process_pe()

    fname = os.path.abspath(pe.path).split('.')
    fname = fname[0]+'.instrumented.'+fname[-1]
    pe.write(filename=fname, append=append, cut=cut_size)

    print('fixing PE checksum ...')
    load_pe(fname)
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(filename=fname)
    INFO('instrumented binary at '+fname)

if __name__ == '__main__':
    args = parse_arg()

    pe,ida=start(args)

    ##################
    # instrument here

    # instrument entry point with 2 NOP
    #inject_code(pe.OPTIONAL_HEADER.AddressOfEntryPoint+pe.OPTIONAL_HEADER.ImageBase, '9090'.decode('hex'))
    if args.ins:
        d = eval(args.ins)
        for k in d:
            LOG('[inject_code]', hex(k), d[k])
            inject_code(k, d[k].decode('hex'))
    ##################

    end()

