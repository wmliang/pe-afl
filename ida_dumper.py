import re

H = lambda addr: hex(addr).strip('L')

def parse_relative(ea):
    buf = idc.get_bytes(ea, get_item_size(ea))
    idx = 0
    mpx_candidate = False

    # call (e8), http://x86.renejeschke.de/html/file_module_x86_id_26.html
    # jmp (eb/e9), http://x86.renejeschke.de/html/file_module_x86_id_147.html
    # jxx (0F 80/0F 81/0F 82/0F 83/0F 84/0F 85/0F 86/0F 87/0F 88/0F 89/0F 8A/0F 8B/0F 8C/0F 8D/0F 8E/0F 8F/70/71/72/73/74/75/76/77/78/79/7A/7B/7C/7D/7E/7F), http://x86.renejeschke.de/html/file_module_x86_id_146.html
    # jcxz/jecxz (67 e3/e3)
    # loop/loope/loopz/loopne/loopnz (e0/e1/e2), http://x86.renejeschke.de/html/file_module_x86_id_161.html
    if ord(buf[idx]) == 0xf2:
        idx += 1
        mpx_candidate = True

    if ord(buf[idx]) in [0xe0, 0xe1, 0xe2, 0xe3, 0xe8, 0xe9, 0xeb]:
        idx += 1
    elif ord(buf[idx]) == 0x0f and (ord(buf[idx+1]) >= 0x80 and ord(buf[idx+1]) <= 0x8f):
        idx += 2
    elif (ord(buf[idx]) >= 0x70 and ord(buf[idx]) <= 0x7f):
        idx += 1
    elif ord(buf[idx]) == 0x67 and ord(buf[idx+1]) == 0xe3:
        idx += 2

    if mpx_candidate and idx == 1:
        idx = 0
  
    if idx:
        return buf[0:idx], buf[idx:]
    else:
        return None, None

def add_relative(ea):
    # need operand length, so parse it manually
    op, operand = parse_relative(ea)
    if op and operand:
        assert len(idc.print_operand(ea, 1)) == 0, 'more than 1 operand'
        assert len(operand) == 1 or len(operand) == 4, 'operand is not rel32'
        relative[ea] = [idc.get_operand_value(ea,0), op.encode('hex'), len(operand), len(op+operand)]

possible_data = []
def add_basic_block(ea):
    op = idc.print_insn_mnem(ea)
    if not(op in ['call'] or op.startswith('j') or op.startswith('loop')):
        return

    # validing branch, ie. jmp near ptr get_wide_dword_1007F84+1
    operand = idc.get_operand_value(ea,0)
    if prev_head(next_head(operand)) != operand and idc.get_operand_type(ea, 0) in [idc.o_imm, idc.o_far, idc.o_near]:
        possible_data.append(H(ea))
        return

    # skip non-conditional branch
    if op in ['call', 'jmp']:
        return

    # identify as basic block, jxx/loop true/false target
    bb.append(idc.next_head(ea))
    bb.append(operand)

def set_color():
    for ea in bb:
        idc.set_color(ea, CIC_ITEM, 0x6699ff)

def check_unicode(ea):
    if get_type(ea) in ['const WCHAR', 'WCHAR', 'wchar_t']:
        idaapi.create_strlit(ea, 0, STRTYPE_C_16); auto_wait();
        if get_str_type(ea) and get_str_type(ea)&0xFF != STRTYPE_C_16 and get_wide_word(ea) != 0:
            print '[WARN] Possible unicode @', H(ea)

def check_guid(ea):
    if get_type(ea) in ['CLSID', 'IID']:
        print '[INFO] Fixed', get_type(ea), '@', H(ea)
        MakeUnknown(ea, 10, DOUNK_SIMPLE); auto_wait();
        SetType(ea, get_type(ea))
    t = idc.get_cmt(ea, 0).upper()[1:] if idc.get_cmt(ea, 0) else ''
    if t in ['CLSID', 'IID']:
        l = idc.get_operand_value(ea, 0)
        if idaapi.getseg(l) and idaapi.getseg(l).perm and idaapi.SEGPERM_EXEC and (not get_type(l)):
            print '[INFO] Fixed', t, '@', H(l)
            MakeUnknown(l, 10, DOUNK_SIMPLE); auto_wait();
            SetType(l, t)

def check_stack_frame(ea):
    snip = ['mov     edi, edi',
    'push    ebp',
    'mov     ebp, esp',
    'sub     esp, ']    # TODO: add/and esp
    if idc.GetDisasm(ea) != snip[0] or idc.GetDisasm(next_head(ea)) != snip[1] or idc.GetDisasm(next_head(next_head(ea))) != snip[2]:
        return
    line = idc.GetDisasm(next_head(next_head(next_head(ea))))
    if line.startswith(snip[3]):
        stk_frame[ea] = ((next_head(ea+5)-(ea+5)), int(line.split(',')[-1].strip('h'), 16))

possible_code = []
def check_suspicious_data(segea):
    ff = [find_func_end(funcea) for funcea in Functions(segea, get_segm_end(segea))]
    for i,j in enumerate(ff):
        ofs = j
        while get_wide_byte(ofs) == 0xCC or get_wide_byte(ofs) == 0x90:
            ofs = ofs + 1
        if get_wide_word(ofs) == 0xff8b:                                                         # mov edi, edi
            create_insn(ofs)
            continue
        for h in range(ofs, ofs+0x80):
            if (is_code(get_full_flags(h)) or
                (get_str_type(h) != None) or                                         # string
                (get_type(h) != None) or                                               # struct
                ('offset' in GetDisasm(h) or 'rva' in GetDisasm(h)) or              # valid data
                ('.' in GetDisasm(h)) or                                              # floating point
                (get_wide_dword(h) == 0xfffffffe or get_wide_dword(h) == 0xFFFFFFE4) or               # GSCookieOffset
                ((get_wide_dword(h) >> 8) == 0) or                                             # integer
                ('align' in GetDisasm(h))                                              # alignment
                ):
                break
            if (get_wide_byte(h) in [0xe0, 0xe1, 0xe2, 0xe3, 0xe8, 0xe9, 0xeb] or             # search for branch
                (0x70 <= get_wide_byte(h) <= 0x7f) or
                (get_wide_byte(h) == 0x67 and get_wide_byte(h+1) == 0xe3) or
                (get_wide_byte(h) == 0x0f and (0x80 <= get_wide_byte(h+1) <= 0x8f))):
                possible_code.append(H(h))
                break
    auto_wait()

def add_rip_relative_inst(head):
    return
    # TODO, 64-bit use rip-relative rather than relocation

def output_file():
    ida_dump = {'bb': bb, 'relative': relative, 'rip_inst': rip_inst, 'idata': idata, 'stk_frame': stk_frame, 'code_loc': code_loc}
    print '[INFO]', str(len(bb)), 'blocks'
    print '[INFO]', str(len(relative)), 'branches'
    print '[INFO]', idc.get_input_file_path()+'.dump.txt is created'
    with open(idc.get_input_file_path()+'.dump.txt', 'w+') as f:
        f.write(repr(ida_dump)+'\n')

def partial_exclude(start, end=None):
    if end is None:
        # clear whole function
        start = NextFunction(PrevFunction(start))
        end = find_func_end(start)
    for h in Heads(start, end):
        if h in bb:
            set_color(h, CIC_ITEM, 0xffffff)
            bb.remove(h)
    output_file()

def partial_include(expr):
    global bb
    func = lambda x: re.search(expr, GetFunctionName(x))
    bbb = filter(func, bb)
    for h in list(set(bb)-set(bbb)):
        set_color(h, CIC_ITEM, 0xffffff)
    bb = bbb
    output_file()

code_loc = {}
def process(text):
    global code_loc
    check_suspicious_data(text)
    code_start = None
    for h in Heads(text, get_segm_end(text)):
        check_unicode(h)
        if is_code(get_full_flags(h)):
            if not code_start:
                code_start = h
            check_stack_frame(h)
            check_guid(h)
#            add_rip_relative_inst(h)
            add_basic_block(h)
            add_relative(h)
        else:
            if code_start:
                code_loc[code_start] = h
                code_start = None

#################################
# partial_include() and partial_exclude() provides manual partial instrumentation
# 
# partial_include('(_?Cm|_Hv[^il])')
# partial_exclude(ScreenEA())
# partial_exclude(0x401020, 0x401040)
#

auto_wait()
bb = []
relative = {}
rip_inst = []
idata = []
stk_frame = {}

idata = [[x, get_segm_end(x)] for x in Segments() if (idaapi.getseg(x).perm & idaapi.SEGPERM_EXEC) and idc.get_segm_name(x) == '.idata']
seg = [[x, get_segm_end(x)] for x in Segments() if (idaapi.getseg(x).perm & idaapi.SEGPERM_EXEC) and idc.get_segm_name(x) != '.idata']
for ea,_ in seg:
    process(ea)

bb = sorted(list(set(bb)))
set_color()

# dump result
if len(possible_code):
    print '[WARN]',str(len(possible_code)),'possible code ?', str(possible_code)
if len(possible_data):
    print '[WARN]',str(len(possible_data)),'possible data ?', str(possible_data)
if not idaapi.get_inf_structure().is_64bit() and len(rip_inst):
    print '[WARN] rip-relative addressing mode on x86 ?'
print '[INFO] re-run this script if you have fixed any [WARN] message manually in IDA'
print '[INFO] partial instrumentation with partial_include() or partial_exclude() if necessary'
output_file()

