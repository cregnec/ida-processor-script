from idaapi import *

class DecodingError(Exception):
    pass

class MyProcessor(processor_t):
    id = 0x8000 + 8888
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["myVMCPU"]
    plnames = ["My VM CPU"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "My assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = [
        "R0", "R1", "R2", "R3", "R4",
        "R5", "R6", "R7", "R7", "R8",
        "R9", "R10", "R11", "R12", "R13",
        "R14", "R15","R16", "R17", "R18",
        "R19", "R20","R21", "R22", "R23",
        "R24", "R25","R26", "R27", "R28",
        "R29", "R30",
        #virutal 
        "CS", "DS"
    ]

    instruc = instrs = [
        { 'name': 'PUSH', 'feature': CF_USE1 },
        { 'name': 'POP', 'feature': CF_USE1 },
        { 'name': 'MOV', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'ADD', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'SUB', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'IMUL', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'IDIV', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'INC', 'feature': CF_USE1 },
        { 'name': 'DEC', 'feature': CF_USE1 },
        { 'name': 'OR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'AND', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'XOR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'SHL', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'SAR', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'NOT', 'feature': CF_USE1 },
        { 'name': 'NEG', 'feature': CF_USE1 },
        { 'name': 'JZ', 'feature': CF_USE1 },
        { 'name': 'JG', 'feature': CF_USE1 },
        { 'name': 'JS', 'feature': CF_USE1 },
        { 'name': 'JLE', 'feature': CF_USE1 },
        { 'name': 'JNS', 'feature': CF_USE1 },
        { 'name': 'JNZ', 'feature': CF_USE1 },
        { 'name': 'JMP', 'feature': CF_USE1 },
        { 'name': 'CALL', 'feature': CF_USE1 | CF_CALL },
        { 'name': 'RET', 'feature': CF_STOP },
        { 'name': 'END', 'feature': CF_STOP },
        { 'name': 'IOFUNC', 'feature': CF_USE1 },
        { 'name': 'SETZ', 'feature': CF_USE1 },
        { 'name': 'INCPC', 'feature': 0},
    ]
    instruc_end = len(instruc)

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]

    def _read_cmd_dword(self):
        ea = self.cmd.ea + self.cmd.size
        dword =get_full_long(ea)
        self.cmd.size += 4
        return dword

    def _read_cmd_byte(self):
        ea = self.cmd.ea + self.cmd.size
        byte = get_full_byte(ea)
        self.cmd.size += 1
        return byte

    def _read_reg(self):
        r = self._read_cmd_byte()
        if r >= 0x20:
            raise DecodingError()
        return r

    def _ana_ntypeinstr(self, name, bytesBeforeOperand=1):
        cmd = self.cmd
        optype = self._read_cmd_byte()
        cmd.itype = self.inames[name]

        #deal with bytes before real operands (ex, return Register(s))
        if bytesBeforeOperand > 0:
            self.cmd.size += bytesBeforeOperand

        if optype in (0, 1):
            cmd[0].type = o_reg
            cmd[0].dtyp = dt_dword
            cmd[0].reg = self._read_reg()
        elif optype in (2, 4):
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_dword
            cmd[0].value = self._read_cmd_dword()

        if optype == 0x0:
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_dword
            cmd[1].reg = self._read_reg()
        elif optype == 0x1:
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_dword
            cmd[1].value = self._read_cmd_dword()
        elif optype == 0x2:
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_dword
            cmd[1].value = self._read_reg()
        elif optype == 0x4:
            cmd[1].type = o_imm
            cmd[1].dtyp = dt_dword
            cmd[1].value = self._read_cmd_dword()
        else:
            raise DecodingError()

    def _ana_one_r(self, name):
        cmd = self.cmd
        cmd.itype = self.inames[name]
        cmd[0].type = o_reg
        cmd[0].dtyp = dt_dword
        cmd[0].reg = self._read_reg()

    def _ana_two_r(self, name):
        cmd = self.cmd
        cmd.itype = self.inames[name]
        cmd[0].type = o_reg
        cmd[0].dtyp = dt_dword
        cmd[0].reg = self._read_reg()
        cmd[1].type = o_reg
        cmd[1].dtyp = dt_dword
        cmd[1].reg = self._read_reg()

    def _ana_jmp(self, name):
        cmd = self.cmd
        cmd.itype = self.inames[name]
        addr = self._read_cmd_dword()
        cmd[0].type = o_near
        cmd[0].dtyp = dt_dword
        cmd[0].addr = addr

    def _ana(self):
        cmd = self.cmd
        opcode = self._read_cmd_byte()
        if opcode == 0x0:
            cmd.size += 1
            cmd.itype = self.inames['INCPC']
        elif opcode == 0x1:
            cmd.itype = self.inames["RET"]
        elif opcode == 0x2:
            self._ana_ntypeinstr("ADD")
        elif opcode == 0x3:
            self._ana_ntypeinstr("SUB")
        elif opcode == 0x4:
            self._ana_ntypeinstr("IMUL")
        elif opcode == 0x5:
            self._ana_ntypeinstr("IDIV", bytesBeforeOperand=2)
        elif opcode == 0x6:
            self._ana_ntypeinstr("XOR")
        elif opcode == 0x7:
            #output register index
            cmd.size += 1
            self._ana_one_r("NEG")
        elif opcode == 0x8:
            #output register index
            cmd.size += 1
            self._ana_one_r("NOT")
        elif opcode == 0x9:
            self._ana_ntypeinstr("AND")
        elif opcode == 0xA:
            self._ana_ntypeinstr("OR")
        elif opcode == 0xB:
            #output register index
            cmd.size += 1
            self._ana_one_r("SETZ")
        elif opcode == 0xC:
            self._ana_ntypeinstr("SHL")
        elif opcode == 0xD:
            self._ana_ntypeinstr("SAR")
        elif opcode == 0xE:
            self._ana_jmp("JMP")
        elif opcode == 0xF:
            self._ana_jmp("CALL")
        elif opcode == 0x10:
            self._ana_jmp("JZ")
        elif opcode == 0x11:
            self._ana_jmp("JS")
        elif opcode == 0x12:
            self._ana_jmp("JLE")
        elif opcode == 0x13:
            self._ana_jmp("JG")
        elif opcode == 0x14:
            self._ana_jmp("JNS")
        elif opcode == 0x15:
            self._ana_jmp("JNZ")
        elif opcode == 0x16:
            self._ana_ntypeinstr("AND", bytesBeforeOperand=0)
        elif opcode == 0x17:
            self._ana_ntypeinstr("SUB", bytesBeforeOperand=0)
        elif opcode == 0x18:
            cmd.itype = self.inames['MOV']
            optype = self._read_cmd_byte()
            if optype == 0:
                self._ana_two_r("MOV")
            elif optype == 1:
                self._ana_one_r("MOV")
                cmd[1].type = o_imm
                cmd[1].dtyp = dt_dword
                cmd[1].value = self._read_cmd_dword()
        elif opcode == 0x19:
            self._ana_one_r("INC")
        elif opcode == 0x1A:
            self._ana_one_r("DEC")
        elif opcode == 0x1B:
            self._ana_one_r("MOV")
            cmd[1].type = o_phrase
            cmd[1].dtyp = dt_dword
            cmd[1].reg = self._read_reg()
        elif opcode == 0x1C:
            cmd.itype = self.inames['MOV']
            cmd[0].type = o_phrase
            cmd[0].dtyp = dt_dword
            cmd[0].reg = self._read_reg()
            cmd[1].type = o_reg
            cmd[1].dtyp = dt_dword
            cmd[1].reg = self._read_reg()
        elif opcode == 0x1D:
            cmd.itype = self.inames['END']
        elif opcode == 0x1E:
            optype = self._read_cmd_byte()
            if optype == 0:
                self._ana_one_r('PUSH')
            else:
                cmd.itype = self.inames['PUSH']
                cmd[0].type = o_imm
                cmd[0].dtyp = dt_dword
                cmd[0].reg = self._read_cmd_dword()
        elif opcode == 0x1F:
            self._ana_one_r('POP')
        elif opcode == 0x20:
            cmd.itype = self.inames['IOFUNC']
            cmd[0].type = o_imm
            cmd[0].dtyp = dt_byte
            cmd[0].value = self._read_cmd_byte()
        else:
            cmd.size += 1
            cmd.itype = self.inames['INCPC']
        return cmd.size

    def ana(self):
        try:
            return self._ana()
        except DecodingError:
            return 0

    def _emu_operand(self, op):
        if op.type == o_mem:
            ua_dodata2(0, op.addr, op.dtyp)
            ua_add_dref(0, op.addr, dr_R)
        elif op.type == o_near:
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(0, op.addr, fl)

    def emu(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(cmd[0])
        if ft & CF_USE2:
            self._emu_operand(cmd[1])
        if ft & CF_USE3:
            self._emu_operand(cmd[2])
        if not ft & CF_STOP:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)
        return True

    def outop(self, op):
        if op.type == o_reg:
            out_register(self.reg_names[op.reg])
        elif op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type in [o_near, o_mem]:
            ok = out_name_expr(op, op.addr, BADADDR)
            if not ok:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, self.cmd.ea)
        elif op.type == o_phrase:
            out_symbol('[')
            out_register(self.reg_names[op.reg])
            out_symbol(']')
        else:
            return False
        return True

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        OutMnem(15)
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

def PROCESSOR_ENTRY():
    return MyProcessor()
