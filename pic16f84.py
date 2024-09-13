import json
import sys

import idaapi
from idaapi import *

class NamedEnum:
    """
    Base class for enumerations (like instructions...)
    Usage:
    class Yadda(NamedEnum):
        def __init__(self, name, whatever):
            NamedEnum.__init__(self, name)
            self.whatever = whatever

        def __str__(self):
            return "Yadda(id={self.id}, name={self.name}, whatever={self.whatever}".format(self=self)

    Yadda("alpha", 42)
    Yadda("beta", 111)

    x = Yadda.alpha
    y = Yadda.__dict__["beta"]
    x.id == 0
    x.name == "alpha"
    y.id == 1
    y.name == "beta"
    len(Yadda._all) == 2
    x == Yadda._all[0]
    y == Yadda._all[1]
    for y in Yadda._all:
        pass
    """
    _all = None

    def __init__(self, name):
        cls = self.__class__
        if cls._all is None:
            cls._all = []
        self.id = len(cls._all)
        cls._all.append(self)

        self.name = name
        cls.__dict__[self.name] = self

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "{self.__class__.__name__}(name={self.name})".format(self=self)


class OpType(NamedEnum):
    pass

OpType("NONE")      # no operands
OpType("W")         # changes W
OpType("F")         # fff ffff in bit0..bit6
#OpType("DF")        # d in bit7, fff ffff in bit0..bit6, see comment below
OpType("B")         # bbb in bit7..bit9
OpType("LITERAL")   # kkkk kkkk in bit0..bit7
OpType("ADDR")      # kkk kkkk kkkk in bit0..bit10
OpType("OPTION")    # (only for deprecated "OPTION")
OpType("TRIS")      # fff in bit0..bit2 (only for deprecated "TRIS")

# NOTE:
# Most of the byte-oriented file reg ops have a "d" bit that specifies the
# destination (d=0 for dest=W, d=1 for dest=register), but the IDA concept
# instruction_t requires that we specify which operand is changed and which
# isn't, so it cannot handle this dynamic destination.
#
# Therefore we need separate instruction_t-s for dest=W and dest=reg, so we
# need to change the official mnemonics a bit.
#
# Where it makes sense, I just follow the logic of "MOVWF = move W to F",
# so "ADDWF f, 1" will remain "ADDWF = add W to F", but "ADDWF f, 0" becomes
# "ADDFW = add F to W"
#
# Sometimes it doesn't make sense, eg. "COMF f, 1" still remains
# "COMF = complement F", but "COMF f, 0" means "complement F but store it
# into W", so it becomes "COMF_W".
#
# "MOVF" is especially nice, as "MOVF f, 0" means "move F to W" so it becomes
# "MOVFW", but 'MOVF f, 1" means "move F to F (and set ZF)", so it becomes
# "TESTF" :)
#
# "SUBWF" is again an exception, as its naive meaning is "subtract W from F",
# which is nice for "SUBWF f, 1", but "SUBWF f, 0" is problematic, because 
# subtraction is not commutative, so "SUBFW" would mean "subtract F from W",
# which suggests the inverse of the actual result, as "SUBWF f, 0" still
# subtracts W from F, just it stores the result into W, so it must become "SUBWF_W".

# Extra feature to specify skip instructions, used only in the constructor call
CF_SKIP = 0x20000

# Mask for CF_USEx and CF_CHGx
CF_USEx = CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5 | CF_USE6
CF_CHGx = CF_CHG1 | CF_CHG2 | CF_CHG3 | CF_CHG4 | CF_CHG5 | CF_CHG6
CF_USEx_CHGx = CF_USEx | CF_CHGx 

class Instruction(NamedEnum):
    """
    The instruction set
    """
    def __init__(self, name, mask, value, feature=0, op1_type=OpType.NONE, op2_type=OpType.NONE):
        NamedEnum.__init__(self, name)
        self.mask = mask
        self.value = value
        self.op1_type = op1_type
        self.op2_type = op2_type
        # separate the skip feature from the rest
        if (feature & CF_SKIP) != 0:
            feature &= ~CF_SKIP
            self.skip = True
        else:
            self.skip = False

        # deduce the use-change features unless explicitly specified
        if (feature & CF_USEx_CHGx) == 0:
            if op1_type == OpType.NONE:
                # no operand, nothing to deduce
                pass
            elif op2_type == OpType.NONE:
                # single operand, uses it, and changes it if it's not an address
                feature |= CF_USE1
                if op1_type != OpType.ADDR:
                    feature |= CF_CHG1
            else:
                # two operands, uses both and changes the 2nd one
                feature |= CF_USE1 | CF_USE2 | CF_CHG2

        self.feature = feature


    def __str__(self):
        return "{self.__class__.__name__}(id={self.id}, name={self.name}, mask={self.mask}, value={self.value}, op1_type={self.op1_type}, op2_type={self.op2_type})".format(self=self)


# byte oriented file register operations
Instruction("CLRF",     0x3f80, 0x0180, 0, OpType.F)
Instruction("CLRW",     0x3f80, 0x0100, 0, OpType.W)
Instruction("MOVWF",    0x3f80, 0x0080, 0, OpType.W, OpType.F)

Instruction("ADDFW",    0x3f80, 0x0700, 0, OpType.F, OpType.W)
Instruction("ADDWF",    0x3f80, 0x0780, 0, OpType.W, OpType.F)
Instruction("ANDFW",    0x3f80, 0x0500, 0, OpType.F, OpType.W)
Instruction("ANDWF",    0x3f80, 0x0580, 0, OpType.W, OpType.F)
Instruction("COMF_W",   0x3f80, 0x0900, 0, OpType.F, OpType.W)
Instruction("COMF",     0x3f80, 0x0980, 0, OpType.F)
Instruction("DECF_W",   0x3f80, 0x0300, 0, OpType.F, OpType.W)
Instruction("DECF",     0x3f80, 0x0380, 0, OpType.F)
Instruction("DECFSZ_W", 0x3f80, 0x0b00, CF_SKIP, OpType.F, OpType.W)
Instruction("DECFSZ",   0x3f80, 0x0b80, CF_SKIP, OpType.F)
Instruction("INCF_W",   0x3f80, 0x0a00, 0, OpType.F, OpType.W)
Instruction("INCF",     0x3f80, 0x0a80, 0, OpType.F)
Instruction("INCFSZ_W", 0x3f80, 0x0f00, CF_SKIP, OpType.F, OpType.W)
Instruction("INCFSZ",   0x3f80, 0x0f80, CF_SKIP, OpType.F)
Instruction("IORFW",    0x3f80, 0x0400, 0, OpType.F, OpType.W)
Instruction("IORWF",    0x3f80, 0x0480, 0, OpType.W, OpType.F)
Instruction("MOVFW",    0x3f80, 0x0800, 0, OpType.F, OpType.W)
Instruction("TESTF",    0x3f80, 0x0880, 0, OpType.F)
Instruction("RLF_W",    0x3f80, 0x0d00, 0, OpType.F, OpType.W)
Instruction("RLF",      0x3f80, 0x0d80, 0, OpType.F)
Instruction("RRF_W",    0x3f80, 0x0c00, 0, OpType.F, OpType.W)
Instruction("RRF",      0x3f80, 0x0c80, 0, OpType.F)
Instruction("SUBWF_W",  0x3f80, 0x0200, 0, OpType.F, OpType.W)
Instruction("SUBWF",    0x3f80, 0x0280, 0, OpType.W, OpType.F)
Instruction("SWAPF_W",  0x3f80, 0x0e00, 0, OpType.F, OpType.W)
Instruction("SWAPF",    0x3f80, 0x0e80, 0, OpType.F)
Instruction("XORFW",    0x3f80, 0x0600, 0, OpType.F, OpType.W)
Instruction("XORWF",    0x3f80, 0x0680, 0, OpType.W, OpType.F)

# bit oriented file register operations
Instruction("BCF",      0x3c00, 0x0100, 0, OpType.B, OpType.F)
Instruction("BSF",      0x3c00, 0x0140, 0, OpType.B, OpType.F)
Instruction("BTFSC",    0x3c00, 0x0180, CF_SKIP | CF_USE1 | CF_USE2, OpType.B, OpType.F)
Instruction("BTFSS",    0x3c00, 0x01c0, CF_SKIP | CF_USE1 | CF_USE2, OpType.B, OpType.F)
# literal operations
Instruction("ADDLW",    0x3e00, 0x3e00, 0, OpType.LITERAL, OpType.W)
Instruction("ANDLW",    0x3f00, 0x3900, 0, OpType.LITERAL, OpType.W)
Instruction("IORLW",    0x3f00, 0x3800, 0, OpType.LITERAL, OpType.W)
Instruction("MOVLW",    0x3c00, 0x3000, 0, OpType.LITERAL, OpType.W)
Instruction("SUBLW",    0x3e00, 0x3c00, 0, OpType.LITERAL, OpType.W)
Instruction("XORLW",    0x3f00, 0x3a00, 0, OpType.LITERAL, OpType.W)
# literal and control operations
Instruction("RETLW",    0x3c00, 0x3400, 0, OpType.LITERAL, OpType.W)
# control operations
Instruction("CALL",     0x3800, 0x2000, CF_CALL, OpType.ADDR)
Instruction("CLRWDT",   0x3fff, 0x0064)
Instruction("GOTO",     0x3800, 0x2800, CF_JUMP | CF_STOP, OpType.ADDR)
Instruction("NOP",      0x3f9f, 0x0000)
Instruction("RETFIE",   0x3fff, 0x0009, CF_STOP)
Instruction("RETURN",   0x3fff, 0x0008, CF_STOP)
Instruction("SLEEP",    0x3fff, 0x0063)
# deprecated operations
Instruction("OPTION",   0x3fff, 0x0062, 0, OpType.W, OpType.OPTION)
Instruction("TRIS",     0x3ff8, 0x0060, 0, OpType.W, OpType.TRIS)


class picmicro_processor_t(idaapi.processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1684
    # Processor features
    flag = PR_RNAMESOK | PRN_HEX | PR_WORD_INS | PR_NO_SEGMOVE | PR_SEGS
    # PR_BINMEM, PR_SEGTRANS see codeSeg()
  
    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 16

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ["p16f84"]

    # long processor names
    # No restriction on name lengthes.
    plnames = ["PICMicro PIC16F84"]

    # size of a segment register in bytes
    segreg_size = 2

    # Array of typical code start sequences (optional)
    # codestart = ["\x60\x00"]  # 60 00 xx xx: MOVqw         SP, SP-delta

    # Array of "return" instruction opcodes (optional)
    # retcodes = ["\x04\x00"]   # 04 00: RET

    # You should define 2 virtual segment registers for CS and DS.
    # Let's call them rVcs and rVds.

    # icode of the first instruction
    instruc_start = 0

    # Size of long double (tbyte) for this processor
    # (meaningful only if ash.a_tbyte != NULL)
    tbyte_size = 0

    assembler = {
        "flag" : ASH_HEXF3 | AS_COLON | ASB_BINF0 | ASO_OCTF1 | AS_NCMAS,
        # user defined flags (local only for IDP) you may define and use your own bits
        "uflag" : 0,

        # Assembler name (displayed in menus)
        "name": "gpasm",

        # org directive
        "origin": "ORG",

        # end directive
        "end": "end",

        # comment string (see also cmnt2)
        "cmnt": ";",

        # ASCII string delimiter
        "ascsep": "\"",

        # ASCII char constant delimiter
        "accsep": "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        "esccodes": "\"'",

        # Data representation (db,dw,...):
        # ASCII string directive
        "a_ascii": "DA",
        # byte directive
        "a_byte": "DB",
        # word directive
        "a_word": "DW",
        #"a_dword": "DD",
        #"a_qword": "DQ",
        #"a_oword": ".int128",
        #"a_float": ".float",
        #"a_double": ".double",
        #"a_tbyte": "DT",
        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers for byte, word, dword, qword, float, double, oword
        #"a_dups": "#d dup (#v)",

        # uninitialized data directive (should include "%s" for the size of data)
        "a_bss": "%s dup ?",

        # "seg" prefix (example: push seg seg001)
        "a_seg": "seg",

        # current IP (instruction pointer) symbol in assembler
        "a_curip": "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        "a_public": "",

        # "weak" name keyword. NULL-gen default, ""-do not generate
        "a_weak": "",

        # "extrn" name keyword
        "a_extrn": "EXTERN",

        # "comm" (communal variable)
        "a_comdef": "",

        # "align" keyword
        "a_align": "ALIGN",

        # operators used in complex expressions
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",

        # size of type (format string)
        "a_sizeof_fmt": "size %s",
    }

    # ----------------------------------------------------------------------
    # Processor module callbacks
    # ----------------------------------------------------------------------
    def get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        """
        return 0

    # ----------------------------------------------------------------------
    def notify_get_autocmt(self):
        """
        Get instruction comment. "cmd" describes the instruction in question
        @return: None or the comment string
        """
        return None

    # ----------------------------------------------------------------------
    def _ana_op(self, op, op_type, opcode):
        if op_type == OpType.NONE:
            op.type = o_void
            op.dtyp = dt_void

        elif op_type == OpType.W:
            # register W
            op.type = o_reg
            op.dtyp = dt_byte
            op.reg = 0  # W == self.regNames[0], FIXME: don't use hard constant

        elif op_type == OpType.F:
            # fff ffff in bit0..bit6
            op.type = o_mem
            op.dtyp = dt_byte
            op.addr = dataSeg() + (opcode & 0x7f) # FIXME: bank handling, see RP0 / STATUS[5]

        elif op_type == OpType.B:
            # bbb in bit7..bit9
            op.type = o_imm
            op.dtyp = dt_byte
            op.value = (opcode & 0x380) >> 7

        elif op_type == OpType.LITERAL:
            # kkkk kkkk in bit0..bit7
            op.type = o_imm
            op.dtyp = dt_byte
            op.value = opcode & 0xff

        elif op_type == OpType.ADDR:
            # kkk kkkk kkkk in bit0..bit10
            op.type = o_near
            op.dtyp = dt_word
            op.addr = opcode & 0x3ff

        elif op_type == OpType.OPTION:
            # only for deprecated "OPTION"
            op.type = o_mem
            op.dtyp = dt_byte
            op.addr = 0x81

        elif op_type == OpType.TRIS:
            # fff in bit0..bit2 (only for deprecated "TRIS")
            op.type = o_mem
            op.dtyp = dt_byte
            op.addr = dataSeg() + 0x80 + (opcode & 0x07) # the TRIS registers

        else:
            # illegal op_type
            print("P16F84._ana_op(opcode=0x{opcode:x}, op_type={op_type}) -> False".format(
                opcode=opcode,
                op_type=op_type
            ))
            return False

        print("P16F84._ana_op(opcode=0x{opcode:x}, op_type={op_type}) -> op.type={op.type}, op.dtyp={op.dtyp}".format(
            opcode=opcode,
            op_type=op_type,
            op=op
        ))

        op.offb = 0;
        return True


    def ana(self):
        """
        Decodes an instruction into the C global variable 'cmd'
        """
        # get the opcode

        # NOTE: We have cnbits=16, but
        # - ua_next_byte() returns only the lower half of that 16-bit "byte"
        # - ua_next_word() returns the lower halves of 2 consecutive "bytes" concatenated
        # So we must use get_original_byte(self.cmd.ea), AND manually increment self.cmd.size

        opcode = get_original_byte(self.cmd.ea)
        self.cmd.size += 1
        print("P16F84.ana ea=0x{ea:x}, opcode=0x{opcode:x}".format(ea=self.cmd.ea, opcode=opcode))
        # print("P16F84 dataSeg=0x{ds:x}".format(ds=dataSeg()))

        # find the matching instruction
        instr = None
        for i in Instruction._all:
            if (opcode & i.mask) == i.value:
                instr = i
                break
        else:
            # illegal instruction
            print("P16F84.ana opcode=0x{opcode:x} not found".format(opcode=opcode))
            return 0

        self.cmd.itype = instr.id

        if not self._ana_op(self.cmd.Op1, instr.op1_type, opcode):
            return 0
        if not self._ana_op(self.cmd.Op2, instr.op2_type, opcode):
            return 0
            
        print("P16F84.ana ea=0x{ea:x}, opcode=0x{opcode:x}, instr={instr}, size={size}".format(
            ea=self.cmd.ea,
            opcode=opcode,
            instr=instr,
            size=self.cmd.size
        ))
        return self.cmd.size


    # ----------------------------------------------------------------------
    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in "cmd" structure.
        If zero is returned, the kernel will delete the instruction.
        """
        feature = self.cmd.get_canon_feature()
        print("P16F84.emu feature=0x{feature:x}".format(feature=feature))

        if feature & CF_USE1:
            pass
        if feature & CF_CHG1:
            pass
        if feature & CF_USE2:
            pass
        if feature & CF_CHG2:
            pass
        if feature & CF_SHFT:
            pass
        if feature & CF_STOP:
            pass
        if feature & CF_CALL:
            op = self.cmd.Op1 # FIXME: don't hardwire Op1
            ua_add_cref(op.offb, op.addr, fl_CN)
            pass
        if feature & CF_JUMP:
            op = self.cmd.Op1 # FIXME: don't hardwire Op1
            QueueSet(Q_jumps, self.cmd.ea)
            ua_add_cref(op.offb, op.addr, fl_JN)

        flow = (feature & CF_STOP == 0) and (feature & CF_JUMP == 0)
        print("P16F84.emu flow=flow".format(flow=flow))
        if flow:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        instr = Instruction._all[self.cmd.itype]
        if instr.skip:
            # QueueSet(Q_jumps, self.cmd.ea) # FIXME: do we need this? what does it do?
            ua_add_cref(0, self.cmd.ea + self.cmd.size + 1, fl_JN)

        return 1

    # ----------------------------------------------------------------------
    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        print("P16F84.out_op(op.type={op.type}, op.dtyp={op.dtyp})".format(op=op))
        if op.type == o_reg:
            out_register(self.regNames[op.reg])
        elif op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type in [o_near, o_mem]:
            r = out_name_expr(op, op.addr, BADADDR)
            if not r:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)
        return True

    # ----------------------------------------------------------------------
    def out(self):
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        """
        print("P16F84.out()")
        buf = idaapi.init_output_buffer(1024)
    
        OutMnem(12)
    
        out_one_operand(0)
    
        for i in range(1, 4):
            op = self.cmd[i]
    
            if op.type == o_void:
                break
    
            out_symbol(',')
            OutChar(' ')
            out_one_operand(i)
    
        term_output_buffer()
    
        cvar.gl_comm = 1
        print("P16F84.out() -> {buf}".format(buf=buf))
        MakeLine(buf)

    # ----------------------------------------------------------------------
    def __init__(self):
        idaapi.processor_t.__init__(self)

        print("P16F84.__init__ start")

        # self._data_seg = add_segm(0, 0x8000, 0x8180, "RAM", SEG_DATA)

        real_regs = [
            # There is only one "hardcore" register: W, all the others
            # (incl. PC and STATUS) are available as memory, so from a CPU
            # viewpoint they are like memory-mapped peripheral registers.
            "W"
        ]

        fake_regs = [
            # Fake segment registers
            "CS",
            "DS"
        ]

        self.regNames = real_regs + fake_regs
        fake_regs_start = len(real_regs)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.regFirstSreg = fake_regs_start
        self.regLastSreg  = fake_regs_start + 1

        # number of CS register
        self.regCodeSreg = fake_regs_start

        # number of DS register
        self.regDataSreg = fake_regs_start + 1

        self.instruc = [{
            "name": i.name,
            "feature": i.feature,
            "cmt": "",
        } for i in Instruction._all]
        self.instruc_end = len(Instruction._all)
        
        print("P16F84.__init__ self.instruc={i}".format(i=json.dumps(self.instruc)))
        print("P16F84.__init__ done")

# ----------------------------------------------------------------------
def PROCESSOR_ENTRY():
  return picmicro_processor_t()
