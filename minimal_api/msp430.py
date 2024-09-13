# ----------------------------------------------------------------------
# Texas Instruments MSP430 processor module
# Copyright (c) 2010-2011 Hex-Rays
#
# This module demonstrates:
#  - instruction decoding and printing
#  - simplification of decoded instructions
#  - creation of code and data cross-references
#  - auto-creation of data items from cross-references
#  - tracing of the stack pointer changes
#  - creation of the stack variables
#  - handling of switch constructs
#
# Please send fixes or improvements to support@hex-rays.com

import sys
import idaapi
import copy
from idaapi import *

# ----------------------------------------------------------------------
class msp430_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = idaapi.PLFM_MSP430

    # Processor features
    flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_WORD_INS \
         | PR_USE32 | PR_DEFSEG32

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['msp430']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['Texas Instruments MSP430']

    # size of a segment register in bytes
    segreg_size = 0

    # Array of typical code start sequences (optional)
    codestart = ['\x0B\x12']  # 120B: push R11

    # Array of 'return' instruction opcodes (optional)
    # retcodes = ['\x30\x41']   # 4130: ret (mov.w @SP+, PC)

    # Array of instructions
    instruc = [
        {'name': '',  'feature': 0},                                # placeholder for "not an instruction"

        ...
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "Generic MSP430 assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': [".msp430"],

        # array of unsupported instructions (array of cmd.itype) (optional)
        #'badworks': [],

        # org directive
        'origin': ".org",

        # end directive
        'end': ".end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".char",

        # byte directive
        'a_byte': ".byte",

        # word directive
        'a_word': ".short",

        # remove if not allowed
        'a_dword': ".long",

        # remove if not allowed
        # 'a_qword': "dq",

        # float;  4bytes; remove if not allowed
        'a_float': ".float",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': ".space %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': ".def",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "",

        # "extrn"  name keyword
        'a_extrn': ".ref",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': ".align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # the include directive (format string) (optional)
        'a_include_fmt': '.include "%s"',
    } # Assembler


    # ----------------------------------------------------------------------
    # The following callbacks are optional
    #

    #def notify_newprc(self, nproc):
    #    """
    #    Before changing proccesor type
    #    nproc - processor number in the array of processor names
    #    return 1-ok,0-prohibit
    #    """
    #    return 1

    #def notify_assemble(self, ea, cs, ip, use32, line):
    #    """
    #    Assemble an instruction
    #     (make sure that PR_ASSEMBLE flag is set in the processor flags)
    #     (display a warning if an error occurs)
    #     args:
    #       ea -  linear address of instruction
    #       cs -  cs of instruction
    #       ip -  ip of instruction
    #       use32 - is 32bit segment?
    #       line - line to assemble
    #    returns the opcode string
    #    """
    #    pass

    def get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
             4 bytes for 32-bit function
             2 bytes otherwise
        """
        return 2

    def notify_get_autocmt(self):
        """
        Get instruction comment. 'cmd' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[self.cmd.itype]:
          return self.instruc[self.cmd.itype]['cmt']

    # ----------------------------------------------------------------------
    def notify_is_sane_insn(self, no_crefs):
        """
        is the instruction sane for the current file type?
        args: no_crefs
        1: the instruction has no code refs to it.
           ida just tries to convert unexplored bytes
           to an instruction (but there is no other
           reason to convert them into an instruction)
        0: the instruction is created because
           of some coderef, user request or another
           weighty reason.
        The instruction is in 'cmd'
        returns: 1-ok, <=0-no, the instruction isn't likely to appear in the program
        """
        return 1

    # ----------------------------------------------------------------------
    # The following callbacks are mandatory
    #
    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        if Feature & CF_JUMP:
            QueueSet(Q_jumps, self.cmd.ea)

        if flow:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        recalc_spd(self.cmd.ea) # recalculate SP register for the next insn

        return 1

    # ----------------------------------------------------------------------
    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by the emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
            out_register(self.regNames[op.reg])
            OutValue(op2, OOFW_IMM | signed )
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)
            OutValue(op, OOF_ADDR | signed | width )
            out_symbol('(')
            out_register(self.regNames[op.reg])
            out_symbol(')')
            out_symbol('@')
            out_register(self.regNames[op.reg])
              out_symbol('+')
        return True

    # ----------------------------------------------------------------------
    def out(self):
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by emu() function.
        Returns: nothing
        """
        # Init output buffer
        buf = idaapi.init_output_buffer(1024)

        # do we need to print a modifier line first?
            out_line("zc", COLOR_INSN)
            term_output_buffer()
            MakeLine(buf)
            buf = idaapi.init_output_buffer(1024)

            out_line("rpt", COLOR_INSN)
            OutChar(' ')
            out_register(self.regNames[self.cmd.segpref])
            term_output_buffer()
            MakeLine(buf)
            buf = idaapi.init_output_buffer(1024)

            out_line("rpt", COLOR_INSN)
            OutChar(' ')
            out_symbol('#')
            out_long(self.cmd.segpref, 10)
            term_output_buffer()
            MakeLine(buf)
            buf = idaapi.init_output_buffer(1024)

        OutMnem(8, postfix)

            out_one_operand(0)

            out_symbol(',')
            OutChar(' ')
            out_one_operand(i)

        term_output_buffer()
        cvar.gl_comm = 1 # generate comment at the next call to MakeLine()
        MakeLine(buf)


    # ----------------------------------------------------------------------
    # does operand match tuple m? (type, value)
    def match_op(self, op, m):
            return false

    # ----------------------------------------------------------------------
    def ana(self):
        """
        Decodes an instruction into self.cmd.
        Returns: self.cmd.size (=the size of the decoded instruction) or zero
        """
        if (self.cmd.ea & 1) != 0:
            return 0
        w = ua_next_word()
        ...
        # Return decoded instruction size or zero
        return self.cmd.size if self.cmd.itype != self.itype_null else 0

    # ----------------------------------------------------------------------
    def __init__(self):
        idaapi.processor_t.__init__(self)

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return msp430_processor_t()
