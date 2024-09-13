# ----------------------------------------------------------------------
# EFI bytecode processor module
# (c) Hex-Rays
# Please send fixes or improvements to support@hex-rays.com

import sys
import idaapi
from idaapi import *

# ----------------------------------------------------------------------
class ebc_processor_t(idaapi.processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = idaapi.PLFM_EBC

    # Processor features
    flag = PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['ebc']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['EFI Byte code']

    # size of a segment register in bytes
    segreg_size = 0

    # Array of typical code start sequences (optional)
    # codestart = ['\x60\x00']  # 60 00 xx xx: MOVqw         SP, SP-delta

    # Array of 'return' instruction opcodes (optional)
    # retcodes = ['\x04\x00']   # 04 00: RET

    # You should define 2 virtual segment registers for CS and DS.
    # Let's call them rVcs and rVds.

    # icode of the first instruction
    instruc_start = 0

    #
    #      Size of long double (tbyte) for this processor
    #      (meaningful only if ash.a_tbyte != NULL)
    #
    tbyte_size = 0

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP)
        # you may define and use your own bits
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "EFI bytecode assembler",

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

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
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

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

        # size of type (format string)
        'a_sizeof_fmt': "size %s",
    } # Assembler

    # ----------------------------------------------------------------------
    # Processor module callbacks
    #
    # ----------------------------------------------------------------------
    def get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        for EBC it's 8 bytes of the actual return address
        plus 8 bytes of the saved frame address
        """
        return 16

    # ----------------------------------------------------------------------
    def notify_get_autocmt(self):
        """
        Get instruction comment. 'cmd' describes the instruction in question
        @return: None or the comment string
        """

    # ----------------------------------------------------------------------
    def can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """

    # ----------------------------------------------------------------------
    def is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """

    # ----------------------------------------------------------------------
    def notify_newfile(self, filename):
        ...

    # ----------------------------------------------------------------------
    def notify_oldfile(self, filename):
        ...

    # ----------------------------------------------------------------------
    def header(self):
        """function to produce start of disassembled text"""
        MakeLine("; natural unit size: %d bits" % (self.PTRSZ*8), 0)

    # ----------------------------------------------------------------------
    def notify_may_be_func(self, state):
        """
        can a function start here?
        the instruction is in 'cmd'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """

    # ----------------------------------------------------------------------
    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
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
        return True

    # ----------------------------------------------------------------------
    # Generate text representation of an instruction in 'cmd' structure.
    # This function shouldn't change the database, flags or anything else.
    # All these actions should be performed only by u_emu() function.
    def out(self):
        # Init output buffer
        buf = idaapi.init_output_buffer(1024)


        OutMnem(12, postfix)

        out_one_operand( 0 )

        for i in xrange(1, 3):
            op = self.cmd[i]

            if op.type == o_void:
                break

            out_symbol(',')
            OutChar(' ')
            out_one_operand(i)

        if self.cmd.itype == self.itype_MOVREL:
            fnaddr = ...
            if fnaddr != None:
                nm = get_name(BADADDR, fnaddr)
                if nm:
                    out_line("; Thunk to " + nm, COLOR_AUTOCMT)
        term_output_buffer()

        cvar.gl_comm = 1
        MakeLine(buf)

    # ----------------------------------------------------------------------
    def ana(self):
        """
        Decodes an instruction into the C global variable 'cmd'
        """

        # take opcode byte
        b = ua_next_byte()

        # the 6bit opcode
        opcode = b & 0x3F

        # opcode supported?
        try:
            ins = self.itable[opcode]
            # set default itype
            self.cmd.itype = getattr(self, 'itype_' + ins.name)
        except:
            return 0
        # call the decoder
        return self.cmd.size if ins.d(b) else 0

    # ----------------------------------------------------------------------
    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.PTRSZ = 4 # Assume PTRSZ = 4 by default
        ...
        ...

# ----------------------------------------------------------------------
def PROCESSOR_ENTRY():
    return ebc_processor_t()
