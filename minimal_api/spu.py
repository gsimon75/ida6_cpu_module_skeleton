# SPU (Cell Broadband Engine Synergistic Processor Unit)
# Contributed by Felix Domke

import sys
import idaapi
from idaapi import *

class spu_processor_t(idaapi.processor_t):
  id = idaapi.PLFM_SPU
  flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
  cnbits = 8
  dnbits = 8
  psnames = ['spu']
  plnames = ['SPU']
  segreg_size = 0
  instruc_start = 0
  tbyte_size = 0
  assembler = {
    'flag' : ASH_HEXF3 | AS_COLON | ASB_BINF0 | ASO_OCTF1 | AS_NCMAS,
    'uflag' : 0,
    'name': "GNU assembler",
    'origin': ".org",
    'end': "end",
    'cmnt': ";",
    'ascsep': "\"",
    'accsep': "'",
    'esccodes': "\"'",
    'a_ascii': ".ascii",
    'a_byte': ".byte",
    'a_word': ".short",
    'a_dword': ".int",
    'a_qword': ".quad",
    'a_oword': ".int128",
    'a_float': ".float",
    'a_double': ".double",
    #'a_tbyte': "dt",
    #'a_dups': "#d dup(#v)",
    'a_bss': "dfs %s",
    'a_seg': "seg",
    'a_curip': ".",
    'a_public': "public",
    'a_weak': "weak",
    'a_extrn': ".extrn",
    'a_comdef': "",
    'a_align': ".align",
    'lbrace': "(",
    'rbrace': ")",
    'a_mod': "%",
    'a_band': "&",
    'a_bor': "|",
    'a_xor': "^",
    'a_bnot': "~",
    'a_shl': "<<",
    'a_shr': ">>",
    'a_sizeof_fmt': "size %s",
  }

  FL_SIGNED = 0x01  # value/address is signed; output as such
  FL_D      = 0x02  # d suffix (disable interrupts)
  FL_E      = 0x04  # e suffix (enable interrupts)
  FL_C      = 0x08  # c suffix (syncc - sync channels)
  FL_P      = 0x10  # p suffix (inline prefetching)

  # ----------------------------------------------------------------------
  # Processor module callbacks
  #
  # ----------------------------------------------------------------------
  def get_frame_retsize(self, func_ea):
      """
      Get size of function return address in bytes
      SPU doesn't use stack but the link register
      """
      return 0

  # ----------------------------------------------------------------------
  def notify_get_autocmt(self):
      """
      Get instruction comment. 'cmd' describes the instruction in question
      @return: None or the comment string
      """
      if self.cmd.itype in self.comments:
         return self.comments[self.cmd.itype]

  # ----------------------------------------------------------------------
  def is_align_insn(self, ea):
    return 2 if get_word(ea) == 0 else 0

  # ----------------------------------------------------------------------
  def notify_newfile(self, filename):
    pass

  # ----------------------------------------------------------------------
  def notify_oldfile(self, filename):
    pass

  # ----------------------------------------------------------------------
  def emu(self):
    Feature = self.cmd.get_canon_feature()

    if Feature & CF_JUMP:
        QueueSet(Q_jumps, self.cmd.ea)

    flow = (Feature & CF_STOP == 0)
    if flow:
      ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

    # create stack vars for ai rd, sp, offs
    # only if rd != sp
    if may_create_stkvars() and self.cmd.itype == self.itype_ai \
          and is_reg(self.cmd.Op2, self.ireg_sp) and not is_reg(self.cmd.Op1, self.ireg_sp) \
          and self.cmd.Op3.type == o_imm and not isDefArg(self.get_uFlag(), 2):
      ...

    # trace the stack pointer if:
    #   - it is the second analysis pass
    #   - the stack pointer tracing is allowed
    if may_trace_sp():
        if flow:
            ...
        else:
            recalc_spd(self.cmd.ea) # recalculate SP register for the next insn

    return 1

  # ----------------------------------------------------------------------
  def outop(self, op):
    optype = op.type
    fl     = op.specval
    signed = OOF_SIGNED if fl & self.FL_SIGNED != 0 else 0
    if optype == o_reg:
      out_register(self.regNames[op.reg])
    elif optype == o_imm:
      OutValue(op, OOFW_IMM | signed | (OOFW_32 if self.PTRSZ == 4 else OOFW_64))
    elif optype in [o_near, o_mem]:
      r = out_name_expr(op, op.addr, BADADDR)
      if not r:
        out_tagon(COLOR_ERROR)
        OutLong(op.addr, 16)
        out_tagoff(COLOR_ERROR)
        QueueSet(Q_noName, self.cmd.ea)
    elif optype == o_displ:
        OutValue(op, OOF_ADDR | (OOFW_32 if self.PTRSZ == 4 else OOFW_64) | signed )
        out_symbol('(')
        out_register(self.regNames[op.reg])
        out_symbol(')')
    return True

  # ----------------------------------------------------------------------
  def out(self):
    buf = idaapi.init_output_buffer(1024)

    OutMnem(15, postfix)

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
    MakeLine(buf)

  # ----------------------------------------------------------------------
  def ana(self):
    opcode = ua_next_long()

    ins = self.itable[IBITS(opcode, 0, 10)]

    if ins is None:
      return 0

    self.cmd.itype = getattr(self, 'itype_' + ins.name)
    for c in self.cmd:
      c.type = o_void
    ins.decode(self, opcode)
    ...
    return self.cmd.size

  # ----------------------------------------------------------------------
  def notify_init(self, idp_file):
    # SPU is big endian
    idaapi.cvar.inf.mf = 1
    # init returns non-zero on success
    return 1

  # ----------------------------------------------------------------------
  def __init__(self):
    idaapi.processor_t.__init__(self)
    self.PTRSZ = 4 # Assume PTRSZ = 4 by default
    ...
    ...

# ----------------------------------------------------------------------
def PROCESSOR_ENTRY():
  return spu_processor_t()
