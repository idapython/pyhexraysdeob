
import ida_pro

from ida_hexrays import *

_mmat_strs = {
    MMAT_ZERO : "MMAT_ZERO",
    MMAT_GENERATED : "MMAT_GENERATED",
    MMAT_PREOPTIMIZED : "MMAT_PREOPTIMIZED",
    MMAT_LOCOPT : "MMAT_LOCOPT",
    MMAT_CALLS : "MMAT_CALLS",
    MMAT_GLBOPT1 : "MMAT_GLBOPT1",
    MMAT_GLBOPT2 : "MMAT_GLBOPT2",
    MMAT_GLBOPT3 : "MMAT_GLBOPT3",
    MMAT_LVARS : "MMAT_LVARS",
}

def mba_maturity_t_to_string(mmt):
    return _mmat_strs.get(mmt, "???")

def mopt_t_to_string(t):
    if t == mop_z: return "mop_z"
    elif t == mop_r: return "mop_r"
    elif t == mop_n: return "mop_n"
    elif t == mop_str: return "mop_str"
    elif t == mop_d: return "mop_d"
    elif t == mop_S: return "mop_S"
    elif t == mop_v: return "mop_v"
    elif t == mop_b: return "mop_b"
    elif t == mop_f: return "mop_f"
    elif t == mop_l: return "mop_l"
    elif t == mop_a: return "mop_a"
    elif t == mop_h: return "mop_h"
    elif t == mop_c: return "mop_c"
    elif t == mop_fn: return "mop_fn"
    elif t == mop_p: return "mop_p"
    elif t == mop_sc: return "mop_sc"
    else: return "???"

def mcode_t_to_string(o):
    if o.opcode == m_nop: return "m_nop"
    elif o.opcode == m_stx: return "m_stx(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_ldx: return "m_ldx(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_ldc: return "m_ldc(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_mov: return "m_mov(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_neg: return "m_neg(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_lnot: return "m_lnot(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_bnot: return "m_bnot(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_xds: return "m_xds(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_xdu: return "m_xdu(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_low: return "m_low(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_high: return "m_high(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_add: return "m_add(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_sub: return "m_sub(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_mul: return "m_mul(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_udiv: return "m_udiv(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_sdiv: return "m_sdiv(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_umod: return "m_umod(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_smod: return "m_smod(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_or: return "m_or(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_and: return "m_and(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_xor: return "m_xor(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_shl: return "m_shl(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_shr: return "m_shr(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_sar: return "m_sar(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_cfadd: return "m_cfadd(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_ofadd: return "m_ofadd(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_cfshl: return "m_cfshl(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_cfshr: return "m_cfshr(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_sets: return "m_sets(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_seto: return "m_seto(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setp: return "m_setp(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setnz: return "m_setnz(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setz: return "m_setz(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setae: return "m_setae(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setb: return "m_setb(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_seta: return "m_seta(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setbe: return "m_setbe(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setg: return "m_setg(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setge: return "m_setge(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setl: return "m_setl(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_setle: return "m_setle(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jcnd: return "m_jcnd(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jnz: return "m_jnz(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jz: return "m_jz(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jae: return "m_jae(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jb: return "m_jb(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_ja: return "m_ja(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jbe: return "m_jbe(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jg: return "m_jg(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jge: return "m_jge(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jl: return "m_jl(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jle: return "m_jle(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_jtbl: return "m_jtbl(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t),)
    elif o.opcode == m_ijmp: return "m_ijmp(%s,%s)" % (mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_goto: return "m_goto(%s)" % (mopt_t_to_string(o.l.t),)
    elif o.opcode == m_call: return "m_call(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_icall: return "m_icall(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_ret: return "m_ret"
    elif o.opcode == m_push: return "m_push(%s)" % (mopt_t_to_string(o.l.t),)
    elif o.opcode == m_pop: return "m_pop(%s)" % (mopt_t_to_string(o.d.t),)
    elif o.opcode == m_und: return "m_und(%s)" % (mopt_t_to_string(o.d.t),)
    elif o.opcode == m_ext: return "m_ext(???)"
    elif o.opcode == m_f2i: return "m_f2i(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_f2u: return "m_f2u(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_i2f: return "m_i2f(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_u2f: return "m_u2f(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_f2f: return "m_f2f(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_fneg: return "m_fneg(%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_fadd: return "m_fadd(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_fsub: return "m_fsub(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_fmul: return "m_fmul(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)
    elif o.opcode == m_fdiv: return "m_fdiv(%s,%s,%s)" % (mopt_t_to_string(o.l.t), mopt_t_to_string(o.r.t), mopt_t_to_string(o.d.t),)

def report(msg):
    print(">>> %s" % msg)

def report_success(msg):
    return report("SUCCESS: %s" % msg)

def report_info(msg):
    print("[I] %s" % msg)

def report_info3(msg):
    print("[III] %s" % msg)

def report_error(msg):
    print("[E] %s" % msg)

def report_error3(msg):
    print("[EEE] %s" % msg)

def report_debug(msg):
    # print("[D] %s" % msg)
    pass
