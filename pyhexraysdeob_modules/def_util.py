
from ida_hexrays import *
import ida_lines
from pyhexraysdeob_modules.hexrays_util import *

# Put an mop_t into an mlist_t. The op must be either a register or a stack
# variable.
def insert_op(blk, ml, op):
    if op.t not in [mop_r, mop_S]:
        return False

    # I needed help from Hex-Rays with this line. Some of the example plugins
    # showed how to insert a register into an mlist_t. None of them showed
    # how to insert a stack variable. I figured out a way to do it by reverse
    # engineering Hex-Rays, but it seemed really janky. This is The Official
    # Method (TM).
    blk.append_use_list(ml, op, MUST_ACCESS)
    return True


# Ilfak sent me this function in response to a similar support request. It
# walks backwards through a block, instruction-by-instruction, looking at
# what each instruction defines. It stops when it finds definitions for
# everything in the mlist_t, or when it hits the beginning of the block.
def my_find_def_backwards(blk, ml, start):
    m_end = blk.head
    p = start if start else blk.tail
    while p:
        _def = blk.build_def_list(p, MAY_ACCESS | FULL_XDSU)
        if _def.includes(ml):
            return p
        p = p.prev


# This is a nearly identical version of the function above, except it works
# in the forward direction rather than backwards.
def my_find_def_forwards(blk, ml, start):
    m_end = blk.head
    p = start if start else blk.head
    while p:
        _def = blk.build_def_list(p, MAY_ACCESS | FULL_XDSU)
        if _def.includes(ml):
            return p
        p = p.next


# This function has way too many arguments. Basically, it's a wrapper around
# my_find_def_backwards from above. It is extended in the following ways:
# * If my_find_def_backwards identifies a definition of the variable "op"
#   which is an assignment from another variable, this function then continues
#   looking for numeric assignments to that variable (and recursively so, if
#   that variable is in turn assigned from another variable).
# * It keeps a list of all the assignment instructions it finds along the way,
#   storing them in the vector passed as the "chain" argument.
# * It has support for traversing more than one basic block in a graph, if
#   the bRecursive argument is true. It won't traverse into blocks with more
#   than one successor if bAllowMultiSuccs is false. In any case, it will
#   never traverse past the block numbered iBlockStop, if that parameter is
#   non-negative.
def find_numeric_def_backwards(blk, op, chain, recursive, allow_multi_succs, block_stop):
    
    report_debug(f"blk = {blk.serial}, op = {op.dstr()}, chain = {chain}, block_stop = {block_stop}")
    mba = blk.mba
    ml = mlist_t()
    
    if not insert_op(blk, ml, op):
        return False, None
    
    # Start from the end of the block. This variable gets updated when a copy
    # is encountered, so that subsequent searches start from the right place.
    start = None
    while True:
        # Told you this function was just a wrapper around
        # my_find_def_backwards.
        _def = my_find_def_backwards(blk, ml, start)
        if _def:
            # Ensure that it's a mov instruction. We don't want, for example,
            # an "stx" instruction, which is assumed to redefine everything
            # until its aliasing information is refined.
            if _def.opcode != m_mov:
                report_error("FindNumericDef: found %s" % mcode_t_to_string(_def))
                return False, None

            # Now that we found a mov, add it to the chain.
            mi = mov_info_t()
            mi.op_copy = _def.l
            mi.block = blk.serial
            mi.ins_mov = _def
            chain.append(mi)

            # Was it a numeric assignment?
            if _def.l.t == mop_n:
                # Great! We're done.
                return True, _def.l

            # Otherwise, if it was not a numeric assignment, then try to track
            # whatever was assigned to it. This can only succeed if the thing
            # that was assigned was a register or stack variable.
            report_info3(f"Now tracking {ida_lines.tag_remove(_def.l._print())}")

            # Try to start tracking the other thing...
            ml.clear()
            if not insert_op(blk, ml, _def.l):
                return False, None

            # Resume the search from the assignment instruction we just
            # processed.
            start = _def
        else:
            # Otherwise, we did not find a definition of the currently-tracked
            # variable on this block. Try to continue if the parameters allow.

            # If recursion was disallowed, or we reached the topmost legal
            # block, then quit.
            if not recursive or blk.serial == block_stop:
                return False, None

            # If there is more than one predecessor for this block, we don't
            # know which one to follow, so stop.
            if blk.npred() != 1:
                return False, None

            # Recurse into sole predecessor block
            pred = blk.pred(0)
            blk = mba.get_mblock(pred)

            # If the predecessor has more than one successor, check to see
            # whether the arguments allow that.
            if not allow_multi_succs and blk.nsucc() != 1:
                return False, None

            # Resume the search at the end of the new block.
            start = None
    return False, None


# This function finds a numeric definition by searching in the forward
# direction.
def find_forward_numeric_def(blk, mop):

    ml = mlist_t()
    if not insert_op(blk, ml, mop):
        return False, None, None

    # Find a forward definition
    assign_insn = my_find_def_forwards(blk, ml, None)
    if assign_insn:
        report_info3(f"Forward search found {ida_lines.tag_remove(assign_insn._print())}")

        # We only want MOV instructions with numeric left-hand sides
        if assign_insn.opcode != m_mov or assign_insn.l.t != mop_n:
            return False, None, None

        # Return the numeric operand if we found it
        return True, assign_insn.l, assign_insn

    return False, None, None


# This function is just a thin wrapper around find_forward_numeric_def, which
# also inserts the mov into the "chain" argument.
def find_forward_stack_var_def(cluster_head, op_copy, chain):

    # Must be a non-NULL stack variable
    if not op_copy or op_copy.t != mop_S:
        return None

    # Find the definition
    ok, num, ins = find_forward_numeric_def(cluster_head, op_copy)
    if not ok:
        return None

    report_info3(f"Forward method found {ida_lines.tag_remove(num._print())}!")

    # If the found definition was suitable, add the assignment to the chain
    mi = mov_info_t()
    mi.op_copy = num
    mi.block = cluster_head.serial
    mi.ins_mov = ins
    chain.append(mi)

    # Return the number
    return num


class mov_info_t:
    def __init__(self, op_copy=None, ins_mov=None, block=-1):
        self.op_copy = op_copy
        self.ins_mov = ins_mov
        self.block = block

