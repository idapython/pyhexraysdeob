
from ida_hexrays import *

import hexrays_util

# Append a goto onto a non-empty block, which is assumed not to already have
# a goto at the end of it.
def append_goto_onto_non_empty_block(blk, block_dest):

    # Allocate a new instruction, using the tail address
    new_goto = minsn_t(blk.tail.ea)

    # Create a goto instruction to the specified block
    new_goto.opcode = m_goto
    new_mop = mop_t()
    new_mop.t = mop_b
    new_mop.b = block_dest
    new_mop.size = NOSIZE
    new_goto.l = new_mop

    # Add it onto the block
    blk.insert_into_block(new_goto, blk.tail)


# For a block with a single successor, change its target from some old block
# to a new block. This is only on the graph level, not in terms of gotos.
def change_single_target(blk, old, new):
    mba = blk.mba

    # Overwrite the successor with the new target
    blk.succset[0] = new

    # Add this block to the predecessor set of the target
    mba.get_mblock(new).predset.push_back(blk.serial)

    # Remove this block from the predecessor set of the old target
    mba.get_mblock(old).predset._del(blk.serial)


GOTO_NOT_SINGLE = -1

# This function eliminates transfers to blocks with a single goto on them.
# Either if a given block has a goto at the end of it, where the destination
# is a block with a single goto on it, or if the block doesn't end in a goto,
# but simply falls through to a block with a single goto on it. Also, this
# process happens recursively; i.e., if A goes to B, and B goes to C, and C
# goes to D, then after we've done our tranformations, A will go to D.
def remove_single_gotos(mba):

    # This information determines, ultimately, to which block a goto will go.
    # As mentioned in the function comment, this accounts for gotos-to-gotos.
    forwarder_info = [0] * mba.qty

    # For each block
    for i in range(mba.qty):

        # Begin by initializing its information to say that it does not
        # consist of a single goto. Update later if it does.
        forwarder_info[i] = GOTO_NOT_SINGLE

        # Get the block and skip any "assert" instructions.
        b = mba.get_mblock(i)
        m2 = getf_reginsn(b.head)

        # Is the first non-assert instruction a goto?
        if not m2 or m2.opcode != m_goto or m2.l.t != mop_b:
            continue

        print(f"[+] Single goto found for block num = {b.serial}")
        # If it was a goto, record the destination block number
        forwarder_info[i] = m2.l.b

    rc = 0

    # Now, actually replace transfer-to-goto blocks with their destinations.
    for i in range(mba.qty):
        blk = mba.get_mblock(i)

        # FYI, don't screw with blocks that have calls at the end of them.
        # You'll get an INTERR. Also, if this block has more than one
        # successor, then it couldn't possibly be a transfer to a goto.
        # (blk->is_call_block() || blk->nsucc() != 1)
        if blk.is_call_block() or blk.nsucc() != 1:
            continue

        # Get the last instruction on the block
        mgoto = blk.tail
        if not mgoto:
            continue

        # Now, look up the block number of the destination.
        was_goto = mgoto.opcode == m_goto

        # If the last instruction was a goto, get the information from there.
        # Otherwise, take the number of the only successor block.
        original_goto_target = mgoto.l.b if was_goto else blk.succ(0)

        # Now, we determine if the target was a single-goto block.
        goto_target = original_goto_target
        should_replace = False
        visited = []

        # Keep looping while we still find goto-to-gotos.
        while True:

            # Keep track of the blocks we've seen so far, so we don't end up
            # in an infinite loop if the goto blocks form a cycle in the
            # graph.
            if goto_target in visited:
                should_replace = False
                break
            else:
                visited.append(goto_target)

            # Once we find the first non-single-goto block, stop.
            if forwarder_info[goto_target] == GOTO_NOT_SINGLE:
                break

            # If we find at least one single goto at the destination, then
            # indicate that we should replace. Keep looping, though, to find
            # the ultimate destination.
            should_replace = True
            print("[+] Replacing single goto target")

            # Now check: did the single-goto block also target a single-goto
            # block?
            goto_target = forwarder_info[goto_target]

        # If the target wasn't a single-goto block, or there was an infinite
        # loop in the graph, don't touch this block.
        if not should_replace:
            continue

        # Otherwise, update the destination with the final target.

        if was_goto:
            # If the block had a goto, overwrite its block destination.
            mgoto.l.b = goto_target
        else:
            # Otherwise, add a goto onto the block. You might think you could skip
            # this step and just change the successor information, but you'll get
            # an INTERR if you do.
            append_goto_onto_non_empty_block(blk, goto_target)

        # Change the successor/predecessor information for this block and its
        # old and new target.
        change_single_target(blk, original_goto_target, goto_target)

        # Counter of the number of blocks changed.
        rc += 1

    # Return the number of blocks whose destinations were changed
    return rc


# For a block that ends in a conditional jump, extract the integer block
# numbers for the "taken" and "not taken" cases.
def extract_jcc_parts(pred1):
    if is_mcode_jcond(pred1.tail.opcode):
        if pred1.tail.d.t != mop_b:
            hexrays_util.report_info("extract_jcc_parts: block was jcc, but destination was %s, not mop_b" % (
                hexrays_util.mopt_t_to_string(pred1.tail.d.t)))
            return False, None, None, None
        ends_with_jcc = pred1
        jcc_dest = pred1.tail.d.b

        # The fallthrough location is the block that's not directly targeted
        # by the jcc instruction. Determine that by looking at the successors.
        # I guess technically Hex-Rays enforces that it must be the
        # sequentially-next-numbered block, but oh well.
        jcc_fall_through = pred1.succ(1) if pred1.succ(0) == jcc_dest else pred1.succ(0)
        return True, ends_with_jcc, jcc_dest, jcc_fall_through

    return False, None, None, None


# For a block with two predecessors, figure out if one of them ends in a jcc
# instruction. Return pointers to the block that ends in a jcc and the one
# that doesn't. Also return the integer numbers of those blocks.
def split_mblocks_by_jcc_ending(pred1, pred2):
    ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through = None, None, -1, -1
    if not pred1.tail or not pred2.tail:
        return False, None, None, None, None

    # Check if the first block ends with jcc. Make sure the second one
    # doesn't also.
    ok, ends_with_jcc, jcc_dest, jcc_fall_through = extract_jcc_parts(pred1)
    if ok:
        if is_mcode_jcond(pred2.tail.opcode):
            return False, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through
        non_jcc = pred2
    else:
        # Otherwise, check if the second block ends with jcc. Make sure the first
        # one doesn't also.
        ok, ends_with_jcc, jcc_dest, jcc_fall_through = extract_jcc_parts(pred2)
        if not ok:
            return False, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through
        non_jcc = pred1
    return True, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through


# The "deferred graph modifier" records changes that the client wishes to make
# to a given graph, but does not apply them immediately. Weird things could
# happen if we were to modify a graph while we were iterating over it, so save
# the modifications until we're done iterating over the graph.
class deferred_graph_modifier_t:

    class edgeinfo_t:
        def __init__(self, src=-1, dst1=-1, dst2=-1):
            self.src = src
            self.dst1 = dst1
            self.dst2 = dst2


    def __init__(self):
        self.clear()


    def clear(self):
        self.edges = []


    # Plan to add an edge
    def add(self, src, dest):
        self.edges.append(deferred_graph_modifier_t.edgeinfo_t(src=src, dst2=dest))


    # Plan to replace an edge from src->old_dest to src->new_dest
    def replace(self, src, old_dest, new_dest):

        # if the edge was already planned to be replaced, replace the
        # old destination with the new one
        for e in self.edges:
            if e.src == src and e.dst1 == old_dest:
                old_dest = e.dst2
        self.edges.append(deferred_graph_modifier_t.edgeinfo_t(src=src, dst1=old_dest, dst2=new_dest))


    # Apply the planned changes to the graph
    def apply(self, mba, cfi=None):

        # Iterate through the edges slated for removal or addition
        for e in self.edges:
            mb_src = mba.get_mblock(e.src)
            if e.dst1 != -1:
                mb_dst1 = mba.get_mblock(e.dst1)
                mb_src.succset._del(mb_dst1.serial)
                mb_dst1.predset._del(mb_src.serial)
            mb_dst2 = mba.get_mblock(e.dst2)
            mb_src.succset.push_back(mb_dst2.serial)
            mb_dst2.predset.push_back(mb_src.serial)
            if cfi == None:
                hexrays_util.report_info("Replaced edge (%d->%d) by (%d->%d)\n" % (
                    e.src, e.dst1, e.src, e.dst2))
            else:
                if e.src in cfi.block_to_key.keys():
                    hexrays_util.report_info(f"Replaced edge ({e.src}->{e.dst1}) by ({e.src}->{e.dst2}) BlockKey = {hex(cfi.block_to_key[e.src])}")
                else:
                    hexrays_util.report_info(f"Replaced edge ({e.src}->{e.dst1}) by ({e.src}->{e.dst2}) BlockKey = {cfi.block_to_key}")
        return len(self.edges)


    # Either change the destination of an existing goto, or add a new goto onto
    # the end of the block to the destination. Also, plan to modify the graph
    # structure later to reflect these changes.
    def change_goto(self, blk, old, new):
        changed = True
        disp_pred = blk.serial

        # If the last instruction isn't a goto, add a new one
        if blk.tail.opcode != m_goto:
            append_goto_onto_non_empty_block(blk, new)
        else:
            # Otherwise, if it is a goto, be sure we're actually
            # *changing* the destination to a different location
            prev = blk.tail.l.b
            if prev == new:
                changed = False
            else:
                # And if so, do it
                blk.tail.l.b = new

        # If we did change the destination, plan to update the graph later
        if changed:
            self.replace(blk.serial, old, new)

        return changed
