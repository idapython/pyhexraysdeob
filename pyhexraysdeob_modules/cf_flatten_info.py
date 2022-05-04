
import ida_idaapi
from ida_hexrays import *

import hexrays_util

MIN_NUM_COMPARISONS = 2

class jz_info_t:
    """
    Helper class, used to determine whether a function is likely obfuscated or not.
    Also used to collect the number of times a var. was used in a comparison, 
    and a list of the values it was compared against
    """
    def __init__(self, op=None, nseen=0):
        self.op = op
        self.nseen = nseen
        self.nums = []

  
    def should_blacklist(self):
        """
        Determines whether a function is likely obfuscated via
        a) Minimum number o fcomparisons made against comp. variable
        b) constant values in comparisons are suff. entropic
        :return: True if not obfuscated
        """

        # This check is pretty weak. I thought I could set the minimum number to
        # 6, but the pattern deobfuscators might eliminate some of them before
        # this function gets called.
        if self.nseen < MIN_NUM_COMPARISONS:
            return True

        # Count the number of 1-bits in the constant values used for comparison
        num_bits = 0
        num_ones = 0
        for num in self.nums:
            num_bits += num.size * 8
            v = num.nnn.value
            for i in range(num.size * 8):
                if v & (1 << i):
                    num_ones += 1

        # Compute the percentage of 1-bits. Given that these constants seem to be
        # created pseudorandomly, the percentage should be roughly 1/2.
        entropy = 0.0 if num_bits == 0 else num_ones / float(num_bits)
        hexrays_util.report_info(f"{self.nseen} comparisons, {len(self.nums)} numbers, {num_bits} bits, {num_ones} ones, {float(entropy)} entropy")
        return entropy < 0.3 or entropy > 0.6


class jz_collector_t(minsn_visitor_t):
    """
    Looks for jz, jg comparisons against constant values. Utilised jz_info_t class.
    """
    def __init__(self):
        minsn_visitor_t.__init__(self)
        self.seen_comparisons = []
        self.n_max_jz = -1

    def visit_minsn(self):
        ins = self.curins

        # We're looking for jz/jg instructions...
        if ins.opcode not in [m_jz, m_jg]:
            return 0

        # ... which compare something against a number ...
        if ins.r.t != mop_n:
            return 0

        found = 0
        this_mop = ins.l
        idx_found = 0

        # Search for the comparison operand in the saved information
        for sc in self.seen_comparisons:
            if sc.op.equal_mops(this_mop, EQ_IGNSIZE):
                sc.nseen += 1
                sc.nums.append(ins.r)
                found = sc.nseen
                break
            idx_found += 1

        # If we didn't find it in the vector, create a new JZInfo structure
        if not found:
            jz = jz_info_t()
            jz.op = this_mop
            jz.nseen = 1
            jz.nums.append(ins.r)
            self.seen_comparisons.append(jz)

        # If the variable we just saw has been used more often than the previous
        # candidate, mark this variable as the new candidate
        if self.n_max_jz < 0 or found > self.seen_comparisons[self.n_max_jz].nseen:
            self.n_max_jz = idx_found

        return 0


# This function finds the "first" block immediately before the control flow
# flattening dispatcher begins. The logic is simple; start at the beginning
# of the function, keep moving forward until the next block has more than one
# predecessor. As it happens, this is where the assignment to the switch
# dispatch variable takes place, and that's mostly why we want it.
# The information is recorded in the arguments iFirst and iDispatch.
def get_first_block(mba):
    """
    Finds the first block before control flow dispatcher begins.
    :param mba: mba_t
    :return: True if found, mblock_t first block, serial first block, dispatcher serial
    """

    hexrays_util.report_info("Determining first block before cfg disp begins")
    # Initialise first and dispatch to erroneous values
    first, dispatch = -1, -1
    curr = 0

    while True:

        hexrays_util.report_info(f"Investigating if dispatcher. Current block = {curr}")
        # If we find a block with more than one successor, we failed.
        mb = mba.get_mblock(curr)
        if mb.nsucc() != 1:
            hexrays_util.report_error(f"Block {curr} had {mb.nsucc()} (!= 1) successors\n")
            return False, None, None, None

        # Get the successor block
        succ = mb.succ(0)
        mb_next_block = mba.get_mblock(succ)

        # If the successor has more than one predecessor, we're done
        if mb_next_block.npred() != 1:
            break

        # Otherwise, move onto the next block
        curr = succ

    # We found it; pass the information back to the caller
    first = curr
    dispatch = mb.succ(0)
    return True, mb, first, dispatch


# This class is used to find all variables that have 32-bit numeric values
# assigned to them in the first block (as well as the values that are
# assigned to them).
class block_insn_assign_number_extractor_t(minsn_visitor_t):
    def __init__(self):
        minsn_visitor_t.__init__(self)
        self.seen_assignments = []

    def visit_minsn(self):
        ins = self.curins

        if ins.opcode != m_mov or ins.l.t != mop_n or ins.l.size != 4:
            return 0

        # Record all such information in the vector
        self.seen_assignments.append((ins.d, ins.l.nnn.value))
        return 0


# Protected functions might use either one, or two, variables for the switch
# dispatch number. If it uses two, one of them is the "update" variable, whose
# contents will be copied into the "comparison" variable in the first dispatch
# block. This class is used to locate the "update" variable, by simply looking
# for a variable whose contents are copied into the "comparison" variable,
# which must have had a number assigned to it in the first block.
class handoff_var_finder_t(minsn_visitor_t):

    class seen_copy_t:
        def __init__(self, op, count=1):
            self.op = op
            self.count = count

    def __init__(self, op_max, num_extractor):
        minsn_visitor_t.__init__(self)

        # We're looking for assignments to this variable
        self.comparison_var = op_max
        self.num_extractor = num_extractor

        # This information is generated by this class. Namely, it's a list of
        # variables that are seen copied into the comparison variable, as well
        # as a count of the number of times it is copied.
        self.seen_copies = []

    def visit_minsn(self):
        ins = self.curins

        # We want copies into our comparison variable
        if ins.opcode not in [m_mov, m_and] or not ins.d.equal_mops(self.comparison_var, EQ_IGNSIZE):
            return 0
        
        # Iterate through the numeric assignments from the first block. These
        # are our candidates.
        for sas in self.num_extractor.seen_assignments:
            if ins.l.equal_mops(sas[0], EQ_IGNSIZE):

                # If we found a copy into our comparison variable from a
                # variable that was assigned to a constant in the first block,
                # add it to the vector (or increment its counter if it was
                # already there).
                found = False

                for sc in self.seen_copies:
                    if sas[0].equal_mops(sc.op, EQ_IGNSIZE):
                        sc.count += 1
                        found = True
                if not found:
                    self.seen_copies.append(handoff_var_finder_t.seen_copy_t(sas[0]))

        return 0


# Once we know which variable is the one used for comparisons, look for all
# jz instructions that compare a number against this variable. This then tells
# us which number corresponds to which basic block.
class jz_mapper_t(minsn_visitor_t):
    def __init__(self, cfi, assign_var):
        minsn_visitor_t.__init__(self)
        self.cfi = cfi
        self.assign_var = assign_var
        self.debug = True

    def visit_minsn(self):
        ins = self.curins
        mba = self.mba
        blk = self.blk
        is_jnz = False

        # We're looking for jz instructions that compare a number ...
        # if its a jnz and the last instruction of the block, the dest_no will be next block in the list
        if ins.opcode != m_jz:
            if blk.tail != ins and ins.opcode != m_jnz:
                return 0
            is_jnz = True
        
        if ins.r.t != mop_n:
            return 0

        # ... against our comparison variable ...
        if not self.cfi.op_compared.equal_mops(ins.l, EQ_IGNSIZE):

            # ... or, if it's the dispatch block, possibly the assignment variable ...
            if blk.serial != self.cfi.dispatch \
               or not self.assign_var.equal_mops(ins.l, EQ_IGNSIZE):
                   return 0

        # ... and the destination of the jz must be a block
        if ins.d.t != mop_b:
            return 0

        # Record the information in two maps
        key_val = ins.r.nnn.value
        
        # told you above, if flag set, the next block is the destination
        if is_jnz:
            block_no = blk.nextb.serial
        else:
            block_no = ins.d.b
        self.cfi.report_info(f"Mapping found, key_val = {hex(key_val)} -> block = {block_no}")
        self.cfi.key_to_block[key_val] = block_no
        self.cfi.block_to_key[block_no] = key_val
        return 0


# Compute dominator information for the function.
def compute_dominators(mba):
    num_blocks = mba.qty
    assert(num_blocks > 0)

    # Use Hex-Rays' handy bitsets_t to represent dominators
    dom_info = []
    for i in range(num_blocks):
        dom_info.append(bitset_t())

    # Per the algorithm, initialize each block to be dominated by every block
    for bs in dom_info:
        bs.fill_with_ones(num_blocks - 1)

    # ... except the first block, which only dominates itself
    dom_info[0].clear()
    dom_info[0].add(0)

    # Now we've got a standard, not-especially-optimized dataflow analysis
    # fixedpoint computation...
    while True:
        changed = False

        # For every block...
        for i in range(1, num_blocks):

            # Grab its current dataflow value and copy it
            bs_curr = dom_info[i]
            bs_before = bitset_t(bs_curr)

            # Get that block from the graph
            block_i = mba.get_mblock(i)

            # Iterate over its predecessors, intersecting their dataflow
            # values against this one's values
            for pr in block_i.predset:
                bs_curr.intersect(dom_info[pr])

            # Then, re-indicate that the block dominates itself
            bs_curr.add(i)

            # If this process changed the dataflow information, we're going to
            # need another iteration
            if bs_before.compare(bs_curr) != 0:
                changed = True

        # Keep going until the dataflow information stops changing
        if not changed:
            break

    # The dominator information has been computed. Now we're going to derive
    # some information from it. Namely, the current representation tells us,
    # for each block, which blocks dominate it. We want to know, instead, for
    # each block, which blocks are dominated by it. This is a simple
    # transformation; for each block b and dominator d, update the information
    # for d to indicate that it dominates b.

    # Create a new array_of_bitsets
    dom_info_output = []
    for i in range(num_blocks):
        dom_info_output.append(bitset_t())

    # Iterate over each block
    for i in range(num_blocks):
        # Get the dominator information for this block (b)
        bs_curr = dom_info[i]

        # For each block d that dominates this one, mark that d dominates b
        for bit in bs_curr:
            odi = dom_info_output[bit]
            odi.add(i)

    # Just return the inverted dominator information
    return dom_info_output


class cf_flatten_info_t:
    def __init__(self, plugin):
        self.plugin = plugin
        self.maturity = None
        self.mb_first = None
        self.detected_dispatchers = []
        self.clear()

    def report_info(self, msg):
        hexrays_util.report_info(msg)

    def report_error(self, msg):
        hexrays_util.report_error(msg)

    def report_debug(self, msg):
        hexrays_util.report_debug(msg)

    def clear(self):
        self.op_assigned = None
        self.op_compared = None
        self.op_sub_compared = None
        self.first = -1
        self.dispatch = -1
        self.ufirst = 0
        self.which_func = ida_idaapi.BADADDR
        self.dom_info = None
        self.dominated_clusters = None
        self.tracking_first_blocks = False
        self.op_and_assign = False
        self.op_and_imm = 0
        self.key_to_block = {}
        self.block_to_key = {}
    
    def clear_mmat_calls(self):
        self.op_assigned = None
        self.op_compared = None
        self.op_sub_compared = None
        self.which_func = ida_idaapi.BADADDR
        self.dom_info = None
        self.dominated_clusters = None
        self.tracking_first_blocks = False
        self.op_and_assign = False
        self.op_and_imm = 0
        self.key_to_block = {}
        self.block_to_key = {}

    # Convenience function to look up a block number by its key. This way, we can
    # write the iterator-end check once, so clients don't have to do it.
    def find_block_by_key(self, key):
        return self.key_to_block.get(key, -1)

    def detect_additional_dispatchers(self, blk):
        """
        Detect additional dispatchers.
        """
        mba = blk.mba
        hexrays_util.report_info(f"Detecting additional dispatchers ..")
        block = mba.get_mblock(0)
        i = 0
        while block.nextb != None:
            block = mba.get_mblock(i)
            if block.npred() >= 3 and block.get_reginsn_qty() >= 1 and i not in self.detected_dispatchers:
                hexrays_util.report_info(f"Block serial = {block.serial} with greater equal 3 predecessors found, verifying whether potential dispatcher ..")
                self.detected_dispatchers.append(i)
            i += 1


    # This function computes all of the preliminary information needed for
    # unflattening.
    def get_assigned_and_comparison_variables(self, blk):

        mba = blk.mba
        self.clear()
        ea = mba.entry_ea

        # Ensure that this function hasn't been blacklisted (e.g. because entropy
        # calculation indicates that it isn't obfuscated).
        if ea in self.plugin.black_list:
            hexrays_util.report_error(f"[+] Function Ea = {hex(ea)} blacklisted!")
            return False
        
        # There's also a separate whitelist for functions that were previously
        # seen to be obfuscated.
        was_white_listed = ea in self.plugin.white_list


        hexrays_util.report_info(f"Running jz_collector")
        # Look for the variable that was used in the largest number of jz/jg
        # comparisons against a constant. This is our "comparison" variable.
        jzc = jz_collector_t()
        mba.for_all_topinsns(jzc)
        if jzc.n_max_jz < 0:
            hexrays_util.report_info(f"No comparisons seen for function Ea = {hex(ea)}, adding function to blacklist")
            # If there were no comparisons and we haven't seen this function
            # before, blacklist it.
            if not was_white_listed:
                self.plugin.black_list.append(ea)
            return False
        
        hexrays_util.report_info(f"Max comparisons seen = {jzc.n_max_jz}")

        # Otherwise, we were able to find jz comparison information. Use that to
        # determine if the constants look entropic enough. If not, blacklist this
        # function. If so, whitelist it.
        if not was_white_listed:
            # this kicks out cfgNetwork handling .. lowering entropy..
            if jzc.seen_comparisons[jzc.n_max_jz].should_blacklist():
                hexrays_util.report_info(f"Classified function as not obfuscated")
                self.plugin.black_list.append(ea)
                return False
            self.plugin.white_list.append(ea)

        op_max = jzc.seen_comparisons[jzc.n_max_jz].op


        hexrays_util.report_info(f"Comparison variable = {op_max.dstr()}")
        # op_max is our "comparison" variable used in the control flow switch.
        if op_max.size < 4:
            self.report_error(f"Comparison variable {op_max.dstr()} is too narrow\n")
            return False

        ok = False
        # Find the "first" block in the function, the one immediately before the
        # control flow switch.
        ok, self.mb_first, self.first, self.dispatch = get_first_block(mba)
        first = self.mb_first
        self.detected_dispatchers.append(self.dispatch)
        self.detect_additional_dispatchers(blk)

        if not ok:
            hexrays_util.report_error(f"Failed determining the first block")
            return False
        
        hexrays_util.report_info(f"Determined dispatcher block = {self.dispatch}, first_block = {first.serial}")

        # Get all variables assigned to numbers in the first block. If we find the
        # comparison variable in there, then the assignment and comparison
        # variables are the same. If we don't, then there are two separate
        # variables.
        fbe = block_insn_assign_number_extractor_t()
        first.for_all_insns(fbe)

        # Was the comparison variable assigned a number in the first block?
        found = False
        for sas in fbe.seen_assignments:
            if sas[0].equal_mops(op_max, EQ_IGNSIZE):
                found = True
                break

        # This is the "assignment" variable, whose value is updated by the switch
        # case code
        local_op_assigned = None
        if found:
            # If the "comparison" variable was assigned a number in the first block,
            # then the function is only using one variable, not two, for dispatch.
            local_op_assigned = op_max
        else:
            # Otherwise, look for assignments of one of the variables assigned a
            # number in the first block to the comparison variable

            # For all variables assigned a number in the first block, find all
            # assignments throughout the function to the comparison variable
            hvf = handoff_var_finder_t(op_max, fbe)
            mba.for_all_topinsns(hvf)

            # There should have only been one of them; is that true?
            if len(hvf.seen_copies) != 1:
                hexrays_util.report_error(f"Multiple copies found by handoff finder! Number of copies = {hvf.seen_copies}")
                return False

            # If only one variable (X) assigned a number in the first block was
            # ever copied into the comparison variable, then X is our "assignment"
            # variable.
            local_op_assigned = hvf.seen_copies[0].op

            # Find the number that was assigned to the assignment variable in the
            # first block.
            found = False
            for sas in fbe.seen_assignments:
                if sas[0].equal_mops(local_op_assigned, EQ_IGNSIZE):
                    ufirst = sas[1]
                    found = True
                    break
            if not found:
                return False

        # Make copies of the comparison and assignment variables so we don't run
        # into liveness issues
        self.op_compared = mop_t(op_max)
        self.op_assigned = mop_t(local_op_assigned)

        # Extract the key-to-block mapping for each JZ against the comparison
        # variable
        jzm = jz_mapper_t(self, local_op_assigned)
        mba.for_all_topinsns(jzm)

        # Save off the current function's starting EA
        self.which_func = ea

        # Compute the dominator information for this function and stash it
        self.dom_info = compute_dominators(mba)


        # Compute some more information from the dominators. Basically, once the
        # control flow dispatch switch has transferred control to the function's
        # code, there might be multiple basic blocks that can execute before
        # control goes back to the switch statement. For all of those blocks, we
        # want to know the "first" block as part of that region of the graph,
        # i.e., the one targeted by a jump out of the control flow dispatch
        # switch.

        # to explain this process in my own words:
        # After the control flow switch block, we enter a control flow block
        # This control flow block can have multiple basic blocks that run after
        # the control flow block (f.e. if else branches etc.)
        # For these non control flow blocks, we collect information, so the first control flow block
        # before them

        # This is done by generating a new bitset again

        # Allocate an array mapping each basic block to the block that dominates
        # it and was targeted by the control flow switch.
        dominated_clusters = [-1] * mba.qty

        # For each block/key pair (the targets of the control flow switch)
        for i, _ in sorted(self.block_to_key.items()):

            # weird case where we have an out of bounds here
            if i > len(self.dom_info):
                continue
            bitset = self.dom_info[i]

            # For each block dominated by this control flow switch target, mark
            # that this block its the beginning of its cluster.
            for bit in bitset:
                self.report_debug("-> setting bit %d to %d" % (bit, i))
                dominated_clusters[bit] = i

        # Save that information off.
        self.dominated_clusters = dominated_clusters
        self.report_info(f"m_DominatedClusters: {', '.join(map(str, self.dominated_clusters))}")

 
        # Ready to go!
        return True
