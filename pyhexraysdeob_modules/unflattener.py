
from ida_hexrays import *

import cf_flatten_info
import def_util
import target_util
import hexrays_util

class cf_unflattener_t(optblock_t):

    def __init__(self, plugin):
        optblock_t.__init__(self)
        self.cfi = cf_flatten_info.cf_flatten_info_t(plugin)
        self.plugin = plugin
        self.last_maturity = MMAT_ZERO
        self.clear()
        self.verbose = False
        self.debug = False

    def report_success(self, blk, changed):
        hexrays_util.report_success("UNFLATTENER: blk.start=%08X (changed=%s)" % (blk.start, changed))

    def report_info(self, msg):
        hexrays_util.report_info(msg)

    def report_error(self, msg):
        hexrays_util.report_error(msg)

    def report_error3(self, msg):
        hexrays_util.report_error3(msg)

    def report_debug(self, msg):
        hexrays_util.report_debug(msg)

    def clear(self):
        self.cfi.clear()
        self.deferred_erasures_local = []
        self.performed_erasures_global = []

    # Find the block that dominates iDispPred, and which is one of the targets of
    # the control flow flattening switch.
    def get_dominated_cluster_head(self, mba, disp_pred):
        mb_cluster_head, cluster_head = None, -1
        # Find the block that is targeted by the dispatcher, and that
        # dominates the block we're currently looking at. This logic won't
        # work for the first block (since it wasn't targeted by the control
        # flow dispatch switch, so it doesn't have an entry in the dominated
        # cluster information), so we special-case it.
        if disp_pred == self.cfi.first:
            cluster_head = self.cfi.first
            mb_cluster_head = mba.get_mblock(self.cfi.first)
        else:
            # If it wasn't the first block, look up its cluster head block
            cluster_head = self.cfi.dominated_clusters[disp_pred]
            if cluster_head < 0:
                return False, None, None
            mb_cluster_head = mba.get_mblock(cluster_head)
            self.report_info("Block %s was part of dominated cluster %s" % (
                disp_pred,
                cluster_head))
        return True, mb_cluster_head, cluster_head


    # This function attempts to locate the numeric assignment to a given variable
    # "what" starting from the end of the block "mb". It follows definitions
    # backwards, even across blocks, until it either reaches the block
    # "mbClusterHead", or, if the boolean "bAllowMultiSuccs" is false, it will
    # stop the first time it reaches a block with more than one successor.
    # If it finds an assignment whose source is a stack variable, then it will not
    # be able to continue in the backwards direction, because intervening memory
    # writes will make the definition information useless. In that case, it
    # switches to a strategy of searching in the forward direction from
    # mbClusterHead, looking for assignments to that stack variable.
    # Information about the chain of assignment instructions along the way are
    # stored in the vector called m_DeferredErasuresLocal, a member variable of
    # the CFUnflattener class.
    def find_block_target_or_last_copy(self, mb, mb_cluster_head, what, allow_multi_succs):
        mba = mb.mba
        cluster_head = mb_cluster_head.serial
        local = []

        # Search backwards looking for a numeric assignment to "what". We may or
        # may not find a numeric assignment, but we might find intervening
        # assignments where "what" is copied from other variables.
        found, op_num = def_util.find_numeric_def_backwards(
            mb, what, local, True, allow_multi_succs, cluster_head)

        # If we found no intervening assignments to "what", that's bad.
        if len(local) == 0:
            return -1

        # opCopy now contains the last non-numeric assignment that we saw before
        # FindNumericDefBackwards terminated (either due to not being able to
        # follow definitions, or, if bAllowMultiSuccs is true, because it recursed
        # into a block with more than one successor.
        op_copy = local[-1].op_copy

        # Copy the assignment chain into the erasures vector, so we can later
        # remove them if our analysis succeeds.
        self.deferred_erasures_local.extend(local)

        # If we didn't find a numeric definition, but we did find an assignment
        # from a stack variable, switch to a forward analysis from the beginning
        # of the cluster. If we don't find it, this is not necessarily an
        # indication that the analysis failed; for blocks with two successors,
        # we do further analysis.
        if not found and op_copy and op_copy.t == mop_S:
            num = def_util.find_forward_stack_var_def(mb_cluster_head, op_copy, local)
            if num:
                op_num = num
                found = True
            else:
                self.report_error3("Forward method also failed")

        dest_no = -1

        # If we found a numeric assignment...
        if found:

            # Look up the integer number of the block corresponding to that value.
            dest_no = self.cfi.find_block_by_key(op_num.nnn.value)

            # If we couldn't find the block, that's bad news.
            if dest_no < 0:
                self.report_error("Block %s assigned unknown key %lx to assigned var" % (
                    mb.serial,
                    op_num.nnn.value))

        return dest_no


    # This function is used for unflattening constructs that have two successors,
    # such as if statements. Given a block that assigns to the assignment variable
    # that has two predecessors, analyze each of the predecessors looking for
    # numeric assignments by calling the previous function.
    def handle_two_preds(self, mb, mb_cluster_head, op_copy):
        ends_with_jcc, non_jcc, actual_goto_target, actual_jcc_target = None, None, -1, -1
        mba = mb.mba
        disp_pred = mb.serial
        cluster_head = mb_cluster_head.serial

        if mb.npred() == 2:
            pred1 = mba.get_mblock(mb.pred(0))
            pred2 = mba.get_mblock(mb.pred(1))
        else:
            # No really, don't call this function on a block that doesn't have two
            # predecessors.
            return False, None, None, None, None

        # Given the two predecessors, find the block with the conditional jump at
        # the end of it (store the block in "ends_with_jcc") and the one without
        # (store it in non_jcc). Also find the block number of the jcc target, and
        # the block number of the jcc fallthrough (i.e., the block number of
        # non_jcc).
        ok, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through = target_util.split_mblocks_by_jcc_ending(pred1, pred2)
        if not ok:
            self.report_info("Block %s w/preds %s, %s did not have one predecessor ending in jcc, one without" % (
                disp_pred, pred1.serial, pred2.serial))
            return False, ends_with_jcc, non_jcc, jcc_dest, jcc_fall_through

        # Sanity checking the structure of the graph. The nonJcc block should only
        # have one incoming edge...
        if non_jcc.npred() != 1:
            self.report_info("Block %d w/preds %d, %d did not have one predecessor ending in jcc, one without" % (
                disp_pred, pred1.serial, pred2.serial))
            return False, None, None, None, None

        # ... namely, from the block ending with the jcc.
        if non_jcc.pred(0) != ends_with_jcc.serial:
            self.report_info("Block %d w/preds %d, %d, non-jcc pred %d did not have the other as its predecessor" % (
                disp_pred, pred1.serial, pred2.serial, non_jcc.serial))
            return False, None, None, None, None

        # Call the previous function to locate the numeric definition of the
        # variable that is used to update the assignment variable if the jcc is
        # not taken.
        actual_goto_target = self.find_block_target_or_last_copy(
            ends_with_jcc, mb_cluster_head, op_copy, allow_multi_succs=False)

        # If that succeeded...
        if actual_goto_target >= 0:

            # ... then do the same thing when the jcc is not taken.
            actual_jcc_target = self.find_block_target_or_last_copy(
                non_jcc, mb_cluster_head, op_copy, allow_multi_succs=True)

            # If that succeeded, great! We can unflatten this two-way block.
            if actual_jcc_target >= 0:
                return True, ends_with_jcc, non_jcc, actual_goto_target, actual_jcc_target

        return False, None, None, None, None


    # Erase the now-superfluous chain of instructions that were used to copy a
    # numeric value into the assignment variable.
    def process_erasures(self, mba):
        self.performed_erasures_global.extend(self.deferred_erasures_local)
        for erase in self.deferred_erasures_local:
            import ida_lines
            self.report_info("Erasing %08X: %s" % (
                erase.ins_mov.ea,
                ida_lines.tag_remove(erase.ins_mov._print())))
            # Be gone, sucker
            mba.get_mblock(erase.block).make_nop(erase.ins_mov)
        self.deferred_erasures_local = []


    # This is the top-level un-flattening function for an entire graph. Hex-Rays
    # calls this function since we register our CFUnflattener class as a block
    # optimizer.
    def func(self, blk):

        mba = blk.mba

        if self.verbose or self.debug:
            self.report_info("Block optimization called at maturity level %s" %
                             hexrays_util.mba_maturity_t_to_string(mba.maturity))

        # Was this function blacklisted? Skip it if so
        if mba.entry_ea in self.plugin.black_list:
            return 0

        # Only operate once per maturity level
        if self.last_maturity == mba.maturity:
            return 0

        # Update the maturity level
        self.last_maturity = mba.maturity

        # We only operate at MMAT_LOCOPT
        if mba.maturity != MMAT_LOCOPT:
            return 0;

        # If local optimization has just been completed, remove transfer-to-gotos
        changed = target_util.remove_single_gotos(mba)
        self.report_debug("\tRemoved %d vacuous GOTOs" % changed)

        # Might as well verify we haven't broken anything
        if changed:
            mba.verify(True)

        # Get the preliminary information needed for control flow flattening, such
        # as the assignment/comparison variables.
        if not self.cfi.get_assigned_and_comparison_variables(blk):
            self.report_error("Couldn't get control-flow flattening information")
            return changed

        # Create an object that allows us to modify the graph at a future point.
        dirty_chains = False
        dgm = target_util.deferred_graph_modifier_t()

        # Iterate through the predecessors of the top-level control flow switch
        for disp_pred in mba.get_mblock(self.cfi.dispatch).predset:
            mb = mba.get_mblock(disp_pred)

            # The predecessors should only have one successor, i.e., they should
            # directly branch to the dispatcher, not in a conditional fashion
            if mb.nsucc() != 1:
                self.report_debug("Block %d had %d successors, not 1" % (disp_pred, mb.nsucc()))
                continue

            # Find the block that dominates this cluster, or skip this block if
            # we can't. This ensures that we only try to unflatten parts of the
            # control flow graph that were actually flattened. Also, we need the
            # cluster head so we know where to bound our searches for numeric
            # definitions.
            ok, mb_cluster_head, cluster_head = self.get_dominated_cluster_head(mba, disp_pred)
            if not mb_cluster_head:
                continue

            # It's best to process erasures for every block we unflatten
            # immediately, so we don't end up duplicating instructions that we
            # want to eliminate
            self.deferred_erasures_local = []

            # Try to find a numeric assignment to the assignment variable, but
            # pass false for the last parameter so that the search stops if it
            # reaches a block with more than one successor. This ought to succeed
            # if the flattened control flow region only has one destination,
            # rather than two destinations for flattening of if-statements.
            dest_no = self.find_block_target_or_last_copy(
                mb, mb_cluster_head, self.cfi.op_assigned, allow_multi_succs=False)

            # Couldn't find any assignments at all to the assignment variable?
            # That's bad, don't continue.
            if not self.deferred_erasures_local:
                continue

            # Did we find a block target? Great; just update the CFG to point the
            # destination directly to its target, rather than back to the
            # dispatcher.
            if dest_no >= 0:

                # Make a note to ourselves to modify the graph structure later
                dgm.change_goto(mb, self.cfi.dispatch, dest_no)

                # Erase the intermediary assignments to the assignment variable
                self.process_erasures(mba)

                self.report_info("Changed goto on %d to %d" % (disp_pred, dest_no))
                changed += 1
                continue

            # Stash off a copy of the last variable in the chain of assignments
            # to the assignment variable, as well as the assignment instruction
            # (the latter only for debug-printing purposes).
            op_copy = self.deferred_erasures_local[-1].op_copy
            m = self.deferred_erasures_local[-1].ins_mov
            self.report_info("Block %d did not define assign a number to assigned var; assigned %s instead" % (
                disp_pred, hexrays_util.mopt_t_to_string(m.l.t)))

            # If the block we're currently examining has more than two
            # predecessors, that's unexpected, so stop.
            if mb.npred() != 2:
                self.report_info("Block %d that assigned non-numeric value had %d predecessors, not 2" % (
                    disp_pred, mb.npred()))
                continue

            # Call the function that handles the case of a conditional assignment
            # to the assignment variable (i.e., the flattened version of an
            # if-statement).
            ok, ends_with_jcc, non_jcc, actual_goto_target, actual_jcc_target = self.handle_two_preds(
                mb, mb_cluster_head, op_copy)
            if ok:
                # If it succeeded...

                # Get rid of the superfluous assignments
                self.process_erasures(mba)

                # Make a note to ourselves to modify the graph structure later,
                # for the non-taken side of the conditional. Change the goto
                # target.
                dgm.replace(mb.serial, self.cfi.dispatch, actual_goto_target)
                mb.tail.l.b = actual_goto_target

                # Mark that the def-use information will need re-analyzing
                dirty_chains = True

                # Copy the instructions from the block that targets the dispatcher
                # onto the end of the jcc taken block.
                mb_head = mb.head
                mb_curr = mb_head
                while True:
                    copy = minsn_t(mb_curr)
                    non_jcc.insert_into_block(copy, non_jcc.tail)
                    mb_curr = mb_curr.next
                    if self.verbose:
                        self.report_info("%d: tail is %s" % (non_jcc.serial, hexrays_util.mcode_t_to_string(non_jcc.tail)))
                    if not mb_curr:
                        break

                # Make a note to ourselves to modify the graph structure later,
                # for the taken side of the conditional. Change the goto target.
                dgm.replace(non_jcc.serial, mb.serial, actual_jcc_target)
                non_jcc.tail.l.b = actual_jcc_target

                # We added instructions to the nonJcc block, so its def-use lists
                # are now spoiled. Mark it dirty.
                non_jcc.mark_lists_dirty()

        # After we've processed every block, apply the deferred modifications to
        # the graph structure.
        changed += dgm.apply(mba)

        # If there were any two-way conditionals, that means we copied
        # instructions onto the jcc taken blocks, which means the def-use info is
        # stale. Mark them dirty, and perform local optimization for the lulz too.
        if dirty_chains:
            mba.mark_chains_dirty()
            mba.optimize_local(0)

        # If we changed the graph, verify that we did so legally.
        if changed:
            self.report_success(blk, changed)
            mba.verify(True)

        return changed
