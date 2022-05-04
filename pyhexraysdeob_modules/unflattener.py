
from ida_hexrays import *

import cf_flatten_info
import def_util
import target_util
import hexrays_util
import ida_lines

class assign_searcher_t(minsn_visitor_t):
    """
    Looks for assign
    """
    def __init__(self, op, dispatcher_reg):
        minsn_visitor_t.__init__(self)
        self.op = op
        self.dispatcher_reg = dispatcher_reg
        hexrays_util.report_info(f"Initiated assign_searcher_t, op = {self.op.dstr()}, dispatcher_reg = {self.dispatcher_reg.dstr()}")
        self.jz_target_block = -1
        self.hits = []
        self.assign_infos = []
    def visit_minsn(self):

        ins = self.curins

        # filter out non mov instr.
        if ins.opcode not in [m_mov, m_jz]:
            return 0
        
        if ins.opcode == m_mov:
            # filter out non mop_number as src operand
            if ins.l.t != mop_n and ins.d.t != mop_r:
                return 0

            if ins.d.dstr() == self.op.dstr():
                hexrays_util.report_info(f"AssignSearcher hit: {ins.dstr()}")
                self.hits.append(ins)
            return 0
        else:

            if (ins.l.dstr() == self.dispatcher_reg.dstr() and ins.r.dstr() == self.op.dstr()) or (ins.l.dstr() == self.op.dstr() and ins.r.dstr() == self.dispatcher_reg.dstr()):
                block_no = ins.d.b
                hexrays_util.report_info(f"Current instruction = {ins.dstr()}, block = {block_no}")
                self.jz_target_block = block_no
            return 0


class cf_unflattener_t(optblock_t):
    """
    Main unflattener class.
    """

    def __init__(self, plugin):
        optblock_t.__init__(self)
        self.cfi = cf_flatten_info.cf_flatten_info_t(plugin)
        self.plugin = plugin
        self.last_maturity = MMAT_ZERO
        self.clear()
        self.verbose = True
        self.debug = True

    def report_success(self, blk, changed):
        hexrays_util.report_success(f"UNFLATTENER: blk.start={hex(blk.start)} (changed={changed})")

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


    def get_dominated_cluster_head(self, mba, disp_pred):
        """
        Find block dominating the dispatcher predecessor and is one of the targets
        of the CFG switch.
        :param mba: mba_t object
        :param disp_pred: dispatcher predecessor serial
        :return: Flag if succeeded, mblock_t, mblock_t serial
        """
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
                self.report_info(f"Cluster_head returned zero!")
                return False, None, None
            mb_cluster_head = mba.get_mblock(cluster_head)
            self.report_info(f"Block {disp_pred} was part of dominated cluster {cluster_head}")

        return True, mb_cluster_head, cluster_head
    
    def get_dominated_cluster_head_by_pattern_dirty(self, mba, mb):
        """
        Return the dominated cluster head by pattern.
        This looks at dom_info, searching for the start of the cluster.
        :param mba: mba_t object
        :param disp_pred: dispatcher predecessor
        :return: Flag if succeeded, mblock_t, mblock_t serial
        """
        
        ok = False
        mb_cluster_head, cluster_head = None, -1

        # get the predset into a separate list
        visited_preds = [mb_serial for mb_serial in mb.predset]
        visited_preds.append(mb.serial)
        self.report_info(f"Searching for cluster_head the dirty way, serial = {mb.serial}, predset = {visited_preds}")

        # go through the predsets
        for pred in visited_preds:
            pred_mb = mba.get_mblock(pred)
            for mb_pred_serial in pred_mb.predset:
                target_mb = mba.get_mblock(mb_pred_serial)
                self.report_debug(f"Visited pred = {pred}, mb_pred_serial = {mb_pred_serial}")
                # if one of the predecessors of the predsets is not in the visited_preds array
                # then take that one separately
                if mb_pred_serial not in visited_preds:
                    dom_info = self.cfi.dom_info[mb_pred_serial]
                    self.report_info(f"Potential cluster_head found, potential_target = {mb_pred_serial}, dom_info = {','.join(str(x) for x in dom_info)}")
                else:
                    continue
                visited_preds.append(mb_pred_serial)

                # check if the dom_info includes visited_preds and the current serial
                # if not, that's not a potential cluster head
                for node in dom_info:
                    self.report_debug(f"Node = {node}")
                    if node not in visited_preds:
                        return ok, mb_cluster_head, cluster_head

                target_pred_mb = mba.get_mblock(target_mb.predset[0])
                # if yes, take the successor, see if the successor branches into 
                # this block in the final instruction via a jz/jc or w.e.
                # if all of this succeeds, we found our dirty cluster head
                last_instr = target_pred_mb.tail
                # not a jz ? don't continue
                if last_instr.opcode != m_jz:
                    self.report_debug(f"Last instruction is not a jump, last_instr = {last_instr.dstr()}")
                    return ok, mb_cluster_head, cluster_head
                
                # is the target block our dispatcher block? great we found it!
                dest_no = last_instr.d.b
                self.report_info(f"cluster_head_dirty, last_instruction = {last_instr.dstr()}, target_block = {dest_no}")
                if dest_no == target_mb.serial:
                    self.report_info(f"Cluster head found! Cluster serial = {dest_no}")
                    return True, mba.get_mblock(dest_no), dest_no
                else:
                    self.report_info(f"Failed finding cluster head via dirty_method for block = {mb.serial}")
                    return ok, mb_cluster_head, cluster_head

        return ok, mb_cluster_head, cluster_head
        

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

        hexrays_util.report_info(f"Current what = {what.dstr()}")

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
            hexrays_util.report_info(f"Local array is zero, failed backward search! Dirty search now for block = {mb.serial}")
            if mb.get_reginsn_qty() == 2:
                hexrays_util.report_info(f"2 instructions check suceeded!")
                head_insn = mb.head
                hexrays_util.report_info(f"Head instruction = {head_insn.dstr()}")
            return -1
        
        hexrays_util.report_info(f"Local array not zero!")

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
        hexrays_util.report_info(f"OpCopy = {op_copy.dstr()}")
        if not found and op_copy and op_copy.t == mop_S:
            hexrays_util.report_info("Running forward analysis")
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
            if dest_no < 0:
                self.report_error(f"Block {mb.serial} assigned unknown key {hex(op_num.nnn.value)} to assigned var")
        else:

            # search all instructions, if the register is assigned only ONCE and that is with a 
            # high entropy variable, we can extract the high entropy value, and grab the block by key via that 
            hexrays_util.report_info(f"Attempting to search for block by key via iterating all instructions, op_copy = {op_copy}")
            searcher = assign_searcher_t(op_copy, self.cfi.op_compared)
            mba.for_all_topinsns(searcher)
            if len(searcher.hits) == 1:
                hexrays_util.report_info(f"Only one assignment, {searcher.hits[0].dstr()}")
                key = searcher.hits[0].l.nnn.value
                dest_no = self.cfi.find_block_by_key(key)
                if dest_no == -1:
                    dest_no = searcher.jz_target_block
                    hexrays_util.report_info(f"Target block via assign_searcher = {dest_no}")
                return dest_no




        return dest_no

    def handle_two_preds(self, mb, mb_cluster_head, op_copy):
        """
        Handle constructs with two successors, f.e. if statements
        If block assigns to assignment variable with 2 predecessors, analyse each
        predecessor looking for numeric assignments by calling the previous function
        :param mb: mblock_t
        :param mb_cluster_head: cluster head mblock_t
        :param op_copy:
        :return:
        """
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



    def process_erasures(self, mba):
        """
        Erase superfluos chain of instructions, used to copy numeric value
        into assignment variable.
        :param mba: mba_t
        """
        self.performed_erasures_global.extend(self.deferred_erasures_local)
        for erase in self.deferred_erasures_local:
            
            self.report_info("Erasing %08X: %s" % (
                erase.ins_mov.ea,
                ida_lines.tag_remove(erase.ins_mov._print())))
            # Be gone, sucker
            mba.get_mblock(erase.block).make_nop(erase.ins_mov)
        self.deferred_erasures_local = []


    def func(self, blk):
        """
        Top level unflattening function for entire graph.
        :param blk: mblock_t
        :return: number of changes applied
        """

        mba = blk.mba

        # if added to white list, we continue
        if mba.entry_ea in self.plugin.black_list and mba.entry_ea not in self.plugin.white_list:
            return 0

        # Only operate once per maturity level, update maturity, operate only on MMAT_LOCOPT
        if self.last_maturity == mba.maturity:
            return 0
        self.last_maturity = mba.maturity
        if mba.maturity != MMAT_LOCOPT:
            return 0
        
        # remove single gotos
        changed = target_util.remove_single_gotos(mba)
        hexrays_util.report_info(f"Number of single GOTOS changed = {changed}")
        if changed != 0:
            mba.verify(True)
        
        # collect assignment and comp. variables
        # main routine to collect cfg information
        if not self.cfi.get_assigned_and_comparison_variables(blk):
            self.report_error("Failed collecting control-flow flattening information")
            return changed

        # Create an object that allows us to modify the graph at a future point.
        dgm = target_util.deferred_graph_modifier_t()
        dirty_chains = False

        # if flag to run for multiple dispatchers is deactivated,
        # then adjust the array to contain the dispatch block detected by 
        # get_first_block only
        if self.plugin.RUN_MLTPL_DISPATCHERS is False:
            self.report_info(f"RUN_MLTPL_DISPATCHERS = {self.plugin.RUN_MLTPL_DISPATCHERS}")
            self.cfi.detected_dispatchers = [self.cfi.dispatch]
        
        self.report_info(f"Number of dispatchers to unflatten = {len(self.cfi.detected_dispatchers)}")
        for detected_dispatcher in self.cfi.detected_dispatchers:
            
            # update the object variable, get predecessors
            self.cfi.dispatch = detected_dispatcher
            dispatch_predset_block = mba.get_mblock(self.cfi.dispatch)
            if dispatch_predset_block is None:
                self.report_error(f"Could not retrieve block for serial = {self.cfi.dispatch}")
                continue

            dispatch_predset = dispatch_predset_block.predset
            self.report_info(f"DispatcherBlock = {self.cfi.dispatch}, predset = {dispatch_predset}")
            
            # Iterate through the predecessors of the top-level control flow switch
            for disp_pred in dispatch_predset:

                only_erase = False
                mb = mba.get_mblock(disp_pred)
                self.report_info(f"dispatcher = {self.cfi.dispatch}, deobfuscating predecessor = {disp_pred}, pred_successors = {mb.nsucc()}")

                # if we have multiple successors, we check whether the last instruction of the block is a jnz,
                # if yes, then get the next block, because this will be the successor
                # if the successor ends with a goto, we update the block we want to check to the successor
                # we set a flag 'only_erase' that we only want to erase the state update in that block, but not the
                # goto itself. Cases like this always ended up as 'failure states' in Emotet. Meaning that the 
                # follow-up block end the complete function
                # This might need additional hardening at later stages
                if mb.nsucc() != 1:
                    tail = mb.tail
                    if tail.opcode == m_jnz:
                        self.report_info(f"Tail instruction is jnz, checking if follow block tail is goto to dispatcher ..")
                        flw_block = mba.get_mblock(disp_pred + 1)
                        if flw_block.tail.opcode == m_goto:
                            self.report_info(f"Tail is goto! patching this block = {disp_pred + 1}, only erasing the assignment")
                            disp_pred = disp_pred + 1
                            mb = mba.get_mblock(disp_pred)
                            only_erase = True
                    else:
                        continue

                # Find the block that dominates this cluster, or skip this block if
                # we can't. This ensures that we only try to unflatten parts of the
                # control flow graph that were actually flattened. Also, we need the
                # cluster head so we know where to bound our searches for numeric
                # definitions.
                ok, mb_cluster_head, cluster_head = self.get_dominated_cluster_head(mba, disp_pred)
                if not mb_cluster_head:
                    # added additional method to search for the cluster head
                    self.report_info(f"Could not find dominated cluster head for pred = {disp_pred} via get_dominated_cluster_head.")
                    ok, mb_cluster_head, cluster_head = self.get_dominated_cluster_head_by_pattern_dirty(mba, mb)
                    if not ok:
                        self.report_info(f"Could not find dominated cluster head for pred = {disp_pred} via dirty way")
                        continue
 
                self.report_info(f"disp_pred = {disp_pred}, cluster_head = {cluster_head}")
                self.deferred_erasures_local = []

                # Try to find a numeric assignment to the assignment variable, but
                # pass false for the last parameter so that the search stops if it
                # reaches a block with more than one successor. This ought to succeed
                # if the flattened control flow region only has one destination,
                # rather than two destinations for flattening of if-statements.
                dest_no = self.find_block_target_or_last_copy(
                    mb, mb_cluster_head, self.cfi.op_assigned, allow_multi_succs=False)

                #!TODO what do we do here...?
                if dest_no == disp_pred:
                    self.report_info(f"Found branch where destination == block, setting dest_no as value in ")
                    continue
                    # dest_no2 = self.cfi.block_to_key[disp_pred]
                    # self.report_info(f"Key = {hex(dest_no2)}")
                # if we couldn't find a proper destination, for the block so far
                # we will try to search for the proper destination by applying pattern matching
                elif dest_no == -1:

                    self.report_info(f"Could not find destination for block = {disp_pred}, attempting pattern search now")
                    disp_block = mba.get_mblock(self.cfi.dispatch)
                    tail_reg = disp_block.tail
                    # if the block has no instruction, return that fetching the dest. block failed
                    if tail_reg == None:
                        dest_no = -1
                    else:
                        # otherwise check if it is a jg instruction
                        # if yes, and there is only 1 successor for the jg block
                        # continue as this means if the jg jump fails, we can only
                        # enter a single successor branch
                        # if the successor branch final instruction is a jcnd,
                        # this is a potential dest block
                        if tail_reg.opcode == m_jg:
                            self.report_info(f"Dispatcher block tail is jg instruction")

                            succ_block = mba.get_mblock(self.cfi.dispatch + 1)
                            if succ_block.tail.opcode == m_jcnd:
                                dest_no = succ_block.tail.d.b
                                self.report_info(f"Destination via jcnd pattern = {dest_no}")


                # Couldn't find any assignments at all to the assignment variable?
                # That's bad, don't continue.
                if not self.deferred_erasures_local:
                    self.report_info(f"No assignments found for block = {disp_pred}!")
                    continue

                # Did we find a block target? Great; just update the CFG to point the
                # destination directly to its target, rather than back to the
                # dispatcher.
                if dest_no >= 0:
                    # Make a note to ourselves to modify the graph structure later
                    msg = ""
                    if only_erase == False:
                        dgm.change_goto(mb, self.cfi.dispatch, dest_no)
                        msg = f"Changed goto on {disp_pred} to {dest_no}"
                    else:
                        msg = f"Erasing only the instruction, only_erase = {only_erase}"

                    # Erase the intermediary assignments to the assignment variable
                    self.process_erasures(mba)
                    self.report_info(msg)

                    changed += 1
                    continue

                # Stash off a copy of the last variable in the chain of assignments
                # to the assignment variable, as well as the assignment instruction
                # (the latter only for debug-printing purposes).
                op_copy = self.deferred_erasures_local[-1].op_copy
                m = self.deferred_erasures_local[-1].ins_mov
                self.report_info(f"Block {disp_pred} did not define assign a number to assigned var; assigned {hexrays_util.mopt_t_to_string(m.l.t)} instead")


                # Call the function that handles the case of a conditional assignment
                # to the assignment variable (i.e., the flattened version of an
                # if-statement).
                ok, ends_with_jcc, non_jcc, actual_goto_target, actual_jcc_target = self.handle_two_preds(
                    mb, mb_cluster_head, op_copy)
                if ok:

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
                        if not mb_curr:
                            break

                    # Make a note to ourselves to modify the graph structure later,
                    # for the taken side of the conditional. Change the goto target.
                    dgm.replace(non_jcc.serial, mb.serial, actual_jcc_target)
                    non_jcc.tail.l.b = actual_jcc_target

                    # We added instructions to the nonJcc block, so its def-use lists
                    # are now spoiled. Mark it dirty.
                    non_jcc.mark_lists_dirty()
        
        
        changed += dgm.apply(mba, self.cfi)
        # After we've processed every block, apply the deferred modifications to
        # the graph structure.

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
    
