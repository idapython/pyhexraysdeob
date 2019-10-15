
import ida_bytes
import ida_segment
import ida_xref
from ida_hexrays import *

import def_util
import hexrays_util

def _optimize(blk, ins):
    if blk:
        blk.optimize_insn(ins)
    else:
        ins.optimize_solo()


def _optimize_and_success(blk, ins, rc=1):
    _optimize(blk, ins)
    return rc


# For microinstructions with two or more operands (in l and r), check to see
# if one of them is a mop_d (result of another microinstruction), where the
# provider microinstruction is has opcode type mc. If successful, return the
# provider microinstruction and the non-matching micro-operand in the
# appropriately-named arguments. Otherwise, return false.
# This helper function is useful for performing pattern-matching upon
# commutative operations. Without it, we'd have to write each of our patterns
# twice: once for when the operation we were looking for was on the left-hand
# side, and once for when the operation was on the right-hand side.
def extract_by_opcode_type(ins, mc):
    op_poss_no_match, poss_match = None, None

    # Does the left-hand side contain the operation we're looking for?
    # Update possNoMatch or possMatch, depending.
    if not ins.l.is_insn() or ins.l.d.opcode != mc:
        op_poss_no_match = ins.l
    else:
        poss_mach = ins.l.d

    # Perform the same check on the right-hand side.
    if not ins.r.is_insn() or ins.r.d.opcode != mc:
        op_poss_no_match = ins.r
    else:
        poss_match = ins.r.d

    # If both sides matched, or neither side matched, fail.
    return (op_poss_no_match and poss_match), poss_match, op_poss_no_match


# The obfuscation techniques upon conditional operations have "&1"
# miscellaneously present or not present within them. Writing pattern-matching
# rules for all of the many possibilities would be extremely tedious. This
# helper function reduces the tedium by checking to see whether the provided
# microinstruction is "x & 1" (or "1 & x"), and it extracts x (as both an
# operand, and, if the operand is a mop_d (result of another
# microinstruction), return the provider instruction also.
def tunnel_through_and_1(ins, require_size_1=True, op_is_ok=False):
    op_inner, inner = None, ins

    # Microinstruction must be AND
    if ins.opcode != m_and:
        return False, inner, op_inner

    # One side must be numeric, the other one non-numeric
    op_and_num, op_and_non_num = ins.find_num_op()
    if not op_and_num:
        return False, inner, op_inner

    # The number must be the value 1
    if op_and_num.nnn.value != 1:
        return False, inner, op_inner
    if require_size_1 and op_and_num.size != 1:
        return False, inner, op_inner

    op_inner = op_and_non_num

    # If the non-numeric operand is an instruction, extract the
    # microinstruction and pass that back to the caller.
    if op_and_non_num.is_insn():
        return True, op_and_non_num.d, op_inner

    # Otherwise, if the non-numeric part wasn't a mop_d, check to see whether
    # the caller specifically wanted a mop_d. If they did, fail. If the caller
    # was willing to accept another operand type, return true.
    return op_is_ok, inner, op_inner

def tunnel_through_and_1_loop(ins):
    while True:
        ok, inner, op_inner = tunnel_through_and_1(ins)
        if ok:
            ins = inner
        else:
            break
    return ins


# The obfuscator implements boolean inversion via "x ^ 1". Hex-Rays, or one of
# our other deobfuscation rules, could also convert these to m_lnot
# instructions. This function checks to see if the microinstruction passed as
# argument matches one of those patterns, and if so, extracts the negated
# term as both a micro-operand and a microinstruction (if the negated operand
# was of mop_d type).
def extract_logically_negated_term(ins, op_is_ok=False):
    ins_negated, op_negated = None, None

    # Check the m_lnot case.
    if ins.opcode == m_lnot:

        # Extract the operand
        op_negated = ins.l

        if ins.l.is_insn():
            # If the operand was mop_d (i.e., result of another microinstruction),
            # retrieve the provider microinstruction. Get rid of the pesky "&1"
            # terms while we're at it.
            ins_negated = ins.l.d
            ins_negated = tunnel_through_and_1_loop(ins_negated)
            return True, ins_negated, op_negated
        else:
            # Otherwise, if the operand was not of type mop_d, "success" depends
            # on whether the caller was willing to accept a non-mop_d operand.
            ins_negated = None
            return op_is_ok, ins_negated, op_negated

    # If the operand wasn't m_lnot, check the m_xor case.
    if ins.opcode != m_xor:
        return False, None, None

    # We're looking for XORs with one constant and one non-constant operand
    op_xor_num, op_xor_non_num = ins.find_num_op()
    if not op_xor_num:
        return False, None, None

    # The constant must be the 1-byte value 1
    if op_xor_num.nnn.value != 1 or op_xor_num.size != 1:
        return False, None, None

    # The non-numeric part must also be 1. This check is probably unnecessary.
    if op_xor_non_num.size != 1:
        return False, None, None

    op_negated = op_xor_non_num

    # If the operand was mop_d (result of another microinstruction), extract
    # it and remove the &1 terms.
    if op_xor_non_num.is_insn():
        ins_negated = op_xor_non_num.d
        ins_negated = tunnel_through_and_1_loop(ins_negated)
        return True, ins_negated, op_negated

    # Otherwise, if the operand was not of type mop_d, "success" depends on
    # whether the caller was willing to accept a non-mop_d operand.
    ins_negated = None
    return op_is_ok, ins_negated, op_negated


# This function checks whether two conditional terms are logically opposite.
# For example, "eax <s 1" and "eax >=s 1" would be considered logically
# opposite. The check is purely syntactic; semantically-equivalent conditions
# that were not implemented as syntactic logical opposites will not be
# considered the same by this function.
def are_conditions_opposite(lhs_cond, rhs_cond):

    # Get rid of pesky &1 terms
    lhs_cond = tunnel_through_and_1_loop(lhs_cond)
    rhs_cond = tunnel_through_and_1_loop(rhs_cond)

    # If the conditions were negated via m_lnot or m_xor by 1, get the
    # un-negated part as a microinstruction.
    lhs_was_negated, negated, op_negated = extract_logically_negated_term(lhs_cond, op_is_ok=False)
    if lhs_was_negated:
        lhs_cond = negated
    rhs_was_negated, negated, op_negated = extract_logically_negated_term(rhs_cond, op_is_ok=False)
    if rhs_was_negated:
        rhs_cond = negated

    # lhsCond and rhsCond will be None if their original terms were
    # negated, but the thing that was negated wasn't the result of another
    # microinstruction.
    if not lhs_cond or not rhs_cond:
        return False

    # If one was negated and the other wasn't, compare them for equality.
    # If the non-negated part of the negated comparison was identical to
    # the non-negated comparison, then the conditions are clearly opposite.
    # I guess this could also be extended by incorporating the logic from
    # below, but I didn't need to do that in practice.
    if lhs_was_negated != rhs_was_negated:
        return lhs_cond.equal_insns(rhs_cond, EQ_IGNSIZE|EQ_IGNCODE)

    # Otherwise, if both were negated or both were non-negated, compare the
    # conditionals term-wise. First, ensure that both microoperands are
    # setXX instructions.
    if is_mcode_set(lhs_cond.opcode) and is_mcode_set(rhs_cond.opcode):

        # Now we have two possibilities.
        if negate_mcode_relation(lhs_cond.opcode) == rhs_cond.opcode:
            # 1: Condition codes are opposite, LHS and RHS are both equal
            return lhs_cond.l.equal_mops(rhs_cond.l, EQ_IGNSIZE) \
                and lhs_cond.r.equal_mops(rhs_cond.r, EQ_IGNSIZE)
        if lhs_cond.opcode == rhs_cond.opcode:
            # 2: Condition codes are the same, LHS and RHS are swapped
            return lhs_cond.l.equal_mops(rhs_cond.r, EQ_IGNSIZE) \
                and lhs_cond.r.equal_mops(rhs_cond.l, EQ_IGNSIZE)

    # No dice.
    return False


class xor_simplifier_t:
    def __init__(self):

        # The set of terms in the XOR chain that aren't constant numbers.
        self.const_ops = []
        self.inserted_const = 0

        # The set of terms in the XOR chain that aren't constant numbers.
        self.non_const_ops = []
        self.inserted_non_const = 0

        # This contains references to the operands that can be zeroed out. I.e.,
        # the terms that were cancelled out, before we actually erase them from
        # the microcode itself.
        self.zero_out = []

    # Insert a micro-operand into one of the two sets above. Remove
    # duplicates -- meaning, if the operand we're trying to insert is already
    # in the set, remove the existing one instead. This is the "cancellation"
    # in practice.
    def _insert_in_list(self, _list, op):
        # Because mop_t types currently cannot be compared or hashed in the
        # current microcode API, I had to use a slow linear search procedure
        # to compare the micro-operand we're trying to insert against all
        # previously-inserted values in the relevant set.
        for other_op in _list:
            # If the micro-operand was already in the set, get rid of it.
            if op.equal_mops(other_op, EQ_IGNSIZE):
                _list.remove(other_op)

                # Mark these operands as being able to be deleted.
                self.zero_out.append(op)
                self.zero_out.append(other_op)

                # Couldn't insert.
                return False

        # Otherwise, if it didn't match an operand already in the set, insert
        # it into the set and return true on successful insertion.
        _list.append(op)
        return True

    # Wrapper to insert constant and non-constant terms
    def insert_const(self, op):
        self.inserted_const += 1
        return self._insert_in_list(self.const_ops, op)

    def insert_non_const(self, op):
        self.inserted_non_const += 1
        return self._insert_in_list(self.non_const_ops, op)

    # Insert one micro-operand. If the operand is the result of another XOR
    # microinstruction, recursively insert the operands being XORed.
    # Otherwise, insert the micro-operand into the proper set (constant or
    # non-constant) depending upon its operand type.
    def insert_op(self, op):
        # If operand is m_xor microinstruction, recursively insert children
        if op.t == mop_d and op.d.opcode == m_xor:
            self.insert_op(op.d.l)
            self.insert_op(op.d.r)
        else:
            # Otherwise, insert it into the constant or non-constant set
            if op.t == mop_n:
                self.insert_const(op)
            else:
                self.insert_non_const(op)

    # This function takes an XOR microinstruction and inserts its operands
    # by calling the function above
    def insert_ins(self, ins):
        if ins.opcode == m_xor:
            # Insert children
            self.insert_op(ins.l)
            self.insert_op(ins.r)

    # Were any cancellations performed?
    def did_simplify(self):
        return len(self.zero_out) > 0

    # Top-level functionality to simplify an XOR microinstruction. Insert the
    # instruction, then see if any simplifications could be performed. If so,
    # remove the simplified terms.
    def simplify(self, ins, blk):

        # Only insert XOR instructions
        if ins.opcode != m_xor:
            return False

        self.insert_ins(ins)

        # Were there common terms that could be cancelled?
        if not self.did_simplify():
            return False

        # Perform the cancellations by zeroing out the common micro-operands
        for zo in self.zero_out:
            zo.make_number(0, zo.size)

        # Trigger Hex-Rays' ordinary optimizations, which will remove the
        # XOR 0 terms. Return true.
        return _optimize_and_success(blk, ins, rc=True)



# Our pattern-based deobfuscation is implemented as an optinsn_t structure,
# which allows us to hook directly into the microcode generation phase and
# perform optimizations automatically, whenever code is decompiled.
class obf_compiler_optimizer_t(optinsn_t):

    def report_success(self, ins, blk):
        import inspect
        stack = inspect.stack()
        frame, _, _, _, _, _ = stack[1]
        fun_name = inspect.getframeinfo(frame)[2]
        if fun_name.startswith("pat_"):
            parts = fun_name.split("_")
            parts2 = list(map(str.capitalize, parts))
            fun_name = "pat_" + "".join(parts2[1:])
        hexrays_util.report_success("%s: blk.start=%08X, ins.ea=%08X" % (
            fun_name,
            blk.start if blk else ida_idaapi.BADADDR,
            ins.ea))

    # This function simplifies microinstruction patterns that look like
    # either: (x & 1) | (y & 1) ==> (x | y) & 1
    # or:     (x & 1) ^ (y & 1) ==> (x ^ y) & 1
    # Though it may not seem like much of an "obfuscation" or "deobfuscation"
    # technique on its own, getting rid of the "&1" terms helps reveal other
    # patterns so they can be deobfuscated.
    def pat_logic_and_1(self, ins, blk):

        # Only applies to OR / XOR microinstructions
        if ins.opcode not in [m_or, m_xor]:
            return 0

        # Only applies when the operands are results of other
        # microinstructions (since, after all, we are expecting them to be
        # ANDed by 1, which is represented in terms of a microinstruction
        # provider mop_d operand).
        if ins.l.t != mop_d or ins.r.t != mop_d:
            return 0

        # Get rid of & 1. ok is true if there was an &1.
        ok, ins_left, op_left = tunnel_through_and_1(ins.l.d, True)
        if not ok:
            return 0

        # Same for right-hand side
        ok, ins_right, op_right = tunnel_through_and_1(ins.r.d, True)
        if not ok:
            return 0

        # If we get here, then the pattern matched.
        # Move the logical operation (OR or XOR) to the left-hand side,
        # with the operands that have the &1 removed.
        ins.l.d.opcode = ins.opcode
        ins.l.d.l.swap(op_left)
        ins.l.d.r.swap(op_right)

        # Change the top-level instruction from OR or XOR to AND, and set the
        # right-hand side to the 1-bit constant value 1.
        ins.opcode = m_and
        ins.r.make_number(1, 1)
        self.report_success(ins, blk)

        # Return 1 to indicate that we changed the instruction.
        return 1

    # One of the obfuscation patterns involves a subtraction by 1. In the
    # assembly code, this is implemented by something like:
    #
    # add eax, 2
    # add eax, ecx ; or whatever
    # sub eax, 3
    #
    # Usually, Hex-Rays will automatically simplify this to (eax+ecx)-1.
    # However, I did experience situations where Hex-Rays still represented
    # the decompiled output as 2+(eax+ecx)-3. This function, then, determines
    # when Hex-Rays has represented the subtraction as just mentioned. If so,
    # it extracts the term that is being subtracted by 1.
    def pat_is_sub_by_1(self, ins):
        # We're looking for x+(y-z), where x and z are numeric
        if ins.opcode != m_add:
            return False

        # Extract x and (y-z)
        op_add_num, op_add_non_num = ins.find_num_op();
        if not op_add_num:
            return False

        # Ensure that the purported (y-z) term actually is a subtraction
        if op_add_non_num.t != mop_d or op_add_non_num.d.opcode != m_nsub:
            return False

        # Extract y and z
        op_sub_num, op_sub_non_num = op_add_non_num.d.find_num_op()
        if op_sub_num != op_add_non_num.d.r:
            return False # the constant must to be on the right side.

        # Pass y back to the caller
        op = op_sub_non_num

        # x-z must be -1, or, equivalently, z-x must be 1.
        ok = (op_sub_num.nnn.value - op_add_num.nnn.value) == 1
        return ok, op

    # This function performs the following pattern-substitution:
    # (x * (x-1)) & 1 ==> 0
    def pat_mul_sub(self, and_ins, blk):

        # Topmost term has to be &1. The 1 is not required to be 1-byte large.
        ins = and_ins
        ok, ins, _ = tunnel_through_and_1(ins, require_size_1=False)
        if not ok:
            return 0

        # Looking for multiplication terms
        if ins.opcode != m_mul:
            return 0

        # We have two different mechanisms for determining if there is a
        # subtraction by 1.
        b_was_sub_by_1 = False

        # Ultimately, we need to find thse things:
        # ins_sub        : subtraction instruction x-1
        # op_mul_non_sub : operand of multiply that isn't a subtraction
        # op_sub_non_num : x from the x-1 instruction

        # Try first method for locating subtraction by 1, i.e., simply
        # subtraction by the constant number 1.
        ok, ins_sub, op_mul_non_sub = extract_by_opcode_type(ins, m_sub)
        if ok:
            op_sub_num, op_sub_non_num = ins_sub.find_num_op()
            if op_sub_num:
                b_was_sub_by_1 = op_sub_num.nnn.value == 1

        # If we didn't find the subtraction, see if we have an add/sub pair
        # instead, which totals to subtraction minus one.
        if not b_was_sub_by_1:
            ok, ins_sub, op_mul_non_sub = extract_by_opcode_type(ins, m_add)
            if ok:
                b_was_sub_by_1, op_sub_non_num = self.pat_is_sub_by_1(ins_sub)

        # If both methods failed, bail.
        if not b_was_sub_by_1:
            return 0

        # We know we're dealing with (x-1) * y. ensure x==y.
        if not op_mul_non_sub.equal_mops(op_sub_non_num, EQ_IGNSIZE):
            return 0

        # If we get here, the pattern matched.
        # Replace the whole multiplication instruction by 0.
        ins.l.make_number(0, ins.l.size)
        self.report_success(ins, blk)
        return _optimize_and_success(blk, and_ins)

    # This function looks tries to replace patterns of the form
    # either: (x&y)|(x^y)   ==> x|y
    # or:     (x&y)|(y^x)   ==> x|y
    def pat_or_via_xor_and(self, ins, blk):

        # Looking for OR instructions...
        if ins.opcode != m_or:
            return 0

        # ... where one side is a compound XOR, and the other is not ...
        ok, xor_ins, op_non_xor = extract_by_opcode_type(ins, m_xor)
        if not ok:
            return 0

        # .. and the other side is a compound AND ...
        if op_non_xor.t != mop_d or op_non_xor.d.opcode != m_and:
            return 0

        # Extract the operands for the AND and XOR terms
        op_xor_1 = xor_ins.l
        op_xor_2 = xor_ins.r
        op_and_1 = op_non_xor.d.l
        op_and_2 = op_non_xor.d.r

        # The operands must be equal
        if (not (op_xor_1.equal_mops(op_and_1, EQ_IGNSIZE) and op_xor_2.equal_mops(op_and_2, EQ_IGNSIZE))) \
           or (op_xor_1.equal_mops(op_and_2, EQ_IGNSIZE) and op_xor_2.equal_mops(op_and_1, EQ_IGNSIZE)):
            return 0

        # Move the operands up to the top-level OR instruction
        ins.l.swap(op_xor_1)
        ins.r.swap(op_xor_2)
        self.report_success(ins, blk)
        return _optimize_and_success(blk, ins)

    # This pattern replaces microcode of the form (x|!x), where x is a
    # conditional, and !x is its syntactically-negated version, with 1.
    def pat_or_negated_same_condition(self, ins, blk):
        # Only applies to (x|y)
        if ins.opcode != m_or:
            return 0

        # Only applies when x and y are compound expressions, i.e., results
        # of other microcode instructions.
        if ins.l.t != mop_d or ins.r.t != mop_d:
            return 0

        # Ensure x and y are syntactically-opposite versions of the same
        # conditional.
        if not are_conditions_opposite(ins.l.d, ins.r.d):
            return 0

        # If we get here, the pattern matched. Replace both sides of OR with
        # 1, and then call optimize_flat to fold the constants.
        ins.l.make_number(1, 1)
        ins.r.make_number(1, 1)
        self.report_success(ins, blk)
        return _optimize_and_success(blk, ins)

    # Replace patterns of the form (x&c)|(~x&d) (when c and d are numbers such
    # that c == ~d) with x^d.
    def pat_or_and_not(self, ins, blk):

        # Looking for OR instructions...
        if ins.opcode != m_or:
            return 0

        # ... with compound operands ...
        if ins.l.t != mop_d or ins.r.t != mop_d:
            return 0

        lhs1, rhs1 = ins.l.d, ins.r.d

        # ... where each operand is an AND ...
        if lhs1.opcode != m_and or rhs1.opcode != m_and:
            return 0


        # Extract the numeric and non-numeric operands from both AND terms
        # ... both AND terms must have one constant ...
        op_lhs_num, op_lhs_non_num = lhs1.find_num_op()
        if not op_lhs_num:
            return 0
        op_rhs_num, op_rhs_non_num = rhs1.find_num_op()
        if not op_rhs_num:
            return 0

        # .. both constants have a size, and are the same size ...
        if op_lhs_num.size == NOSIZE or op_lhs_num.size != op_rhs_num.size:
            return 0

        # ... and the constants are bitwise inverses of one another ...
        if (op_lhs_num.nnn.value & op_rhs_num.nnn.value) != 0:
            return 0

        # One of the non-numeric parts must have a binary not (i.e., ~) on it
        # Check the left-hand size for binary not
        op_non_notted, op_notted_num, op_notted = None, None, None
        if op_lhs_non_num.t == mop_d and op_lhs_non_num.d.opcode == m_bnot:
            # Extract the NOTed term
            op_notted = op_lhs_non_num.d.l
            # Make note of the corresponding constant value
            op_notted_num = op_lhs_num
        else:
            op_non_notted = op_lhs_non_num

        # Check the left-hand size for binary not
        if op_rhs_non_num.t == mop_d and op_rhs_non_num.d.opcode == m_bnot:
            # Both sides NOT? Not what we want, return 0
            if op_notted is not None:
                return 0
            # Extract the NOTed term
            op_notted = op_rhs_non_num.d.l
            # Make note of the corresponding constant value
            op_notted_num = op_rhs_num
        else:
            # Neither side has a NOT? Bail
            if op_non_notted is not None:
                return 0
            op_non_notted = op_rhs_non_num

        # The expression that was NOTed must match the non-NOTed operand
        if not op_notted.equal_mops(op_non_notted, EQ_IGNSIZE):
            return 0

        # Okay, all of our conditions matched. Make an XOR(x,d) instruction
        ins.opcode = m_xor
        ins.l.swap(op_non_notted)
        ins.r.swap(op_notted_num)
        self.report_success(ins, blk)
        return 1

    # Remove XOR chains with common terms. E.g. x^5^y^6^5^x ==> y^6.
    # This uses the XorSimplifier class from PatternDeobfuscateUtil.
    def pat_xor_chain(self, ins, blk):
        if ins.opcode != m_xor:
            return 0

        # Automagically find duplicated expressions and erase them
        xs = xor_simplifier_t()
        if not xs.simplify(ins, blk):
            return 0
        self.report_success(ins, blk)
        return 1

    # Compare two sets of mop_t * element-by-element. Return true if they match.
    def non_const_sets_match(self, s1, s2):
        # Iterate over one set
        for eL in s1:
            found = False
            # Iterate over the other set
            for eR in s2:
                # Compare the element from the first set against the ones in
                # the other set.
                if eL.equal_mops(eR, EQ_IGNSIZE):
                    found = True
                    break
            # If we can't find some element from the first set in the other, we're done
            if not found:
                return False
        # All elements matched
        return True

    # Compare two sets of mop_t * (number values) element-by-element. There
    # should be one value in the larger set that's not in the smaller set.
    # Find and return it if that's the case.
    def find_non_common_constant(self, smaller, bigger):
        op_no_match = None
        # Iterate through the larger set
        for eL in bigger:
            found = False
            # Find each element in the smaller set
            for eR in smaller:
                if eL.equal_mops(eR, EQ_IGNSIZE):
                    found = True
                    break
                # We're looking for one constant in the larger set that isn't
                # present in the smaller set.
            if not found:
                # If noMatch was not NULL, then there was more than one
                # constant in the larger set that wasn't in the smaller one,
                # so return NULL on failure.
                if op_no_match is not None:
                    return None
                op_no_match = eL
        # Return the constant from the larger set that wasn't in the smaller
        return op_no_match

    # Matches patterns of the form:
    # (a^b^c^d) & (a^b^c^d^e) => (a^b^c^d) & ~e, where e is numeric
    # The terms don't necessarily have to be in the same order; we extract the
    # XOR subterms from both sides and find the missing value from the smaller
    # XOR chain.
    def pat_and_xor(self, ins, blk):
        # Instruction must be AND ...
        if ins.opcode != m_and:
            return 0

        # ... at least one side must be XOR ...
        left_is_not_xor = ins.l.t != mop_d or ins.l.d.opcode == m_xor
        right_is_not_xor = ins.r.t != mop_d or ins.r.d.opcode == m_xor
        if not left_is_not_xor and not right_is_not_xor:
            return 0

        # Collect the constant and non-constant parts of the XOR chains. We
        # use the XorSimplifier class, but we don't actually simplify the
        # instruction; we just make use of the existing functionality to
        # collect the operands that are XORed together.
        xsL, xsR = xor_simplifier_t(), xor_simplifier_t()
        xsL.insert_op(ins.l)
        xsR.insert_op(ins.r)

        # There must be the same number of non-constant terms on both sides
        if len(xsL.non_const_ops) != len(xsR.non_const_ops):
            return 0

        lxsLc, lxsRc = len(xsL.const_ops), len(xsR.const_ops)

        if lxsLc == lxsRc + 1:
            # Either the left is one bigger than the right...
            smaller, bigger, left_is_smaller = xsR.const_ops, xsL.const_ops, False
        elif lxsRc == lxsLc + 1:
            # Or the right is one bigger than the left...
            smaller, bigger, left_is_smaller = xsL.const_ops, xsR.const_ops, True
        else:
            # Or, the pattern doesn't match, so return 0.
            return 0

        # The sets of non-constant operands must match
        if not self.non_const_sets_match(xsL.non_const_ops, xsR.non_const_ops):
            return 0

        # Find the one constant value that wasn't common to both sides
        # If there wasn't one, the pattern failed, so return 0
        no_match = self.find_non_common_constant(smaller, bigger)
        if not no_match:
            return 0

        # Invert the non-common number and truncate it down to its proper size
        no_match.nnn.update_value(~no_match.nnn.value & ((1 << (no_match.size * 8)) - 1))

        # Replace the larger XOR construct with the now-inverted value
        if left_is_smaller:
            ins.r.swap(no_match)
        else:
            ins.l.swap(no_match)
        self.report_success(ins, blk)
        return 1

    # Replaces conditionals of the form !(!c1 || !c2) with (c1 && c2).
    def pat_lnot_or_lnot_lnot(self, ins, blk):

        # The whole expression must be logically negated.
        ok, inner, _ = extract_logically_negated_term(ins, op_is_ok=False)
        if not ok or inner is None:
            return 0

        # The thing that was negated must be an OR with compound operands.
        if inner.opcode != m_or or inner.l.t != mop_d or inner.r.t != mop_d:
            return 0

        # The two compound operands must also be negated
        ok, _, op_left = extract_logically_negated_term(inner.l.d)
        if not ok:
            return 0
        ok, _, op_right = extract_logically_negated_term(inner.r.d)
        if not ok:
            return 0

        # If we're here, the pattern matched. Make the AND.
        ins.opcode = m_and
        ins.l.swap(op_left)
        ins.r.swap(op_right)
        self.report_success(ins, blk)
        return 1

    # Replaces terms of the form ~(~x | n), where n is a number, with x & ~n.
    def pat_bnot_or_bnot_const(self, ins, blk):
        # We're looking for BNOT instructions (~y)...
        if ins.opcode != m_bnot or ins.l.t != mop_d:
            return 0

        # ... where x is an OR instruction ...
        inner = ins.l.d
        if inner.opcode != m_or:
            return 0

        # ... and one side is constant, where the other one isn't ...
        op_or_num, op_or_non_num = inner.find_num_op()
        if not op_or_num:
            return 0

        # ... and the non-constant part is itself a BNOT instruction (~x)
        if op_or_non_num.t != mop_d or op_or_non_num.d.opcode != m_bnot:
            return 0

        # Once we found it, rewrite the top-level BNOT with an AND
        ins.opcode = m_and
        ins.l.swap(op_or_non_num.d.l)

        # Invert the numeric part
        not_num = ~(op_or_num.nnn.value) & ((1 << (op_or_num.size * 8)) - 1)
        ins.r.make_number(not_num, op_or_num.size)
        self.report_success(ins, blk)
        return 1

    # This function just inspects the instruction and calls the
    # pattern-replacement functions above to perform deobfuscation.
    def optimize(self, ins, blk):
        handlers = {
            m_bnot : self.pat_bnot_or_bnot_const,
            m_or : [
                self.pat_or_and_not,
                self.pat_or_via_xor_and,
                self.pat_or_negated_same_condition,
                self.pat_logic_and_1,
            ],
            m_and : [
                self.pat_and_xor,
                self.pat_mul_sub,
            ],
            m_xor : [
                self.pat_xor_chain,
                self.pat_lnot_or_lnot_lnot,
                self.pat_logic_and_1,
            ],
            m_lnot : self.pat_lnot_or_lnot_lnot,
        }

        rc = 0
        hs = handlers.get(ins.opcode, None)
        if hs is not None:
            if not isinstance(hs, list):
                hs = [hs]
            for h in hs:
                rc = h(ins, blk)
                if rc:
                    break

        return rc

    # Callback function. Do pattern-deobfuscation.
    def func(self, blk, ins):
        ret_val = self.optimize(ins, blk)

        # This callback doesn't seem to get called for subinstructions of
        # conditional branches. So, if we're dealing with a conditional branch,
        # manually optimize the condition expression
        if (is_mcode_jcond(ins.opcode) or \
            is_mcode_set(ins.opcode)) and \
            ins.l.t == mop_d:

            # In order to optimize the jcc condition, we actually need a different
            # structure than optinsn_t: in particular, we need a minsn_visitor_t.
            # This local structure declaration just passes the calls to
            # minsn_visitor_t::visit_minsn onto the Optimize function in this
            # optinsn_t object.
            class blah_t(minsn_visitor_t):
                def __init__(self, oco):
                    minsn_visitor_t.__init__(self)
                    self.oco = oco
                def visit_minsn(self):
                    try:
                        return self.oco.optimize(self.curins, self.blk)
                    except:
                        import traceback
                        traceback.print_exc()
                        raise

            # Optimize all subinstructions of the JCC conditional
            ret_val += ins.for_all_insns(blah_t(self))

        # If any optimizations were performed...
        if ret_val:
            # ... inform the user ...
            hexrays_util.report_debug("ObfCompilerOptimizer: replaced by %s" %
                                      hexrays_util.mcode_t_to_string(ins))

            _optimize(blk, ins)

            # I got an INTERR if I optimized jcc conditionals without marking the lists dirty.
            blk.mark_lists_dirty()
            blk.mba.verify(True)

        return ret_val
