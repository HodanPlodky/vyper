import operator

from vyper.exceptions import CompilerPanic
from vyper.utils import (
    evm_div,
    evm_mod,
    evm_pow,
    int_bounds,
    int_log2,
    is_power_of_two,
    signed_to_unsigned,
    unsigned_to_signed,
)
from vyper.venom.analysis.dfg import DFGAnalysis
from vyper.venom.analysis.equivalent_vars import VarEquivalenceAnalysis
from vyper.venom.analysis.liveness import LivenessAnalysis
from vyper.venom.basicblock import IRInstruction, IRLabel, IRLiteral, IROperand, IRVariable
from vyper.venom.passes.base_pass import IRPass

# from vyper.venom.venom_to_assembly import COMMUTATIVE_INSTRUCTIONS

SIGNED = False
UNSIGNED = True

COMMUTATIVE_OPS = {"add", "mul", "eq", "ne", "and", "or", "xor"}
COMPARISON_OPS = {"gt", "sgt", "ge", "sge", "lt", "slt", "le", "sle"}
STRICT_COMPARISON_OPS = {t for t in COMPARISON_OPS if t.endswith("t")}
UNSTRICT_COMPARISON_OPS = {t for t in COMPARISON_OPS if t.endswith("e")}


def _wrap256(x, unsigned=UNSIGNED):
    x %= 2**256
    # wrap in a signed way.
    if not unsigned:
        x = unsigned_to_signed(x, 256, strict=True)
    return x


# unsigned: convert python num to evm unsigned word
#   e.g. unsigned=True : -1 -> 0xFF...FF
#        unsigned=False: 0xFF...FF -> -1
def _evm_int(lit: IRLiteral | None, unsigned: bool = True) -> int | None:
    if lit is None:
        return None

    val: int = lit.value

    if unsigned and val < 0:
        return signed_to_unsigned(val, 256, strict=True)
    elif not unsigned and val > 2**255 - 1:
        return unsigned_to_signed(val, 256, strict=True)

    return val


def _check_num(val: int) -> bool:
    if val < -(2**255):
        return False
    elif val >= 2**256:
        return False
    return True


arith = {
    "add": (operator.add, "+", UNSIGNED),
    "sub": (operator.sub, "-", UNSIGNED),
    "mul": (operator.mul, "*", UNSIGNED),
    "div": (evm_div, "/", UNSIGNED),
    "sdiv": (evm_div, "/", SIGNED),
    "mod": (evm_mod, "%", UNSIGNED),
    "smod": (evm_mod, "%", SIGNED),
    "exp": (evm_pow, "**", UNSIGNED),
    "eq": (operator.eq, "==", UNSIGNED),
    "ne": (operator.ne, "!=", UNSIGNED),
    "lt": (operator.lt, "<", UNSIGNED),
    "le": (operator.le, "<=", UNSIGNED),
    "gt": (operator.gt, ">", UNSIGNED),
    "ge": (operator.ge, ">=", UNSIGNED),
    "slt": (operator.lt, "<", SIGNED),
    "sle": (operator.le, "<=", SIGNED),
    "sgt": (operator.gt, ">", SIGNED),
    "sge": (operator.ge, ">=", SIGNED),
    "or": (operator.or_, "|", UNSIGNED),
    "and": (operator.and_, "&", UNSIGNED),
    "xor": (operator.xor, "^", UNSIGNED),
}


def _flip_comparison_op(opname):
    assert opname in COMPARISON_OPS
    if "g" in opname:
        return opname.replace("g", "l")
    if "l" in opname:
        return opname.replace("l", "g")
    raise CompilerPanic(f"bad comparison op {opname}")  # pragma: nocover


class AlgebraicOptimizationPass(IRPass):
    """
    This pass reduces algebraic evaluatable expressions.

    It currently optimizes:
        * iszero chains
    """

    dfg: DFGAnalysis

    def _optimize_iszero_chains(self) -> None:
        fn = self.function
        for bb in fn.get_basic_blocks():
            for inst in bb.instructions:
                if inst.opcode != "iszero":
                    continue

                iszero_chain = self._get_iszero_chain(inst.operands[0])
                iszero_count = len(iszero_chain)
                if iszero_count == 0:
                    continue

                assert isinstance(inst.output, IRVariable)
                for use_inst in self.dfg.get_uses(inst.output):
                    opcode = use_inst.opcode

                    if opcode == "iszero":
                        # We keep iszero instuctions as is
                        continue
                    if opcode in ("jnz", "assert"):
                        # instructions that accept a truthy value as input:
                        # we can remove up to all the iszero instructions
                        keep_count = 1 - iszero_count % 2
                    else:
                        # all other instructions:
                        # we need to keep at least one or two iszero instructions
                        keep_count = 1 + iszero_count % 2

                    if keep_count >= iszero_count:
                        continue

                    out_var = iszero_chain[keep_count].operands[0]
                    use_inst.replace_operands({inst.output: out_var})

    def _get_iszero_chain(self, op: IROperand) -> list[IRInstruction]:
        chain: list[IRInstruction] = []

        while True:
            assert isinstance(op, IRVariable)
            inst = self.dfg.get_producing_instruction(op)
            if inst is None or inst.opcode != "iszero":
                break
            op = inst.operands[0]
            chain.append(inst)

        chain.reverse()
        return chain

    def eval_op(self, op: IROperand) -> IRLiteral | None:
        if isinstance(op, IRLiteral):
            return op
        elif isinstance(op, IRVariable):
            next_inst = self.dfg.get_producing_instruction(op)
            assert next_inst is not None, f"must have producing inst {op}\n{self.dfg._dfg_outputs}"
            return self.eval(next_inst)
        else:
            return None

    def eval(self, inst: IRInstruction) -> IRLiteral | None:
        if inst.opcode == "store":
            if isinstance(inst.operands[0], IRLiteral):
                return inst.operands[0]
            elif isinstance(inst.operands[0], IRVariable):
                next_inst = self.dfg.get_producing_instruction(inst.operands[0])
                assert next_inst is not None, "must have producing inst"
                return self.eval(next_inst)
        return None

    def static_eq(
        self, op_0: IROperand, op_1: IROperand, eop_0: IRLiteral | None, eop_1: IRLiteral | None
    ) -> bool:
        return (eop_0 is not None and eop_0 == eop_1) or self.eq_analysis.equivalent(op_0, op_1)

    def _peepholer(self):
        while True:
            change = False
            for bb in self.function.get_basic_blocks():
                for inst in bb.instructions:
                    change |= self._handle_inst_peephole(inst)

            if not change:
                break

    def _handle_inst_peephole(self, inst: IRInstruction) -> bool:
        def update(opcode: str, *args: IROperand | int) -> bool:
            inst.opcode = opcode
            inst.operands = [arg if isinstance(arg, IROperand) else IRLiteral(arg) for arg in args]
            return True

        def store(*args: IROperand | int) -> bool:
            return update("store", *args)

        if len(inst.operands) < 1:
            return False

        opcode = inst.opcode
        op_0 = inst.operands[0]
        eop_0 = self.eval_op(inst.operands[0])

        if opcode == "iszero" and _evm_int(eop_0) is not None:
            val = _evm_int(eop_0)
            assert val is not None, "Cannot be none"
            val = int(val == 0)
            return store(val)

        if len(inst.operands) != 2:
            return False

        op_1 = inst.operands[1]
        eop_1 = self.eval_op(inst.operands[1])

        if (
            opcode == "add"
            and isinstance(eop_0, IRLiteral)
            and isinstance(inst.operands[1], IRLabel)
        ):
            inst.opcode = "offset"
            return True

        if opcode in COMMUTATIVE_OPS and eop_1 is not None:
            eop_0, eop_1 = eop_1, eop_0
            op_0, op_1 = op_1, op_0

        if opcode in {"shl", "shr", "sar"} and _evm_int(eop_1) == 0:
            # x >> 0 == x << 0 == x
            return store(op_0)

        if inst.opcode not in arith.keys():
            return False
        fn, _, unsigned = arith[inst.opcode]

        if isinstance(eop_0, IRLiteral) and isinstance(eop_1, IRLiteral):
            assert isinstance(eop_0.value, int), "must be int"
            assert isinstance(eop_1.value, int), "must be int"
            a = _evm_int(eop_0, unsigned)
            b = _evm_int(eop_1, unsigned)
            res = fn(b, a)
            res = _wrap256(res, unsigned)
            if res is not None and _check_num(res):
                inst.opcode = "store"
                inst.operands = [IRLiteral(res)]
                return True

        if opcode in {"add", "sub", "xor", "or"} and eop_0 == IRLiteral(0):
            return store(op_1)

        if opcode in {"sub", "xor", "ne"} and self.static_eq(op_0, op_1, eop_0, eop_1):
            # (x - x) == (x ^ x) == (x != x) == 0
            return store(0)

        if opcode in STRICT_COMPARISON_OPS and self.static_eq(op_0, op_1, eop_0, eop_1):
            # (x < x) == (x > x) == 0
            return store(0)

        if opcode in {"eq"} | UNSTRICT_COMPARISON_OPS and self.static_eq(op_0, op_1, eop_0, eop_1):
            # (x == x) == (x >= x) == (x <= x) == 1
            return store(1)

        if (
            opcode in {"mul", "div", "sdiv", "mod", "smod", "and"}
            and _evm_int(eop_0, unsigned) == 0
        ):
            return store(0)

        if opcode in {"mod", "smod"} and eop_0 == IRLiteral(1):
            return store(0)

        if opcode in {"mul", "div", "sdiv"} and eop_0 == IRLiteral(1):
            return store(op_1)
        if opcode in {"and", "or", "xor"} and _evm_int(eop_0, SIGNED) == -1:
            assert unsigned == UNSIGNED, "must be unsigned"
            if opcode == "and":
                # -1 & x == x
                return store(op_1)

            if opcode == "xor":
                # -1 ^ x == ~x
                return update("not", op_1)

            if opcode == "or":
                # -1 | x == -1
                val = _evm_int(IRLiteral(-1), unsigned)
                assert val is not None
                return store(val)

            raise CompilerPanic("unreachable")  # pragma: nocover

        # -1 - x == ~x (definition of two's complement)
        if opcode == "sub" and _evm_int(eop_1, SIGNED) == -1:
            return update("not", op_0)  # finalize("not", [args[1]])

        if opcode == "exp":
            # n ** 0 == 1 (forall n)
            # 1 ** n == 1
            if _evm_int(eop_0) == 0 or _evm_int(eop_1) == 1:
                return store(1)
            # 0 ** n == (1 if n == 0 else 0)
            if _evm_int(eop_1) == 0:
                return update("iszero", op_0)
            # n ** 1 == n
            if _evm_int(eop_0) == 1:
                return store(op_1)

        val = _evm_int(eop_0)
        if (
            opcode in {"mod", "div", "mul"}
            and isinstance(eop_0, IRLiteral)
            and val is not None
            and is_power_of_two(val)
        ):
            val_0 = _evm_int(eop_0)
            assert isinstance(val_0, int)
            assert unsigned == UNSIGNED, "something's not right."
            # shave two gas off mod/div/mul for powers of two
            # x % 2**n == x & (2**n - 1)
            if opcode == "mod":
                return update("and", val_0 - 1, op_1)

            if opcode == "div":
                # x / 2**n == x >> n
                # recall shr/shl have unintuitive arg order
                return update("shr", op_1, int_log2(val_0))

            # note: no rule for sdiv since it rounds differently from sar
            if opcode == "mul":
                # x * 2**n == x << n
                return update("shl", op_1, int_log2(val_0))

            raise CompilerPanic("unreachable")  # pragma: no cover

        # the not equal equivalent is not needed
        if opcode == "eq" and eop_0 == IRLiteral(0):
            return update("iszero", op_1)

        if opcode == "eq" and eop_1 == IRLiteral(0):
            return update("iszero", op_0)

        if opcode == "eq" and self.eq_analysis.equivalent(op_0, op_1):
            return store(1)

        assert isinstance(inst.output, IRVariable), "must be variable"
        uses = self.dfg.get_uses(inst.output)
        is_truthy = all(i.opcode in ("assert", "iszero") for i in uses)

        if is_truthy:
            if opcode == "eq":
                assert unsigned == UNSIGNED, "must be unsigned"
                # (eq x y) has the same truthyness as (iszero (xor x y))
                # it also has the same truthyness as (iszero (sub x y)),
                # but xor is slightly easier to optimize because of being
                # commutative.
                # note that (xor (-1) x) has its own rule
                index = inst.parent.instructions.index(inst)
                tmp = inst.parent.parent.get_next_variable()
                tmp_inst = IRInstruction("xor", [op_0, op_1], output=tmp)
                inst.parent.insert_instruction(tmp_inst, index)
                self.dfg.add_output(tmp, tmp_inst)
                self.dfg.add_use(tmp, inst)

                return update("iszero", tmp)

            # TODO can we do this?
            # if val == "div":
            #     return finalize("gt", ["iszero", args])

            if opcode == "or" and isinstance(eop_0, IRLiteral) and eop_0 != 0:
                # (x | y != 0) for any (y != 0)
                return store(1)

        if opcode in COMPARISON_OPS:
            prefer_strict = not is_truthy
            if isinstance(eop_1, IRLiteral):  # _is_int(args[0]):
                opcode = _flip_comparison_op(opcode)
                inst.opcode = opcode
                eop_0, eop_1 = eop_1, eop_0
                op_0, op_1 = op_1, op_0
                inst.operands[0], inst.operands[1] = op_0, op_1

            is_gt = "g" in opcode

            # local version of _evm_int which defaults to the current binop's signedness
            def _int(x):
                return _evm_int(x, unsigned=unsigned)

            lo, hi = int_bounds(bits=256, signed=not unsigned)

            # for comparison operators, we have three special boundary cases:
            # almost always, never and almost never.
            # almost_always is always true for the non-strict ("ge" and co)
            # comparators. for strict comparators ("gt" and co), almost_always
            # is true except for one case. never is never true for the strict
            # comparators. never is almost always false for the non-strict
            # comparators, except for one case. and almost_never is almost
            # never true (except one case) for the strict comparators.
            if is_gt:
                almost_always, never = lo, hi
                almost_never = hi - 1
            else:
                almost_always, never = hi, lo
                almost_never = lo + 1

            if _int(eop_0) == never:
                # e.g. gt x MAX_UINT256, slt x MIN_INT256
                return store(0)

            if _int(eop_0) == almost_never:
                # (lt x 1), (gt x (MAX_UINT256 - 1)), (slt x (MIN_INT256 + 1))
                return update("eq", op_1, never)

            # rewrites. in positions where iszero is preferred, (gt x 5) => (ge x 6)
            if not prefer_strict and _int(eop_0) == almost_always:
                # e.g. gt x 0, slt x MAX_INT256
                index = inst.parent.instructions.index(inst)
                tmp = inst.parent.parent.get_next_variable()
                tmp_inst = IRInstruction("eq", [op_0, op_1], output=tmp)
                inst.parent.insert_instruction(tmp_inst, index)
                self.dfg.add_output(tmp, tmp_inst)
                self.dfg.add_use(tmp, inst)

                return update("iszero", tmp)

            # special cases that are not covered by others:

            if opcode == "gt" and eop_0 == 0:
                # improve codesize (not gas), and maybe trigger
                # downstream optimizations
                index = inst.parent.instructions.index(inst)
                tmp = inst.parent.parent.get_next_variable()
                tmp_inst = IRInstruction("iszero", [op_1], output=tmp)
                inst.parent.insert_instruction(tmp_inst, index)
                self.dfg.add_output(tmp, tmp_inst)
                self.dfg.add_use(tmp, inst)

                return update("iszero", tmp)
        return False

    def _comparison(self, inst: IRInstruction, prefer_strict: bool) -> bool:
        return False

    def run_pass(self):
        dfg = self.analyses_cache.request_analysis(DFGAnalysis)
        assert isinstance(dfg, DFGAnalysis)
        self.dfg = dfg

        self.eq_analysis = self.analyses_cache.request_analysis(VarEquivalenceAnalysis)

        self._peepholer()
        self._optimize_iszero_chains()

        self.analyses_cache.invalidate_analysis(DFGAnalysis)
        self.analyses_cache.invalidate_analysis(LivenessAnalysis)
