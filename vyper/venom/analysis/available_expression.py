from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from functools import cached_property

import vyper.venom.effects as effects
from vyper.venom.analysis.analysis import IRAnalysesCache, IRAnalysis
from vyper.venom.analysis.cfg import CFGAnalysis
from vyper.venom.analysis.dfg import DFGAnalysis
from vyper.venom.basicblock import (
    BB_TERMINATORS,
    COMMUTATIVE_INSTRUCTIONS,
    IRBasicBlock,
    IRInstruction,
    IROperand,
    IRVariable,
)
from vyper.venom.context import IRFunction
from vyper.venom.effects import Effects

NONIDEMPOTENT_INSTRUCTIONS = frozenset(["log", "call", "staticcall", "delegatecall", "invoke"])

# instructions that queries info about current
# environment this is done because we know that
# all these instruction should have always
# the same value in function


# instruction that dont need to be stored in available expression
UNINTERESTING_OPCODES = frozenset(
    [
        "calldatasize",
        "gaslimit",
        "address",
        "codesize",
        "store",
        "phi",
        "param",
        "nop",
        "returndatasize",
        "gas",
        "gasprice",
        "origin",
        "coinbase",
        "timestamp",
        "number",
        "prevrandao",
        "chainid",
        "basefee",
        "blobbasefee",
        "pc",
        "msize",
    ]
)


@dataclass
class _Expression:
    opcode: str
    # the child is either expression of operand since
    # there are possibilities for cycles
    operands: list[IROperand | _Expression]
    cache_hash: int | None = None

    # equality for lattices only based on original instruction
    def __eq__(self, other) -> bool:
        if not isinstance(other, _Expression):
            return False
        return self.same(other)

    def __hash__(self) -> int:
        # Unfortunately the hash has been the performance
        # bottle neck in some cases so I cached the value
        if self.cache_hash is None:
            # the reason for the sort is that some opcodes could
            # be commutative and in that case the order of the
            # operands would not matter (so this is needed)
            # for correct implementation of hash (x == x => hash(x) == hash(y))
            self.cache_hash = hash((self.opcode, tuple(sorted(hash(op) for op in self.operands))))
        return self.cache_hash

    # Full equality for expressions based on opcode and operands
    def same(self, other) -> bool:
        return same(self, other)

    def __repr__(self) -> str:
        if self.opcode == "store":
            assert len(self.operands) == 1, "wrong store"
            return repr(self.operands[0])
        res = self.opcode + "("
        res += ",".join(repr(op) for op in self.operands)
        res += ")"
        return res

    @cached_property
    def depth(self) -> int:
        max_depth = 0
        for op in self.operands:
            if isinstance(op, _Expression):
                d = op.depth
                if d > max_depth:
                    max_depth = d
        return max_depth + 1

    def get_reads(self, ignore_msize) -> Effects:
        tmp_reads = effects.reads.get(self.opcode, effects.EMPTY)
        if ignore_msize:
            tmp_reads &= ~Effects.MSIZE
        return tmp_reads

    def get_writes(self, ignore_msize) -> Effects:
        tmp_reads = effects.writes.get(self.opcode, effects.EMPTY)
        if ignore_msize:
            tmp_reads &= ~Effects.MSIZE
        return tmp_reads

    @property
    def is_commutative(self) -> bool:
        return self.opcode in COMMUTATIVE_INSTRUCTIONS


def same(a: IROperand | _Expression, b: IROperand | _Expression) -> bool:
    if isinstance(a, IROperand) and isinstance(b, IROperand):
        return a.value == b.value
    if not isinstance(a, _Expression) or not isinstance(b, _Expression):
        return False

    if a is b:
        return True

    if a.opcode != b.opcode:
        return False

    # Early return special case for commutative instructions
    if a.is_commutative:
        if same(a.operands[0], b.operands[1]) and same(a.operands[1], b.operands[0]):
            return True

    # General case
    for self_op, other_op in zip(a.operands, b.operands):
        if type(self_op) is not type(other_op):
            return False
        if isinstance(self_op, IROperand) and self_op != other_op:
            return False
        if isinstance(self_op, _Expression) and self_op is not other_op:
            return False

    return True


class _AvailableExpression:
    """
    Class that holds available expression
    and provides API for handling them
    """

    exprs: dict[_Expression, list[IRInstruction]]

    def __init__(self):
        self.exprs = dict()

    def __eq__(self, other) -> bool:
        if not isinstance(other, _AvailableExpression):
            return False

        return self.exprs == other.exprs

    def __repr__(self) -> str:
        res = "available expr\n"
        for key, val in self.exprs.items():
            res += f"\t{key}: {val}\n"
        return res

    def add(self, expr: _Expression, src_inst: IRInstruction):
        if expr not in self.exprs:
            self.exprs[expr] = []
        self.exprs[expr].append(src_inst)

    def remove_effect(self, effect: Effects, ignore_msize):
        if effect == effects.EMPTY:
            return
        to_remove = set()
        for expr in self.exprs.keys():
            read_effs = expr.get_reads(ignore_msize)
            write_effs = expr.get_writes(ignore_msize)
            op_effect = read_effs | write_effs
            if op_effect & effect != effects.EMPTY:
                to_remove.add(expr)

        for expr in to_remove:
            del self.exprs[expr]

    def get_source(self, expr: _Expression) -> IRInstruction | None:
        """
        Get source instruction of expression if currently available
        """
        tmp = self.exprs.get(expr)
        if tmp is not None:
            # arbitrarily choose the first instruction
            return tmp[0]
        return None

    def copy(self) -> _AvailableExpression:
        res = _AvailableExpression()
        for k, v in self.exprs.items():
            res.exprs[k] = v.copy()
        return res

    @staticmethod
    def lattice_meet(lattices: list[_AvailableExpression]):
        if len(lattices) == 0:
            return _AvailableExpression()
        res = lattices[0].copy()
        for item in lattices[1:]:
            tmp = res
            res = _AvailableExpression()
            for expr, insts in item.exprs.items():
                if expr not in tmp.exprs:
                    continue
                new_insts = []
                for i in tmp.exprs[expr]:
                    if i in insts:
                        new_insts.append(i)
                if len(new_insts) == 0:
                    continue
                res.exprs[expr] = new_insts
        return res


class CSEAnalysis(IRAnalysis):
    inst_to_expr: dict[IRInstruction, _Expression]
    dfg: DFGAnalysis
    inst_to_available: dict[IRInstruction, _AvailableExpression]
    bb_ins: dict[IRBasicBlock, _AvailableExpression]
    bb_outs: dict[IRBasicBlock, _AvailableExpression]

    ignore_msize: bool

    def __init__(self, analyses_cache: IRAnalysesCache, function: IRFunction):
        super().__init__(analyses_cache, function)
        self.analyses_cache.request_analysis(CFGAnalysis)
        dfg = self.analyses_cache.request_analysis(DFGAnalysis)
        assert isinstance(dfg, DFGAnalysis)
        self.dfg = dfg

        self.inst_to_expr = dict()
        self.inst_to_available = dict()
        self.bb_ins = dict()
        self.bb_outs = dict()

        self.ignore_msize = not self._contains_msize()

    def analyze(self):
        worklist = deque()
        worklist.append(self.function.entry)
        while len(worklist) > 0:
            bb: IRBasicBlock = worklist.popleft()
            if self._handle_bb(bb):
                worklist.extend(bb.cfg_out)

    # msize effect should be only necessery
    # to be handled when there is a possibility
    # of msize read otherwise it should not make difference
    # for this analysis
    def _contains_msize(self) -> bool:
        for bb in self.function.get_basic_blocks():
            for inst in bb.instructions:
                if inst.opcode == "msize":
                    return True
        return False

    def _handle_bb(self, bb: IRBasicBlock) -> bool:
        available_exprs = _AvailableExpression.lattice_meet(
            [self.bb_outs.get(pred, _AvailableExpression()) for pred in bb.cfg_in]
        )

        if bb in self.bb_ins and self.bb_ins[bb] == available_exprs:
            return False

        self.bb_ins[bb] = available_exprs.copy()

        change = False
        for inst in bb.instructions:
            if inst.opcode in ("store", "phi") or inst.opcode in BB_TERMINATORS:
                continue

            if inst not in self.inst_to_available or available_exprs != self.inst_to_available[inst]:
                self.inst_to_available[inst] = available_exprs.copy()

            expr = self._mk_expr(inst, available_exprs)
            expr = self._get_instance(expr, available_exprs)

            self._update_expr(inst, expr)

            write_effects = expr.get_writes(self.ignore_msize)
            available_exprs.remove_effect(write_effects, self.ignore_msize)

            # nonidempotent instruction effect other instructions
            # but since it cannot be substituted it does not have
            # to be added to available exprs
            if inst.opcode in NONIDEMPOTENT_INSTRUCTIONS:
                continue

            expr_effects = expr.get_writes(self.ignore_msize) & expr.get_reads(self.ignore_msize)
            if expr_effects == effects.EMPTY:
                available_exprs.add(expr, inst)

        if bb not in self.bb_outs or available_exprs != self.bb_outs[bb]:
            self.bb_outs[bb] = available_exprs
            # change is only necessery when the output of the
            # basic block is changed (otherwise it wont affect rest)
            change |= True

        return change

    def _get_operand(
        self, op: IROperand, available_exprs: _AvailableExpression
    ) -> IROperand | _Expression:
        if not isinstance(op, IRVariable):
            return op
        inst = self.dfg.get_producing_instruction(op)
        assert inst is not None, op
        # the phi condition is here because it is only way to
        # create dataflow loop
        if inst.opcode == "phi":
            return op
        if inst.opcode == "store":
            return self._get_operand(inst.operands[0], available_exprs)
        if inst in self.inst_to_expr:
            e = self.inst_to_expr[inst]
            same_insts = available_exprs.exprs.get(e, [])
            if inst in same_insts:
                return self.inst_to_expr[same_insts[0]]
            return e
        assert inst.opcode in UNINTERESTING_OPCODES
        expr = self._mk_expr(inst, available_exprs)
        return self._get_instance(expr, available_exprs)

    def get_expression(
        self, inst: IRInstruction 
    ) -> tuple[_Expression, IRInstruction] | None:
        available_exprs = self.inst_to_available.get(inst, _AvailableExpression())

        assert available_exprs is not None  # help mypy
        expr = self.inst_to_expr.get(inst)
        if expr is None:
            return None
        src = available_exprs.get_source(expr)
        if src is None:
            return None
        return (expr, src)

    def get_from_same_bb(self, inst: IRInstruction, expr: _Expression) -> list[IRInstruction]:
        available_exprs = self.inst_to_available.get(inst, _AvailableExpression())
        res = available_exprs.exprs[expr]
        return [i for i in res if i != inst and i.parent == inst.parent]

    def _mk_expr(self, inst:IRInstruction, available_exprs: _AvailableExpression) -> _Expression:
        operands: list[IROperand | _Expression] = [
            self._get_operand(op, available_exprs) for op in inst.operands
        ]
        expr = _Expression(inst.opcode, operands)

        return expr

    def _get_instance(self, expr: _Expression, available_exprs: _AvailableExpression) -> _Expression:
        """
        Check if the expression is not all ready in available expressions
        is so then return that instance
        """
        src_inst = available_exprs.get_source(expr)
        if src_inst is not None:
            same_expr = self.inst_to_expr[src_inst]
            return same_expr

        return expr

    def _update_expr(self, inst: IRInstruction, expr: _Expression):
        self.inst_to_expr[inst] = expr
