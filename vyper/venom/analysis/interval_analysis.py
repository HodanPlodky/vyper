import math
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from vyper.venom.analysis.analysis import IRAnalysis
from vyper.venom.analysis.cfg import CFGAnalysis
from vyper.venom.analysis.dfg import DFGAnalysis
from vyper.venom.analysis.liveness import LivenessAnalysis
from vyper.venom.basicblock import (
    IRBasicBlock,
    IRInstruction,
    IRLabel,
    IRLiteral,
    IROperand,
    IRVariable,
)


@dataclass
class Interval:
    bot: int | float
    top: int | float

    @staticmethod
    def get_top() -> "Interval":
        return Interval(-math.inf, math.inf)

    @staticmethod
    def get_bot() -> "Interval":
        return Interval(math.inf, -math.inf)

    @staticmethod
    def from_val(val: int) -> "Interval":
        return Interval(val, val)

    def __repr__(self) -> str:
        return f"[{self.bot}, {self.top}]"

    def is_bot(self) -> bool:
        return self.top == -math.inf and self.bot == math.inf

    def is_const(self) -> bool:
        return self.bot == self.top and not math.isinf(self.bot)

    def enclose(self, other: "Interval") -> bool:
        return self.bot < other.bot < self.top and self.bot < other.top < self.top

    def expand_to_inf(self) -> "Interval":
        return Interval(self.bot, math.inf)

    def expand_to_neginf(self) -> "Interval":
        return Interval(-math.inf, self.top)

    def must_be_lt(self, other: "Interval") -> "Interval":
        other = other.sub(1).expand_to_inf()
        return self.constrain_by(other)

    def must_be_gt(self, other: "Interval") -> "Interval":
        other = other.add(1).expand_to_neginf()
        return self.constrain_by(other)

    # TODO check if this does not create of by one errors
    def constrain_by(self, other: "Interval") -> "Interval":
        bot = self.bot
        top = self.top
        if self.enclose(other):
            # could return more intervals but for just now
            # ignore it
            return self
        if bot < other.top < top:
            bot = other.top
        elif bot < other.bot < top:
            top = other.bot
        return Interval(bot, top)

    def add(self, other: "Interval | int") -> "Interval":
        if isinstance(other, int):
            return Interval(self.bot + other, self.top + other)
        if isinstance(other, Interval):
            return Interval(self.bot + other.bot, self.top + other.top)

    def sub(self, other: int) -> "Interval":
        return Interval(self.bot - other, self.top - other)

class IntervalLattice:
    constants: list[int | float]  # must be ordered

    def __init__(self, constants: list[int | float]):
        self.constants = constants
        self.constants.insert(0, -math.inf)
        self.constants.append(math.inf)

    def widen(self, interval: Interval) -> Interval:
        pos_bot = bisect_right(self.constants, interval.bot)
        pos_top = bisect_left(self.constants, interval.top)

        bot = (
            interval.bot if interval.bot == self.constants[pos_bot] else self.constants[pos_bot - 1]
        )
        top = interval.top if interval.top == self.constants[pos_top] else self.constants[pos_top]

        return Interval(bot, top)

    def join(self, left: Interval, right: Interval) -> Interval:
        if left.is_bot():
            return right
        if right.is_bot():
            return left
        if left == right:
            return left
        res = Interval(
            left.bot if left.bot < right.bot else right.bot,
            left.top if left.top > right.top else right.top,
        )
        return self.widen(res)

    def eval(self, inst: IRInstruction, abs_ops: list[Interval]) -> Interval:
        opcode = inst.opcode
        if opcode == "store":
            return abs_ops[0]
        elif opcode == "add":
            return Interval(abs_ops[0].bot + abs_ops[1].bot, abs_ops[0].top + abs_ops[1].top)
        elif opcode == "phi":
            res: Interval = Interval.get_bot()
            for op in abs_ops:
                res = self.join(res, op)
            return res
        else:
            return Interval.get_top()


class MapLattice:
    data: dict[IRVariable, Interval]

    def __init__(self, data: dict[IRVariable, Interval]) -> None:
        self.data = data

    def copy(self):
        return MapLattice(self.data.copy())

    @staticmethod
    def join(lattice: IntervalLattice, left: "MapLattice", right: "MapLattice") -> "MapLattice":
        res = left.copy()
        res.join_inplace(lattice, right)
        return res

    def join_inplace(self, lattice: IntervalLattice, right: "MapLattice"):
        for f, right_val in right.data.items():
            left_val = self.data.get(f, Interval.get_bot())
            self.data[f] = lattice.join(right_val, left_val)

    def update(self, var: IRVariable, val: Interval) -> bool:
        if var in self.data.keys() and self.data[var] == val:
            return False
        self.data[var] = val
        return True

    def get(self, var: IRVariable) -> Interval:
        return self.data.get(var, Interval.get_bot())

    def __eq__(self, value: object, /) -> bool:
        if not isinstance(value, MapLattice):
            return False

        return self.data == value.data

    @staticmethod
    def get_bot() -> "MapLattice":
        return MapLattice(dict())

    def __repr__(self) -> str:
        return repr(self.data)


class IntervalAnalysis(IRAnalysis):
    intervals: dict[IRInstruction, MapLattice]
    intervals_outs: dict[IRBasicBlock, dict[IRBasicBlock, MapLattice]]
    lattice: IntervalLattice

    def analyze(self, consts: list[int | float] | None = None):
        if consts is None:
            consts = list()
        self.analyses_cache.request_analysis(LivenessAnalysis)
        self.analyses_cache.request_analysis(CFGAnalysis)
        self.lattice = IntervalLattice(self._get_constants(consts))
        self.intervals = dict()
        self.intervals_outs = dict()

        while True:
            change = False
            for bb in self.function.get_basic_blocks():
                change |= self._handle_bb(bb)

            if not change:
                break

    def _get_constants(self, consts: list[int | float]) -> list[int | float]:
        res: list[int | float] = consts
        for bb in self.function.get_basic_blocks():
            for inst in bb.instructions:
                if inst.opcode == "store" and inst.operands[0].value not in res:
                    res.append(inst.operands[0].value)

        res.sort()
        return res

    def _operand_to_abs(self, op: IROperand, actual_state: MapLattice) -> Interval:
        if isinstance(op, IRVariable):
            return actual_state.get(op)  # should be always in the dict (otherwise it is my fault)
        elif isinstance(op, IRLiteral):
            return Interval.from_val(op.value)
        else:
            return Interval.get_top()

    def _get_abs_op(self, inst: IRInstruction, actual_state: MapLattice) -> list[Interval]:
        if inst.opcode == "phi":
            return [self._operand_to_abs(op, actual_state) for (_, op) in inst.phi_operands]
        else:
            return [self._operand_to_abs(op, actual_state) for op in inst.operands]

    def _handle_bb(self, bb: IRBasicBlock) -> bool:
        actual_state = MapLattice.get_bot()
        for in_bb in bb.cfg_in:
            item = self.intervals_outs.get(in_bb, dict()).get(bb, MapLattice.get_bot())
            actual_state.join_inplace(self.lattice, item)

        change = False

        for inst in bb.instructions:
            if isinstance(inst.output, IRVariable):
                n_val = self.lattice.eval(inst, self._get_abs_op(inst, actual_state))
                actual_state.update(inst.output, n_val)
                if inst not in self.intervals.keys() or actual_state != self.intervals[inst]:
                    change = True
                    self.intervals[inst] = actual_state.copy()
            elif inst.opcode == "assert":
                assert isinstance(inst.operands[0], IRVariable)
                self._constrain(inst.operands[0], actual_state)

        if bb not in self.intervals_outs.keys():
            change = True
            self.intervals_outs[bb] = dict()
        if bb.instructions[-1].opcode == "jnz":
            inst = bb.instructions[-1]
            non_zero_label = inst.operands[1]
            zero_label = inst.operands[2]
            non_zero_state = actual_state.copy()
            var = inst.operands[0]
            assert isinstance(var, IRVariable)
            self._constrain(var, non_zero_state)
            self._constrain(var, actual_state, pred=False)
            non_zero_state = self.simplify_state(bb, non_zero_state)
            zero_state = self.simplify_state(bb, actual_state)

            assert isinstance(non_zero_label, IRLabel)
            assert isinstance(zero_label, IRLabel)
            non_zero_bb = self.function.get_basic_block(non_zero_label.value)
            zero_bb = self.function.get_basic_block(zero_label.value)
            if (
                zero_bb not in self.intervals_outs[bb].keys()
                or self.intervals_outs[bb][zero_bb] != zero_state
            ):
                change = True
                self.intervals_outs[bb][zero_bb] = zero_state
            if (
                non_zero_bb not in self.intervals_outs[bb].keys()
                or self.intervals_outs[bb][non_zero_bb] != non_zero_state
            ):
                change = True
                self.intervals_outs[bb][non_zero_bb] = non_zero_state

        else:
            tmp_actual = self.simplify_state(bb, actual_state)
            for out_bb in bb.cfg_out:
                if (
                    out_bb not in self.intervals_outs[bb].keys()
                    or self.intervals_outs[bb][out_bb] != tmp_actual
                ):
                    change = True
                    self.intervals_outs[bb][out_bb] = tmp_actual

        return change

    def simplify_state(self, bb: IRBasicBlock, actual_state: MapLattice) -> MapLattice:
        tmp_data = dict()
        for var in bb.out_vars:
            tmp_data[var] = actual_state.get(var)
        tmp_actual = MapLattice(tmp_data)
        return tmp_actual

    def get_intervals(self, inst: IRInstruction) -> MapLattice:
        return self.intervals.get(inst, MapLattice.get_bot())

    def _constrain(
        self, var: IRVariable, actual_state: MapLattice, pred: bool = True
    ) -> MapLattice:
        dfg = self.analyses_cache.request_analysis(DFGAnalysis)
        assert isinstance(dfg, DFGAnalysis)
        inst = dfg.get_producing_instruction(var)
        assert isinstance(inst, IRInstruction)
        opcode = inst.opcode

        if opcode == "iszero":
            assert isinstance(inst.operands[0], IRVariable)
            return self._constrain(inst.operands[0], actual_state, not pred)
        elif opcode == "lt":
            abs_ops = self._get_abs_op(inst, actual_state)
            assert len(abs_ops) == 2
            if not abs_ops[0].is_const() and not abs_ops[1].is_const():
                return actual_state
            if pred:
                if abs_ops[1].is_const():
                    abs_ops[0] = abs_ops[0].must_be_lt(abs_ops[1])
                elif abs_ops[0].is_const():
                    abs_ops[1] = abs_ops[1].must_be_gt(abs_ops[0])
            else:
                if abs_ops[1].is_const():
                    abs_ops[0] = abs_ops[0].must_be_gt(abs_ops[1].add(1))
                elif abs_ops[0].is_const():
                    abs_ops[1] = abs_ops[1].must_be_lt(abs_ops[0].sub(1))
            assert isinstance(inst.operands[0], IRVariable)
            assert isinstance(inst.operands[1], IRVariable)
            actual_state.update(inst.operands[0], abs_ops[0])
            actual_state.update(inst.operands[1], abs_ops[1])
        elif opcode == "gt":
            pass
        return actual_state
