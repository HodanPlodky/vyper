import math
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from vyper.venom.analysis.analysis import IRAnalysis
from vyper.venom.analysis.cfg import CFGAnalysis
from vyper.venom.analysis.liveness import LivenessAnalysis
from vyper.venom.basicblock import IRBasicBlock, IRInstruction, IRLiteral, IROperand, IRVariable


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


class IntervalLattice:
    constants: list[int | float]  # ordered

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
        if left == right:
            return left
        res = Interval(
            left.bot if left.bot < right.bot else right.bot,
            left.top if left.top > right.top else right.top,
        )
        return self.widen(res)

    def eval(self, inst: IRInstruction, abs_ops: list[Interval]) -> Interval:
        if inst.opcode == "store":
            return abs_ops[0]
        elif inst.opcode == "add":
            return Interval(abs_ops[0].bot + abs_ops[1].bot, abs_ops[0].top + abs_ops[1].top)
        elif inst.opcode == "phi":
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
    intervals_outs: dict[IRBasicBlock, MapLattice]
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
            item = self.intervals_outs.get(in_bb, MapLattice.get_bot())
            actual_state.join_inplace(self.lattice, item)

        change = False

        for inst in bb.instructions:
            if isinstance(inst.output, IRVariable):
                n_val = self.lattice.eval(inst, self._get_abs_op(inst, actual_state))
                actual_state.update(inst.output, n_val)
                if inst not in self.intervals.keys() or actual_state != self.intervals[inst]:
                    change = True
                    self.intervals[inst] = actual_state.copy()

        tmp_data = dict()
        for var in bb.out_vars:
            tmp_data[var] = actual_state.get(var)
        tmp_actual = MapLattice(tmp_data)
        if bb not in self.intervals_outs.keys() or tmp_actual != self.intervals_outs[bb]:
            change = True
            self.intervals_outs[bb] = tmp_actual

        return change

    def get_intervals(self, inst: IRInstruction) -> MapLattice:
        return self.intervals.get(inst, MapLattice.get_bot())
