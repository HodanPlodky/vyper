import math
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from vyper.venom.analysis.analysis import IRAnalysis
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
        top = (
            interval.top if interval.top == self.constants[pos_top] else self.constants[pos_top - 1]
        )

        return Interval(bot, top)

    def join(self, left: Interval, right: Interval) -> Interval:
        if left == right:
            return left
        res = Interval(
            left.bot if left.bot < right.bot else right.bot,
            left.top if left.top < right.top else right.top,
        )
        return self.widen(res)

    def eval(self, inst: IRInstruction, abs_ops: list[Interval]) -> Interval:
        if inst.opcode == "store":
            return abs_ops[0]
        elif inst.opcode == "add":
            return Interval(abs_ops[0].bot + abs_ops[1].bot, abs_ops[0].top + abs_ops[1].top)
        elif inst.opcode == "phi":
            pass
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
        return self.data[var]

    def __eq__(self, value: object, /) -> bool:
        if not isinstance(value, MapLattice):
            return False

        return self.data == value.data

    @staticmethod
    def get_bot() -> "MapLattice":
        return MapLattice(dict())


class IntervalAnalysis(IRAnalysis):
    intervals: dict[IRInstruction, MapLattice]
    intervals_outs: dict[IRBasicBlock, MapLattice]
    lattice: IntervalLattice

    def analyze(self):
        self.analyses_cache.request_analysis(LivenessAnalysis)
        self.lattice = IntervalLattice(self._get_constants())
        self.intervals = dict()
        self.intervals_outs = dict()

        while True:
            change = False
            for bb in self.function.get_basic_blocks():
                change |= self._handle_bb(bb)

            if not change:
                break

    def _get_constants(self) -> list[int | float]:
        res: list[int | float] = list()
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

    def _handle_bb(self, bb: IRBasicBlock) -> bool:
        actual_state = MapLattice.get_bot()
        for in_bb in bb.cfg_in:
            item = self.intervals_outs.get(in_bb, MapLattice.get_bot())
            actual_state.join_inplace(self.lattice, item)

        change = False

        for inst in bb.instructions:
            if isinstance(inst.output, IRVariable):
                n_val = self.lattice.eval(
                    inst, [self._operand_to_abs(op, actual_state) for op in inst.operands]
                )
                actual_state.update(inst.output, n_val)
                if inst not in self.intervals.keys() or actual_state != self.intervals[inst]:
                    change = True
                    self.intervals[inst] = actual_state.copy()

        if bb not in self.intervals_outs.keys() or actual_state != self.intervals_outs[bb]:
            change = True
            self.intervals_outs[bb] = actual_state

        return change
