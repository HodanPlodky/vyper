from vyper.venom.analysis import IRAnalysis
from vyper.venom.analysis.interval_analysis import IntervalAnalysis, Interval
from vyper.venom.analysis.cfg import CFGAnalysis
from vyper.venom.basicblock import IRInstruction, IRBasicBlock
from vyper.venom.effects import Effects



class UsedMemAnalysis(IRAnalysis):
    interval_analysis: IntervalAnalysis
    mem_used: dict[IRInstruction, Interval]
    mem_used_bb: dict[IRBasicBlock, Interval]

    def analyze(self):
        self.interval_analysis = self.analyses_cache.request_analysis(IntervalAnalysis) # type: ignore
        self.analyses_cache.request_analysis(CFGAnalysis)

        while True:
            change = False
            for bb in self.function.get_basic_blocks():
                change |= self._handle_bb(bb)

            if not change:
                break

    def join(self, a: Interval, b: Interval) -> Interval:
        return self.interval_analysis.lattice.join(a, b)
    
    def _handle_bb(self, bb: IRBasicBlock) -> bool:
        current = Interval.get_bot()

        for out_bb in bb.cfg_out:
            current = self.join(current, self.mem_used_bb[out_bb])

        for inst in reversed(bb.instructions):
            self.mem_used[inst] = current
            current = self._handle_inst(inst, current)
        
        if self.mem_used_bb.get(bb, Interval.get_bot()) != current:
            self.mem_used_bb[bb] = current
            return True
        return False


    def min_inter(self, start: Interval, end: Interval) -> Interval:
        if start.top > end.bot:
            return Interval.get_bot()
        return Interval(start.top, end.bot)


    def _handle_inst(self, inst: IRInstruction, current: Interval) -> Interval:
        if False:
            pass
        elif inst.opcode == "mstore":
            dst = inst.operands[1]
            inter = self.interval_analysis.get_val(inst, dst)
            assert not inter.is_bot(), "cannot be bot"
            to_inter = inter.add(32)
            return current.constrain_by(self.min_inter(inter, to_inter))
        elif inst.opcode == "mload":
            op = inst.operands[0]
            inter = self.interval_analysis.get_val(inst, op)
            assert not inter.is_bot(), "cannot be bot"
            return self.join(inter, current)
        elif Effects.MEMORY in inst.get_read_effects():
            return Interval.get_top()
        return Interval.get_bot()
            
