from vyper.venom.passes.base_pass import IRPass
from vyper.venom.analysis.interval_analysis import IntervalAnalysis
from vyper.venom.analysis.liveness import LivenessAnalysis
from vyper.venom.analysis.dfg import DFGAnalysis
from vyper.venom.basicblock import IRInstruction, IRVariable

class RemoveUnnecessaryAssertsPass(IRPass):
    interval_analysis: IntervalAnalysis
    dfg: DFGAnalysis

    def run_pass(self, *args, **kwargs):
        consts = [x for x in range(256, 8)]
        interval_analysis = self.analyses_cache.request_analysis(IntervalAnalysis, consts)
        assert isinstance(interval_analysis, IntervalAnalysis)
        self.interval_analysis = interval_analysis

        dfg = self.analyses_cache.request_analysis(DFGAnalysis)
        assert isinstance(dfg, DFGAnalysis)
        self.dfg = dfg

        for bb in self.function.get_basic_blocks():
            for inst in bb.instructions:
                if inst.opcode == "assert":
                    self._handle_assert(inst)
        
        self.analyses_cache.invalidate_analysis(LivenessAnalysis)
        self.analyses_cache.invalidate_analysis(IntervalAnalysis)
        self.analyses_cache.invalidate_analysis(DFGAnalysis)


    def _handle_assert(self, inst: IRInstruction):
        assert inst.opcode == "assert"
        assert isinstance(inst.operands[0], IRVariable)
        source = self.dfg.get_producing_instruction(inst.operands[0])
        assert isinstance(source, IRInstruction)
        state = self.interval_analysis.get_intervals(source)
        

        _, changed = self.interval_analysis._constrain(inst.operands[0], state)
        if not changed:
            inst.operands = []
            inst.opcode = "nop"
