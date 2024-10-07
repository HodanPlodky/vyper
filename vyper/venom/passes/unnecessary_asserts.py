from vyper.venom.passes.base_pass import IRPass
from vyper.venom.analysis.interval_analysis import IntervalAnalysis
from vyper.venom.basicblock import IRInstruction, IRVariable

class RemoveUnnecessaryAssertsPass(IRPass):
    interval_analysis: IntervalAnalysis

    def run_pass(self, *args, **kwargs):
        interval_analysis = self.analyses_cache.request_analysis(IntervalAnalysis)
        assert isinstance(interval_analysis, IntervalAnalysis)
        self.interval_analysis = interval_analysis
        print("end of analysis")

    def _handle_assert(self, inst: IRInstruction):
        assert inst.opcode == "assert"
        assert isinstance(inst.operands[0], IRVariable)
        state = self.interval_analysis.get_intervals(inst)
        _, changed = self.interval_analysis._constrain(inst.operands[0], state)
        if not changed:
            inst.operands = []
            inst.opcode = "nop"
