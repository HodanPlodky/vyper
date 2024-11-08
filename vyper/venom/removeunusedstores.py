from vyper.venom.passes.base_pass import IRPass
from vyper.venom.analysis.liveness import LivenessAnalysis
from vyper.venom.analysis.usedmem import UsedMemAnalysis
from vyper.venom.analysis.interval_analysis import IntervalAnalysis, Interval
from vyper.venom.basicblock import IRInstruction

class RemoveUnusedStorePass(IRPass):
    interval_analysis: IntervalAnalysis
    uses_mem_analysis: UsedMemAnalysis

    def run_pass(self):
        self.interval_analysis = self.analyses_cache.request_analysis(IntervalAnalysis) # type: ignore
        self.uses_mem_analysis = self.analyses_cache.request_analysis(UsedMemAnalysis) # type: ignore

        for bb in self.function.get_basic_blocks():
            for inst in bb.instructions:
                self._handle_inst(inst)
        
        self.analyses_cache.invalidate_analysis(LivenessAnalysis)

    def _handle_inst(self, inst: IRInstruction):
        if inst.opcode == "mstore":
            dst = self.interval_analysis.get_val(inst, inst.operands[1])
            #mem = self.uses_mem_analysis.mem_used.get(inst, )

