from vyper.utils import OrderedSet
from vyper.venom.analysis.cfg import CFGAnalysis
from vyper.venom.analysis.dfg import DFGAnalysis
from vyper.venom.analysis.liveness import LivenessAnalysis
from vyper.venom.analysis.loop_detection import NaturalLoopDetectionAnalysis
from vyper.venom.basicblock import IRBasicBlock, IRInstruction, IRLabel, IRVariable, IRLiteral
from vyper.venom.function import IRFunction
from vyper.venom.passes.base_pass import IRPass


def _ignore_instruction(inst: IRInstruction) -> bool:
    return (
        inst.is_volatile
        or inst.is_bb_terminator
        or inst.opcode == "returndatasize"
        or inst.opcode == "phi"
        or (inst.opcode == "add" and isinstance(inst.operands[1], IRLabel))
        or inst.opcode == "store"
    )


# must check if it has as operand as literal because
# there are cases when the store just moves value
# from one variable to another
def _is_correct_store(inst: IRInstruction) -> bool:
    return inst.opcode == "store" and isinstance(inst.operands[0], IRLiteral)


class LoopInvariantHoisting(IRPass):
    """
    This pass detects invariants in loops and hoists them above the loop body.
    Any VOLATILE_INSTRUCTIONS, BB_TERMINATORS CFG_ALTERING_INSTRUCTIONS are ignored
    """

    function: IRFunction
    loops: dict[IRBasicBlock, OrderedSet[IRBasicBlock]]
    dfg: DFGAnalysis

    def run_pass(self):
        self.analyses_cache.request_analysis(CFGAnalysis)
        self.dfg = self.analyses_cache.request_analysis(DFGAnalysis)
        loops = self.analyses_cache.request_analysis(NaturalLoopDetectionAnalysis)
        self.loops = loops.loops
        invalidate = False
        while True:
            change = False
            for from_bb, loop in self.loops.items():
                hoistable: list[IRInstruction] = self._get_hoistable_loop(from_bb, loop)
                if len(hoistable) == 0:
                    continue
                change |= True
                self._hoist(from_bb, hoistable)
            if not change:
                break
            invalidate = True

        # only need to invalidate if you did some hoisting
        if invalidate:
            self.analyses_cache.invalidate_analysis(LivenessAnalysis)
            self.analyses_cache.invalidate_analysis(DFGAnalysis)

    def _hoist(self, target_bb: IRBasicBlock, hoistable: list[IRInstruction]):
        self._remove_duplicates(target_bb, hoistable)
        for inst in hoistable:
            bb = inst.parent
            bb.remove_instruction(inst)
            target_bb.insert_instruction(inst, index=len(target_bb.instructions) - 1)

    def _remove_duplicates(self, target_bb : IRBasicBlock, insts : list[IRInstruction]):
        def same(a_inst : IRInstruction, b_inst : IRInstruction) -> bool:
            if (
                a_inst.opcode == b_inst.opcode 
                and a_inst.opcode in ["add", "mul"]
                and a_inst.operands[1] == b_inst.operands[1]
                and isinstance(a_inst.operands[0], IRVariable)
                and isinstance(b_inst.operands[0], IRVariable)
                and self.dfg.get_producing_instruction(a_inst.operands[0]).opcode == "store"
                and self.dfg.get_producing_instruction(b_inst.operands[0]).opcode == "store"
            ):
                #print("yo")
                return (
                    self.dfg.get_producing_instruction(a_inst.operands[0]).operands[0]
                    == self.dfg.get_producing_instruction(b_inst.operands[0]).operands[0]
                )
            elif (
                a_inst.opcode == b_inst.opcode 
                and a_inst.opcode in ["add", "mul"]
                and a_inst.operands[0] == b_inst.operands[0]
                and isinstance(a_inst.operands[1], IRVariable)
                and isinstance(b_inst.operands[1], IRVariable)
                and self.dfg.get_producing_instruction(a_inst.operands[1]).opcode == "store"
                and self.dfg.get_producing_instruction(b_inst.operands[1]).opcode == "store"
            ):
                #print("yo")
                return (
                    self.dfg.get_producing_instruction(a_inst.operands[1]).operands[0]
                    == self.dfg.get_producing_instruction(b_inst.operands[1]).operands[0]
                )
            else:
                return False

        i = 0
        #print("from:", insts)
        while i < len(insts) - 1:
            #print("inst", insts[i], insts[i].operands[0], "insts", insts[(i+1):], sep="\n")
            same_insts = filter(lambda x: same(insts[i], x), insts[(i + 1):])
            #print(list(same_insts))
            for inst in same_insts:
                insts.remove(inst)
                #inst.output.value = insts[i].output.value
                #inst.output = insts[i].output
                for bb in self.loops[target_bb]:
                    assert isinstance(bb, IRBasicBlock), "huh"
                    try:
                        bb.remove_instruction(inst)
                    except:
                        pass
                    for other_inst in bb.instructions:
                        for idx, op in enumerate(other_inst.operands):
                            #print("jaja", op, inst)
                            if op.value == inst.output.value:
                                op.value == insts[i].output.value
                                other_inst.operands[idx] = insts[i].output
            i += 1
        #print("to:", insts)

    def _get_hoistable_loop(
        self, from_bb: IRBasicBlock, loop: OrderedSet[IRBasicBlock]
    ) -> list[IRInstruction]:
        result: list[IRInstruction] = []
        for bb in loop:
            result.extend(self._get_hoistable_bb(bb, from_bb))
        return result

    def _get_hoistable_bb(self, bb: IRBasicBlock, loop_idx: IRBasicBlock) -> list[IRInstruction]:
        result: list[IRInstruction] = []
        for inst in bb.instructions:
            if self._can_hoist_instruction_ignore_stores(inst, self.loops[loop_idx]):
                result.extend(self._store_dependencies(inst, loop_idx))
                result.append(inst)

        return result

    # query store dependacies of instruction (they are not handled otherwise)
    def _store_dependencies(
        self, inst: IRInstruction, loop_idx: IRBasicBlock
    ) -> list[IRInstruction]:
        result: list[IRInstruction] = []
        for var in inst.get_input_variables():
            source_inst = self.dfg.get_producing_instruction(var)
            assert isinstance(source_inst, IRInstruction), "source"
            if not _is_correct_store(source_inst):
                continue
            for bb in self.loops[loop_idx]:
                if source_inst.parent == bb:
                    result.append(source_inst)
        return result

    # since the stores are always hoistable this ignores
    # stores in analysis (their are hoisted if some instrution is dependent on them)
    def _can_hoist_instruction_ignore_stores(
        self, inst: IRInstruction, loop: OrderedSet[IRBasicBlock]
    ) -> bool:
        if _ignore_instruction(inst):
            return False
        for bb in loop:
            if self._dependent_in_bb(inst, bb):
                return False
        return True

    def _dependent_in_bb(self, inst: IRInstruction, bb: IRBasicBlock):
        for in_var in inst.get_input_variables():
            assert isinstance(in_var, IRVariable), "dep1"
            source_ins = self.dfg.get_producing_instruction(in_var)
            assert isinstance(source_ins, IRInstruction), f"dep2, {in_var}, {source_ins}"

            # ignores stores since all stores are independant
            # and can be always hoisted
            if _is_correct_store(source_ins):
                continue

            if source_ins.parent == bb:
                return True
        return False
