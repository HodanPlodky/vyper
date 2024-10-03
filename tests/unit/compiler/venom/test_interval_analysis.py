from vyper.venom.context import IRContext
from vyper.venom.passes.make_ssa import MakeSSA
from vyper.venom.analysis.analysis import IRAnalysesCache
from vyper.venom.analysis.interval_analysis import IntervalAnalysis
from vyper.venom.basicblock import IRBasicBlock, IRLabel, IRLiteral

def test_interval_analysis():
    ctx = IRContext()
    fn = ctx.create_function("test")

    bb = fn.get_basic_block()
    var_0 = bb.append_instruction("store", 10)

    bb_loop = IRBasicBlock(IRLabel("bb_loop"), fn)
    fn.append_basic_block(bb_loop)
    bb.append_instruction("jmp", bb_loop.label)
    
    bb_loop.append_instruction("phi", bb.label, var_0, bb_)
    num = bb_loop.append_instruction("store", 1)
    var_1 = bb_loop.append_instruction("add", num, var_0)
    bb_loop.append_instruction("jmp", bb.label)

    ac = IRAnalysesCache(fn)
    print(fn)

    interval_analysis = ac.request_analysis(IntervalAnalysis)
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert False
