import math

from vyper.venom.analysis.analysis import IRAnalysesCache
from vyper.venom.analysis.interval_analysis import Interval, IntervalAnalysis
from vyper.venom.basicblock import IRBasicBlock, IRLabel, IRVariable
from vyper.venom.context import IRContext


def test_interval_analysis():
    ctx = IRContext()
    fn = ctx.create_function("test")

    bb = fn.get_basic_block()
    var_0 = bb.append_instruction("store", 10)

    bb_loop = IRBasicBlock(IRLabel("bb_loop"), fn)
    fn.append_basic_block(bb_loop)
    bb.append_instruction("jmp", bb_loop.label)
    var_1 = IRVariable("var")
    var_2 = bb_loop.append_instruction("phi", bb.label, var_0, bb_loop.label, var_1)
    num = bb_loop.append_instruction("store", 1)
    bb_loop.append_instruction("add", num, var_2, ret=var_1)
    bb_loop.append_instruction("jmp", bb_loop.label)

    ac = IRAnalysesCache(fn)

    interval_analysis = ac.force_analysis(IntervalAnalysis)
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(var_1, IRVariable)
    assert interval_analysis.intervals_outs[bb_loop].get(var_1) == Interval(11, math.inf)

    interval_analysis = ac.force_analysis(IntervalAnalysis, consts = [100])
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(var_1, IRVariable)
    assert interval_analysis.intervals_outs[bb_loop].get(var_1) == Interval(10, math.inf)
