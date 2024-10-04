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
    assert interval_analysis.intervals_outs[bb_loop][bb_loop].get(var_1) == Interval(11, math.inf)

    interval_analysis = ac.force_analysis(IntervalAnalysis, consts=[100])
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(var_1, IRVariable)
    assert interval_analysis.intervals_outs[bb_loop][bb_loop].get(var_1) == Interval(11, math.inf)


def test_interval_analysis_assert_constrain():
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

    constrain_var = bb_loop.append_instruction("store", 23)  # random number
    cond = bb_loop.append_instruction("lt", var_1, constrain_var)
    bb_loop.append_instruction("assert", cond)
    bb_loop.append_instruction("jmp", bb_loop.label)

    ac = IRAnalysesCache(fn)

    interval_analysis = ac.force_analysis(IntervalAnalysis)
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(var_1, IRVariable)
    assert interval_analysis.intervals_outs[bb_loop][bb_loop].get(var_1) == Interval(11, 22)

    interval_analysis = ac.force_analysis(IntervalAnalysis, consts=[100])
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(var_1, IRVariable)
    assert interval_analysis.intervals_outs[bb_loop][bb_loop].get(var_1) == Interval(11, 22)


def test_interval_analysis_custom_costants():
    ctx = IRContext()
    fn = ctx.create_function("test")

    bb = fn.get_basic_block()
    num = bb.append_instruction("store", 10)
    var_0 = bb.append_instruction("add", num, num)

    bb_loop = IRBasicBlock(IRLabel("bb_loop"), fn)
    fn.append_basic_block(bb_loop)
    bb.append_instruction("jmp", bb_loop.label)
    var_1 = IRVariable("var")
    var_2 = bb_loop.append_instruction("phi", bb.label, var_0, bb_loop.label, var_1)
    bb_loop.append_instruction("store", 1, ret=var_1)
    bb_loop.append_instruction("jmp", bb_loop.label)

    ac = IRAnalysesCache(fn)

    interval_analysis = ac.force_analysis(IntervalAnalysis)
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(var_2, IRVariable)
    assert interval_analysis.get_intervals(bb_loop.instructions[0]).get(var_2) == Interval(
        1, math.inf
    )

    interval_analysis = ac.force_analysis(IntervalAnalysis, consts=[100])
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(var_2, IRVariable)
    assert interval_analysis.get_intervals(bb_loop.instructions[0]).get(var_2) == Interval(1, 100)


def test_interval_analysis_constrain_jnz():
    ctx = IRContext()
    fn = ctx.create_function("test")

    bb = fn.get_basic_block()
    then_bb = IRBasicBlock(IRLabel("then"), fn)
    exit_bb = IRBasicBlock(IRLabel("exit"), fn)
    fn.append_basic_block(then_bb)
    fn.append_basic_block(exit_bb)

    # random value
    addr = bb.append_instruction("store", 10)
    var_0 = bb.append_instruction("mload", addr)

    num = bb.append_instruction("store", 1000)
    cond = bb.append_instruction("lt", var_0, num)
    bb.append_instruction("assert", cond)

    # constrain
    constrain_var = bb.append_instruction("store", 63)
    cond = bb.append_instruction("lt", var_0, constrain_var)
    bb.append_instruction("jnz", cond, then_bb.label, exit_bb.label)

    var_1 = then_bb.append_instruction("store", 10)
    then_bb.append_instruction("jmp", exit_bb.label)

    res = exit_bb.append_instruction("phi", then_bb.label, var_1, bb.label, var_0)
    exit_bb.append_instruction("stop")

    ac = IRAnalysesCache(fn)

    interval_analysis = ac.force_analysis(IntervalAnalysis)
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(res, IRVariable)
    assert interval_analysis.get_intervals(exit_bb.instructions[0]).get(res) == Interval(10, 1000)

def test_interval_analysis_constrain_sameval():
    ctx = IRContext()
    fn = ctx.create_function("test")

    bb = fn.get_basic_block()
    then_bb = IRBasicBlock(IRLabel("then"), fn)
    exit_bb = IRBasicBlock(IRLabel("exit"), fn)
    fn.append_basic_block(then_bb)
    fn.append_basic_block(exit_bb)

    num = bb.append_instruction("store", 10)
    var_0 = bb.append_instruction("add", num, num)

    constrain_var = bb.append_instruction("store", 63)
    cond = bb.append_instruction("lt", var_0, constrain_var)
    bb.append_instruction("jnz", cond, then_bb.label, exit_bb.label)

    num_a = then_bb.append_instruction("store", 15)
    num_b = then_bb.append_instruction("store", 5)
    var_1 = then_bb.append_instruction("add", num_a, num_b)
    then_bb.append_instruction("jmp", exit_bb.label)

    res = exit_bb.append_instruction("phi", then_bb.label, var_1, bb.label, var_0)
    exit_bb.append_instruction("stop")

    ac = IRAnalysesCache(fn)

    interval_analysis = ac.force_analysis(IntervalAnalysis)
    assert isinstance(interval_analysis, IntervalAnalysis)

    assert isinstance(res, IRVariable)
    assert interval_analysis.get_intervals(exit_bb.instructions[0]).get(res) == Interval(20, 20)
