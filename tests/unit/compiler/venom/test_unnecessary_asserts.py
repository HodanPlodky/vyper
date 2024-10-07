import math

from vyper.venom.analysis.analysis import IRAnalysesCache
from vyper.venom.analysis.interval_analysis import IntervalAnalysis
from vyper.venom.basicblock import IRBasicBlock, IRLabel, IRVariable
from vyper.venom.context import IRContext
from vyper.venom.passes.unnecessary_asserts import RemoveUnnecessaryAssertsPass

def test_unnecessery_assert():
    ctx = IRContext()
    fn = ctx.create_function("test")

    bb = fn.get_basic_block()
    addr = bb.append_instruction("store", 10)
    val = bb.append_instruction("mload", addr)
    constrain = bb.append_instruction("store", 20)
    cond = bb.append_instruction("lt", val, constrain)
    bb.append_instruction("assert", cond)
    bb.append_instruction("stop")

    ac = IRAnalysesCache(fn)
    
    interval: IntervalAnalysis = ac.request_analysis(IntervalAnalysis)
    for inst in bb.instructions:
        print(interval.get_intervals(inst))

    print(fn)
    RemoveUnnecessaryAssertsPass(ac, fn).run_pass()
    print(fn)

    assert sum(1 for inst in bb.instructions if inst.opcode == "assert") == 1, "wrong number of assert"
