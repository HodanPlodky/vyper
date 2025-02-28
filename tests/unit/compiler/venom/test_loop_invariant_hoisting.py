import pytest

from tests.venom_utils import parse_from_basic_block, assert_ctx_eq
from vyper.venom.analysis.analysis import IRAnalysesCache
from vyper.venom.analysis.loop_detection import NaturalLoopDetectionAnalysis
from vyper.venom.basicblock import IRBasicBlock, IRLabel, IRVariable
from vyper.venom.context import IRContext
from vyper.venom.function import IRFunction
from vyper.venom.passes.loop_invariant_hosting import LoopInvariantHoisting


def _create_loops(fn, depth, loop_id, body_fn=lambda _: (), top=True):
    bb = fn.get_basic_block()
    cond = IRBasicBlock(IRLabel(f"cond{loop_id}{depth}"), fn)
    body = IRBasicBlock(IRLabel(f"body{loop_id}{depth}"), fn)
    if top:
        exit_block = IRBasicBlock(IRLabel(f"exit_top{loop_id}{depth}"), fn)
    else:
        exit_block = IRBasicBlock(IRLabel(f"exit{loop_id}{depth}"), fn)
    fn.append_basic_block(cond)
    fn.append_basic_block(body)

    bb.append_instruction("jmp", cond.label)

    cond_var = IRVariable(f"cond_var{loop_id}{depth}")
    cond.append_instruction("iszero", 0, ret=cond_var)
    assert isinstance(cond_var, IRVariable)
    cond.append_instruction("jnz", cond_var, body.label, exit_block.label)
    body_fn(fn, loop_id, depth)
    if depth > 1:
        _create_loops(fn, depth - 1, loop_id, body_fn, top=False)
    bb = fn.get_basic_block()
    bb.append_instruction("jmp", cond.label)
    fn.append_basic_block(exit_block)


def _simple_body(fn, loop_id, depth):
    assert isinstance(fn, IRFunction)
    bb = fn.get_basic_block()
    add_var = IRVariable(f"add_var{loop_id}{depth}")
    bb.append_instruction("add", 1, 2, ret=add_var)


def _hoistable_body(fn, loop_id, depth):
    assert isinstance(fn, IRFunction)
    bb = fn.get_basic_block()
    store_var = IRVariable(f"store_var{loop_id}{depth}")
    add_var_a = IRVariable(f"add_var_a{loop_id}{depth}")
    bb.append_instruction("store", 1, ret=store_var)
    bb.append_instruction("add", 1, store_var, ret=add_var_a)
    add_var_b = IRVariable(f"add_var_b{loop_id}{depth}")
    bb.append_instruction("add", store_var, add_var_a, ret=add_var_b)


def _simple_body_code(loop_id, depth):
    return f"""
        %a{depth}{loop_id} = add 1, 2"""


def _create_loops_code(depth, loop_id, body=lambda _, _a: "", last: bool = False):
    if depth <= 0:
        return ""
    inner = _create_loops_code(depth - 1, loop_id, body, False)

    res = f"""
        jmp @cond{depth}{loop_id}
    cond{depth}{loop_id}:
        jnz %par, @exit{depth}{loop_id}, @body{depth}{loop_id}
    body{depth}{loop_id}:
        {body(loop_id, depth)}
    {inner}
        jmp @cond{depth}{loop_id}
    exit{depth}{loop_id}:
    """

    if last:
        res += """
        stop
        """

    return res


@pytest.mark.parametrize("depth", range(1, 4))
@pytest.mark.parametrize("count", range(1, 4))
def test_loop_detection_analysis(depth, count):
    loops = ""
    for i in range(count):
        loops += _create_loops_code(depth, i, _simple_body_code, last=(i == count - 1))

    code = f"""
    main:
        %par = param
    {loops}
    """

    print(code)

    ctx = parse_from_basic_block(code)
    assert len(ctx.functions) == 1

    fn = list(ctx.functions.values())[0]
    ac = IRAnalysesCache(fn)
    analysis = ac.request_analysis(NaturalLoopDetectionAnalysis)
    assert isinstance(analysis, NaturalLoopDetectionAnalysis)

    assert len(analysis.loops) == depth * count


@pytest.mark.parametrize("depth", range(1, 4))
@pytest.mark.parametrize("count", range(1, 4))
def test_loop_invariant_hoisting_simple(depth, count):
    pre_loops = ""
    for i in range(count):
        pre_loops += _create_loops_code(depth, i, _simple_body_code, last=(i == count - 1))

    post_loops = ""
    for i in range(count):
        hoisted = ""
        for d in range(depth):
            hoisted += _simple_body_code(i, depth - d)
        post_loops += hoisted
        post_loops += _create_loops_code(depth, i, last=(i == count - 1))


    pre = f"""
    main:
        %par = param
    {pre_loops}
    """

    post = f"""
    main:
        %par = param
    {post_loops}
    """
    
    ctx = parse_from_basic_block(pre)
    print(ctx)

    for fn in ctx.functions.values():
        ac = IRAnalysesCache(fn)
        LoopInvariantHoisting(ac, fn).run_pass()

    post_ctx = parse_from_basic_block(post)
    
    print(ctx)
    print(post_ctx)

    assert_ctx_eq(ctx, post_ctx)

@pytest.mark.parametrize("depth", range(1, 4))
@pytest.mark.parametrize("count", range(1, 4))
def test_loop_invariant_hoisting_dependant(depth, count):
    ctx = IRContext()
    fn = ctx.create_function("_global")

    for c in range(count):
        _create_loops(fn, depth, c, _hoistable_body)

    bb = fn.get_basic_block()
    bb.append_instruction("ret")

    ac = IRAnalysesCache(fn)
    LoopInvariantHoisting(ac, fn).run_pass()

    entry = fn.entry
    assignments = list(map(lambda x: x.value, entry.get_assignments()))
    for bb in filter(lambda bb: bb.label.name.startswith("exit_top"), fn.get_basic_blocks()):
        assignments.extend(map(lambda x: x.value, bb.get_assignments()))

    assert len(assignments) == depth * count * 4
    for loop_id in range(count):
        for d in range(1, depth + 1):
            assert f"%store_var{loop_id}{d}" in assignments, repr(fn)
            assert f"%add_var_a{loop_id}{d}" in assignments, repr(fn)
            assert f"%add_var_b{loop_id}{d}" in assignments, repr(fn)
            assert f"%cond_var{loop_id}{d}" in assignments, repr(fn)


def _unhoistable_body(fn, loop_id, depth):
    assert isinstance(fn, IRFunction)
    bb = fn.get_basic_block()
    add_var_a = IRVariable(f"add_var_a{loop_id}{depth}")
    bb.append_instruction("mload", 64, ret=add_var_a)
    add_var_b = IRVariable(f"add_var_b{loop_id}{depth}")
    bb.append_instruction("add", add_var_a, 2, ret=add_var_b)
    bb.append_instruction("mstore", 10, add_var_b)


@pytest.mark.parametrize("depth", range(1, 4))
@pytest.mark.parametrize("count", range(1, 4))
def test_loop_invariant_hoisting_unhoistable(depth, count):
    ctx = IRContext()
    fn = ctx.create_function("_global")

    for c in range(count):
        _create_loops(fn, depth, c, _unhoistable_body)

    bb = fn.get_basic_block()
    bb.append_instruction("ret")

    print(fn)

    ac = IRAnalysesCache(fn)
    LoopInvariantHoisting(ac, fn).run_pass()
    print(fn)

    entry = fn.entry
    assignments = list(map(lambda x: x.value, entry.get_assignments()))
    for bb in filter(lambda bb: bb.label.name.startswith("exit_top"), fn.get_basic_blocks()):
        assignments.extend(map(lambda x: x.value, bb.get_assignments()))

    assert len(assignments) == depth * count
    for loop_id in range(count):
        for d in range(1, depth + 1):
            assert f"%cond_var{loop_id}{d}" in assignments, repr(fn)
