from tests.venom_utils import assert_ctx_eq, parse_venom, parse_from_basic_block
from vyper.venom.analysis import IRAnalysesCache
from vyper.venom.passes import MakeSSA, Mem2Var, RemoveUnusedVariablesPass


def _check_pre_post(pre, post):
    ctx = parse_venom(pre)
    for fn in ctx.functions.values():
        ac = IRAnalysesCache(fn)
        MakeSSA(ac, fn).run_pass()
    assert_ctx_eq(ctx, parse_venom(post))


def test_phi_case():
    pre = """
    function loop {
    main:
        %v = mload 64
        jmp @test
    test:
        jnz %v, @then, @else
    then:
        %t = mload 96
        assert %t
        jmp @if_exit
    else:
        jmp @if_exit
    if_exit:
        %v = add %v, 1
        jmp @test
    }
    """
    post = """
    function loop {
    main:
        %v = mload 64
        jmp @test
    test:
        %v:1 = phi @main, %v, @if_exit, %v:2
        jnz %v:1, @then, @else
    then:
        %t = mload 96
        assert %t
        jmp @if_exit
    else:
        jmp @if_exit
    if_exit:
        %v:2 = add %v:1, 1
        jmp @test
    }
    """
    _check_pre_post(pre, post)

def test_multiple_make_ssa_error():
    pre = """
    main:
        %v = mload 64
        jmp @test
    test:
        jnz %v, @then, @else
    then:
        %t = mload 96
        assert %t
        jmp @if_exit
    else:
        jmp @if_exit
    if_exit:
        %v = add %v, 1
        jmp @test
    """

    post = """
    main:
        %v = mload 64
        jmp @test
    test:
        %v:1:1 = phi @main, %v, @if_exit, %v:2
        jnz %v:1:1, @then, @else
    then:
        %t = mload 96
        assert %t
        jmp @if_exit
    else:
        jmp @if_exit
    if_exit:
        %v:2 = add %v:1:1, 1
        jmp @test
    """

    ctx = parse_from_basic_block(pre)
    for fn in ctx.functions.values():
        ac = IRAnalysesCache(fn)
        MakeSSA(ac, fn).run_pass()
        #Mem2Var(ac, fn).run_pass()
        MakeSSA(ac, fn).run_pass()
        #RemoveUnusedVariablesPass(ac, fn).run_pass()

    print(ctx)

    assert_ctx_eq(ctx, parse_from_basic_block(post));
