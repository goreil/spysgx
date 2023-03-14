import pathlib
import angr
import claripy
import guardian

PATH = pathlib.Path(__file__).parent / "enclave.so"
SECRET = claripy.BVV(1, 64)


inst_traces = {}
traces = {}
for secret in [0, 1]:
    proj = angr.Project(PATH)
    proj.hook_symbol('sgx_is_outside_enclave', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    guard = guardian.Project(proj, find_missing_ecalls_or_ocalls=True, violation_check=False)
    guard.set_target_ecall(0)

    ecall_addr = 0x403000
    simgr = guard.simgr
    simgr.explore(find = ecall_addr)
    assert simgr.found
    # Delete non active states
    simgr.move('active', 'discarded')
    simgr.move('found', 'active')

    # Start tracing
    state = simgr.active[0]
    state.regs.rdi = secret

    def mem_trace(state):
        addr = state.inspect.mem_read_address
        print("State", state, "ReadAddr:", addr)
        state.globals['memtrace'].append(addr)
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_trace)
    state.globals['memtrace'] = []

    callstack = len(state.callstack)
    while (len(simgr.active[0].callstack) >= callstack):
        simgr.step()
    inst_traces[secret] = list(state.history.bbl_addrs)
    traces[secret] = state.globals['memtrace']

