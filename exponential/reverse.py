import angr, claripy
import os, psutil   
proj = angr.Project('./main', auto_load_libs=False)
secret = claripy.BVS('secret', 64 * 8)
state = proj.factory.entry_state(args=['./main', secret], add_options={
    "ZERO_FILL_UNCONSTRAINED_MEMORY",
    "ZERO_FILL_UNCONSTRAINED_REGISTERS",
}) 
state.options.remove(angr.options.LAZY_SOLVES)
# Breakpoint for every memory access
accesses = []
simgr = proj.factory.simulation_manager(state)

# Make rdi point to symbolic memory
# Add a breakpoint for every memory access
with open("accesses.txt", "r") as f:
    trace = [int(x) for x in f.read().splitlines()]

memory_usage = []  
step = 0    
def add_constraint(state):
    """Add constraint at mem_read breakpoint."""
    state.add_constraints(state.inspect.mem_read_address == trace.pop(0))
    # Add current memory usage to list
    global step
    step += 1
    print(step)
    memory_usage.append(psutil.Process(os.getpid()).memory_info().rss)

simgr.active[0].inspect.b('mem_read', when=angr.BP_BEFORE, action=add_constraint)
simgr.run()
if (simgr.errored):
    simgr.errored[0].state.solver.eval(secret, cast_to=bytes)
else:
    simgr.deadended[0].solver.eval(secret, cast_to=bytes)