import angr
import random 
random.seed(0)
proj = angr.Project('./main', auto_load_libs=False)
# Create a random 64byte secret string
secret = bytes([random.randint(0, 255) for _ in range(64)])
state = proj.factory.entry_state(args=['./main', secret], add_options={
    "ZERO_FILL_UNCONSTRAINED_MEMORY",
    "ZERO_FILL_UNCONSTRAINED_REGISTERS"
}) 
state.options.remove(angr.options.LAZY_SOLVES)
# Breakpoint for every memory access
accesses = []
simgr = proj.factory.simulation_manager(state)

# Explore until we reach the access function
simgr.active[0].inspect.b('mem_read', when=angr.BP_BEFORE, action=lambda s: accesses.append(s.solver.eval(s.inspect.mem_read_address)))
simgr.run()

with open("accesses.txt", "w") as f:
    f.write("\n".join(map(str,accesses)))