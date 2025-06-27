import claripy
import angr

proj = angr.Project("./prodkey")

chars = [claripy.BVS('c%d' % i, 8) for i in range(30)] # 30 bytes
input_str = claripy.Concat(*chars + [claripy.BVV(b'\n')]) # + \n
initial_state = proj.factory.entry_state(stdin=input_str) # use as stdin

for c in chars: # make sure all chars are printable
    initial_state.solver.add(c >= 0x20, c <= 0x7e)

simgr = proj.factory.simulation_manager(initial_state)
simgr.explore(find=0x400E5D)

if simgr.found:
    print(simgr.found[0].posix.dumps(0)) # dump content of stdin