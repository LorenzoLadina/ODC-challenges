import claripy
import angr

proj = angr.Project("./cracksymb")
options = {angr.options.LAZY_SOLVES} # make it faster
chars = [claripy.BVS('c%d' % i, 8) for i in range(23)] # 23 bytes
input_str = claripy.Concat(*chars + [claripy.BVV(b'\n')]) # + \n
initial_state = proj.factory.entry_state(stdin=input_str, add_options=options) # use as stdin

for c in chars: # make sure all chars are printable
    initial_state.solver.add(c >= 0x21, c <= 0x7e)


to_avoid = [0x40317C,0x402F79,0x402D77,0x402B7C,0x40297C,0x402781,0x402576,0x402379,0x402181,0x401F7D,0x401D7A,
            0x401B6D,0x401978,0x40177F,0x401592,0x40139D,0x4011AF,0x400FAC,0x400DA6,0x400BAD,0x4009AC,0x400797]

simgr = proj.factory.simulation_manager(initial_state)
simgr.explore(find=0x403370,avoid=to_avoid)

if simgr.found:
    print(simgr.found[0].posix.dumps(0)) # dump content of stdin