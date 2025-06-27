from z3 import *

solver = Solver()

# The fixed keys byte array
keys = [
    0x0B,
    0x4C,
    0x0F,
    0x00,
    0x01,
    0x16,
    0x10,
    0x07,
    0x09,
    0x38,
    0x00,
]

# Create 12 `BitVec` variables for the flag (values)
values = [BitVec(f'values[{i}]', 8) for i in range(12)]  # 8-bit ASCII

# Add constraints to ensure values are printable ASCII characters
for i in range(12):
    solver.add(values[i] >= 32, values[i] <= 126)

# Add XOR constraints based on the provided keys
for i in range(len(keys)):
    solver.add(keys[i] ^ values[i] == values[i + 1])

# Solve and display results
if solver.check() == sat:
    model = solver.model()
    flag = ''.join(chr(model[values[i]].as_long()) for i in range(12))
    print("The flag is:", flag)
else:
    print("No solution found")
