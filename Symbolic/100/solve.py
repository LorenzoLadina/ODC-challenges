from z3 import *

solver = Solver()
values = [Int(f'values[{i}]') for i in range(30)]
symbols = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

for i in range(30):
    solver.add(values[i] >= 0, values[i] <= 61)

# Add the equation constraint
solver.add(
    -26 * values[14] + 4 * values[10] + values[8] + 6 * values[0] - 10 * values[18] == -891
)
solver.add(
    -10 * values[17]
       + -70 * values[12]
       + -70 * values[6]
       + values[1]
       - values[2]
       - 4 * values[7]
       - 10 * values[23]
       - values[26]
       - values[28] == -4135
)
solver.add(
    values[26]
       + 10 * values[17]
       + 4 * values[7]
       + 70 * values[6]
       + values[2]
       + 70 * values[12]
       + 10 * values[23]
       + values[28] == 4183
)
solver.add(27 * values[14] + 4 * (3 * values[3] + values[7]) - 12 * values[29] == 1250)
solver.add(-72 * values[21] + -10 * values[18] + values[14] - (6 * values[4] - values[8] + values[13]) + values[24] == -3687)
solver.add(values[24]
       + 10 * values[17]
       + 4 * values[7]
       + 70 * values[6]
       + values[0]
       - values[1]
       + 5 * values[5]
       + 70 * values[12]
       - 6 * values[13]
       - values[14]
       + 10 * values[18]
       - 72 * values[21]
       + 10 * values[23]
       + values[26] == 1423)
solver.add(2 * values[14]
       + values[13]
       + 70 * values[12]
       + 4 * values[10]
       + 70 * values[6]
       - 10 * values[0]
       - 20 * values[18]
       + 72 * values[21]
       - values[24]
       - 10 * values[29] == 4738)
solver.add(values[7] == 5)
solver.add(values[8] == 21)
solver.add(values[14] + values[9] - 6 * values[4] - 10 * values[18] == -450)
solver.add(values[14] + 4 * values[10] - 10 * values[18] == -348)
solver.add(72 * values[21]
       + 9 * values[17]
       + 7 * values[11]
       + 69 * values[6]
       + -values[1]
       - values[3]
       + 66 * values[12]
       - 3 * values[14]
       + 10 * values[23]
       + values[26]
       - values[27]
       - values[28]
       + values[29] == 7181)
solver.add(-10 * values[18]
       + values[13]
       + values[7]
       + 3 * values[12]
       + values[14]
       - values[15]
       + 72 * values[21]
       - values[24]
       + values[25] == 2923)
solver.add(73 * values[13]
       + 504 * values[12]
       + 72 * values[7]
       + 504 * values[6]
       + 216 * values[14]
       - values[19]
       + 72 * values[23]
       - values[24]
       + 72 * values[25] == 35723)
solver.add(values[14] == 34)
solver.add(values[15] - values[7] - values[25] == 12)
solver.add(-72 * values[23]
       + -10 * values[18]
       + 8 * values[16]
       + -72 * values[13]
       + values[8]
       + -72 * values[7]
       + 6 * values[0]
       - 504 * values[6]
       + 4 * values[10]
       - 504 * values[12]
       - 242 * values[14]
       - 8 * values[15]
       - 72 * values[25] == -36811)
solver.add(90 * values[17] + 630 * (values[6] + values[12]) + 90 * values[23] == 36270)
solver.add(-72 * values[21] + -values[13] - values[14] + 10 * values[18] + values[24] == -2836)
solver.add(values[19] - values[13] + values[24] == 61)
solver.add(values[24] + values[19] + 3 * values[3] - values[13] + 9 * values[20] - 3 * values[29] == 589)
solver.add(-30 * values[18]
       + 3 * values[14]
       + 3 * values[13]
       + 2 * (-6 * values[4] + values[9])
       + 216 * values[21]
       - 3 * values[24] == 8360)
solver.add(6 * values[4] - values[12] + values[22] == 131)
solver.add(7 * (values[12] + values[6]) - 27 * values[14] + values[23] == -564)
solver.add(values[26]
       + values[24]
       + 10 * values[23]
       - (values[13]
        + -70 * values[12]
        - (4 * values[7]
         + values[2]
         - values[1]
         + 70 * values[6])
        - 10 * values[17])
       + values[28] == 4163)
solver.add(6 * values[14]
       + -68 * values[12]
       + -69 * values[6]
       + values[1]
       + values[3]
       - 6 * values[4]
       + values[7]
       - values[8]
       - 9 * values[17]
       - 72 * values[21]
       - values[22]
       - 10 * values[23]
       + values[25]
       - values[26]
       + values[27]
       + values[28]
       - values[29] == -7030)
solver.add(values[27]
       + -72 * values[21]
       + 411 * values[17]
       + 2871 * values[6]
       + values[3]
       - 41 * values[1]
       + 2871 * values[12]
       + 3 * values[14]
       + 410 * values[23]
       + 41 * values[26]
       + values[28]
       - values[29] == 162666)
solver.add(80 * values[18]
       + -9 * values[17]
       + -5 * values[14]
       + -69 * values[12]
       + values[1]
       + 48 * values[4]
       - 69 * values[6]
       - 8 * values[8]
       + 8 * values[13]
       + 504 * values[21]
       - 10 * values[23]
       - 8 * values[24]
       - values[26]
       + values[27] == 22429)
solver.add(-72 * values[21]
       + 3 * values[14]
       + -69 * values[6]
       + values[3]
       + values[1]
       - 69 * values[12]
       - 9 * values[17]
       - 10 * values[23]
       - values[26]
       + values[27]
       + values[28]
       - values[29] == -7014)
solver.add(values[29] == 24)



# Check if the solver can find a solution
if solver.check() == sat:
    model = solver.model()
    solution = ""
    for i in range(30):
       solution += symbols[int(model[values[i]].as_long())]
    print(solution)

else:
    print("No solution found")
