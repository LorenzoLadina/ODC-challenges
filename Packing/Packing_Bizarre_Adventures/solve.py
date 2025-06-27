# the program unpacks the first checking function, than checks the first 16 bytes of the flag xoring them with some keys
# than if the first part is correct, unpacks the secondo checking function and checks the second part of the flag xoring it with some other keys

from pwn import *
from libdebug import debugger

def extract_keys(t, bp):
    #print(f"xored with {hex(d.regs.rax)}")
    keys.append(d.regs.rax)

def extract_results(t, bp):
    #print(f"compared with {hex(d.regs.rax)}")
    results.append(d.regs.rax)

keys = []
results = []
temp_flag = b"A" * 32  # 32 bytes

d = debugger("./chall")

r = d.run()
bp_decode = d.bp(0x1369, hardware=True, file="chall")
d.cont()

r.recvuntil(b"enter!\n")
r.sendline(temp_flag)

# unpacking the first checking function 5 loops, saw it from gdb
for i in range(5):
    d.cont()

# setting breakpoints where the bytes of the flag are xored and compared
bp_xoring = d.bp(0x13ea, hardware=True, file="chall", callback=extract_keys)
bp_comparing = d.bp(0x13f9, hardware=True, file="chall", callback=extract_results)
d.cont()

d.wait()
d.kill()

# extracting the first part of the flag
first_part_of_flag = ""
for i in range(16):
    first_part_of_flag += chr(results[i] ^ keys[i])
#print(first_part_of_flag)

### second part of the exploit, re run the program and check the second part of the flag

keys = []
results = []
temp_flag = first_part_of_flag.encode() + b"A" * 16  # 32 bytes

r = d.run()
bp_decode = d.bp(0x1369, hardware=True, file="chall")
d.cont()

r.recvuntil(b"enter!\n")
r.sendline(temp_flag)

# unpacking the first (again) and the second checking function 6 loops, saw it from gdb
for i in range(5+6):
    d.cont()

# setting breakpoints where the bytes of the flag are xored and compared
bp_xoring = d.bp(0x13ef, hardware=True, file="chall", callback=extract_keys)
bp_comparing = d.bp(0x13fe, hardware=True, file="chall", callback=extract_results)
d.cont()

d.wait()
d.kill()

# extracting the second part of the flag
second_part_of_flag = ""
for i in range(len(results)):
    second_part_of_flag += chr(results[i] ^ keys[i])

# combining the two parts of the flag
flag = first_part_of_flag + second_part_of_flag
print(flag)

