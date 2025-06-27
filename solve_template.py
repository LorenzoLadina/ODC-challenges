from pwn import *
import time


CHALL_PATH = "./XXX"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("XXX.training.offensivedefensive.it",8080,ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)

c.recvuntil(b"")
c.send(b"\n")
c.interactive()