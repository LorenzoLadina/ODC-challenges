from pwn import *

COMMANDS = """

"""

# The application uses strncmp to compare the input with the flag
# We can use costum strncmp to leak the flag, see strncmp.c

ptrace_preload = './ptrace.so'
strncmp_preload = './strncmp.so'

if args.GDB:
    c = gdb.debug(['./revmem','test'], COMMANDS ,env={'LD_PRELOAD': ptrace_preload})
else:
    c = process(['./revmem','test'], env={'LD_PRELOAD': strncmp_preload})


c.interactive()
