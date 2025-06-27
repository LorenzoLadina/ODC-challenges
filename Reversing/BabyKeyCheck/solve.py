from libdebug import debugger

def call(t, bp):
    print("Breakpoint hit at 0x1A0F")

d = debugger("./baby_keycheck")

r = d.run()

bp = d.bp(0x1A0F, file="baby_keycheck", callback=call)

d.cont()

print(r.recvuntil(b'flag> '))
r.sendline(b"flag{y0u_d4_qu33n_0}")


d.wait()
d.kill()

