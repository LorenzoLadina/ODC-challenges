from libdebug import debugger
import string

def call(t, bp):
    pass

d = debugger("./provola")

buffer = b""
flag = b"$" * 37
max_hits = 0

for i in range(37):
    for c in string.printable:
        buffer = flag[:i] + c.encode() + flag[i+1:]

        r = d.run()
        bp = d.bp(0x1A0F, file="provola", callback=call)
        d.cont()

        r.recvuntil(b"password.")
        r.sendline(buffer)

        d.wait()
        d.kill()
        
        if bp.hit_count > max_hits:
            max_hits = bp.hit_count
            flag = buffer
            print(flag)
            break
