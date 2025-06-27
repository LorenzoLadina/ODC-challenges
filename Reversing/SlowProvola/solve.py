from libdebug import debugger
import time


CHALL_PATH = "./slow_provola"

def call(t, bp):
    pass

flag = b"flag{"
breakpoints = [0x1DA6,
            0x1E4E,
            0x1EF6,
            0x1F9E,
            0x2046,
            0x20EE,
            0x2196,
            0x223E,
            0x22E6,
            0x238E,
            0x2436,
            0x24DE,
            0x2586,
            0x262E,
            0x26D6,
            0x277E,
            0x2826,
            0x28CE,
            0x2976,
            0x2A1E,
            0x2AC6,
            0x2B6E,
            0x2C16,
            0x2CBE,
            0x2D66,
            0x2E0E,
            0x2EB6,
            0x2F5E,
            0x3006,
            0x30AE,
            0x3156,
            0x31FE,
            0x32A6,
            0x334E,
            0x33F6,
            0x349E,
            0x3546,
            0x35EE,
            0x3696,
            0x373E,
            0x37E6,
            0x388E,
            0x3936,
            0x39DE,
            0x3A86,
            0x3B2E,
            0x3BCD,
            0x3C66,
            0x3CFF,
            0x3D98,
            0x3E31,
            0x3ECA,
            0x3F63,
            0x3FFC,
            0x4095,
            0x412E,
            0x41C7,
            0x4260,
            0x42F9,
            0x4392,
            0x442B,
            0x44C4,
            0x455D]

# bypass the sleep function with a costum sleep that do nothing
d = debugger(CHALL_PATH, env={"LD_PRELOAD": "./sleep.so"})

for breakpoint in breakpoints:
    for c in range(0x21, 0x7f):

        r = d.run()
        bp = d.bp(breakpoint, file="slow_provola", callback=call)
        d.cont()

        r.recvuntil(b"password.\n")
        buffer = flag + bytes([c]) + b"A" * (68 - len(flag) - 1)
        r.sendline(buffer)

        d.wait()
        d.kill()
        if bp.hit_count == 32: # if it 32 times it means that the character is correct
            flag += bytes([c])
            print(flag)
            break
