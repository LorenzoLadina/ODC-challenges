from pwn import *

output = []

key =[0x66,
    0x0A,
    0x0D,
    0x06,
    0x1C,
    0x0F,
    0x1C,
    0x01,
    0x1A,
    0x2C,
    0x28,
    0x16,
    0x12,
    0x2C,
    0x3E,
    0x0F,
    0x31,
    0x3A,
    0x04,
    0x12,
    0x0A,
    0x26,
    0x2D,
    0x17,
    0x13,
    0x13,
    0x17,
    0x01,
    0x16,
    0x18,
    0x6A,
    0x17]

v1 = 0

for i in key:
    res = xor(v1,i)
    output.append(res)
    print(res)
    v1 = res

print(b''.join(output))