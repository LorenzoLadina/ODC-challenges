from pwn import *

kkk = b"babuzz"
magic0 = [0x1B, 0x51, 0x17, 0x2A, 0x1E, 0x4E, 0x3D, 0x10, 0x17, 0x46, 0x49, 0x14, 0x3D]

first_part = xor(kkk, magic0)

# print(pointer)

starting_point = 0xBB
magic1 = [0xEB, 0x51, 0xB0, 0x13, 0x85, 0xB9, 0x1C, 0x87, 0xB8, 0x26, 0x8D , 0x07]

for b in magic1:
    temp = b - starting_point
    # print(str((chr(temp % 256))).encode())
    first_part += str((chr(temp % 256))).encode()
    starting_point += temp

flag = b"flag{" + first_part + b"}"
print(flag)