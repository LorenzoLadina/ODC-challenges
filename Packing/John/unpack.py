from pwn import xor
import os

base = 0x8048000
keys = [b'\x01\x02\x03\x04', b'\x10\x20\x30\x40', b'B00B', b'DEAD', b'\xff\xff\xff\xff']

full_content = b''



def unpack(filename, address, size, save=False):
    key = keys[address % 5]
    with open(filename, 'rb') as f:
        full_content = f.read()
        offset = address - base
    unpacked = b''
    for i in range(0, size*4, 4):
        unpacked += xor(full_content[offset+i:offset+i+4], key)

    #print(unpacked)
    if save:
        with open(filename, 'wb') as f:
            f.write(full_content[:offset] + unpacked + full_content[offset + len(unpacked):])
    return unpacked



os.system('rm john_*')
os.system('cp john john_unpacked')
unpack('./john_unpacked', 0x0804970E, 83, save=True)

################# second unpacking ####################


# we create a new file john_unpacked_unpacked where all the checks are unpacked
checks = {
    0x080492A0: 17,
    0x080492E5: 17,
    0x08049329: 23,
    0x080496AB: 24,
    0x080495E4: 49,
    0x08049546: 39,
    0x0804951F: 9
}

os.system('cp john_unpacked john_unpacked_unpacked')
for address, size in checks.items():
    unpack('./john_unpacked_unpacked', address, size, save=True)


# first check -> flag start with flag{

# second check -> flag end with }

# third check -> checks if flag contains only ascii characters

# fourth check
# the first 6 characters after "flag{" are compared with a packed string
unpack('./john_unpacked_unpacked', 0x08049385, 54, save=True)

# fifth check
# we need another unpacking
unpack('./john_unpacked_unpacked', 0x0804945E, 48, save=True)

# sixth check -> check last 10 characters before "}" 
# solved with z3 see check6.py 

# seventh check
# length of the flag must be 33