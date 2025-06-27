from pwn import xor

data = [
0x4827c3baaa35c7cc,	
0x2648a0c1cd54abaa,
0x3c46afcfde54b5ab,	
0x3178e2e5d05ba8a5,
0x3c78b7d5cd6ab2a3,	
0x1740a2d6cc6aa2a4,
0x265ea7e5c75ab5aa,	
0x3c4e9cc9cb4298ed,
0x35189cded854af93,
]

keys = []

for i in range(1, len(data)):
    keys.append(xor(data[i].to_bytes(8, 'little'), data[0].to_bytes(8, 'little')))

print(b''.join(keys))