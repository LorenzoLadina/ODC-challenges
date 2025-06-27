from libdebug import debugger
import string

flagset = string.ascii_letters + string.digits + "_"
flag_len = 27

found = ""
flag = ""
for i in range(6):
    for c in flagset:
        flag = "flag{" + found + c + "A" * (flag_len - len(found) - 1) + "}"
        d = debugger(["./john", flag])
        d.run()
        d.bp(0x080496EA)
        for _ in range(i + 1):
            d.cont()
        if (d.regs.eax == ord(c)):
            print(f"Found: {c}")
            found += c
            
            break

print("current flag is", flag)