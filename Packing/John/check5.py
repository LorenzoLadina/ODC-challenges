from libdebug import debugger

n_char_found = 0

def call(t, bp):
    global n_char_found
    n_char_found += d.regs.rax # if rax is 1, then the character is correct


compare_address = 0x804951e

values = ''
while len(values) < 9:
    for c in range(33, 127):
        if c == 34 or c == 39: # skip " and '
            continue
        testing = chr(c)
        flag = "flag{packer" + values + testing + 'A'*(9-len(values)-1) + "&-annoying__}" #total must be 33
        #print(len(flag))
        #print(flag)
        n_char_found = 0
        d = debugger(["./john", flag])
        d.run()
        bp = d.bp(compare_address, file="john", callback=call)
        d.cont()
        d.wait()
        d.kill()
        #print(f"[+] {chr(c)} {n_char_found} ")
        if n_char_found > len(values):
            values += testing
            print(flag)
            break

# flag{packer-4_3-1337&-annoying__}