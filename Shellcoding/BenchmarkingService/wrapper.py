#!/usr/bin/env python3
import subprocess
import time
import sys

if __name__=="__main__":
    sys.stdout.write("======= BENCHMARKING SERVICE V1.0 =======\n")
    sys.stdout.write("Shellcode: ")
    shellcode = sys.stdin.buffer.read(1024)
    sys.stdout.write("Testing the performance of your shellcode...\n")
    start = time.time()
    p = subprocess.run(['./benchmarking_service'], input=shellcode, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    end = time.time()
    delta = end - start
    sys.stdout.write("Time: %s\n" % delta)